const Promise = require('bluebird')
const request = require('request-promise')
// https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
const aws4 = require('aws4')

const nodeVault = require('./main')

// constant
const METADATA_URL = 'http://169.254.169.254/latest/'

// obtains, parses and formats the relevant data
// from the EC2 instance metadata service
const getInstanceData = () => Promise.props({
  id: request(`${METADATA_URL}dynamic/instance-identity/document`)
    .then(JSON.parse).then(doc => doc.instanceId),
  role: request(`${METADATA_URL}meta-data/iam/security-credentials/`)
}).then(async data => Object.assign(data, {
  credentials: await request(`${METADATA_URL}meta-data/iam/security-credentials/${data.role}`)
    .then(JSON.parse)
}))

// creates a signed request by inferring data from the
// EC2 instance metadata service and signing it with
// AWS signature version 4
const getSignedEc2Request = async () => {
  // get instance data
  const instanceData = await getInstanceData()

  // construct request
  const url = 'https://sts.amazonaws.com/'
  const body = 'Action=GetCallerIdentity&Version=2011-06-15'
  const headers = { 'X-Vault-AWS-IAM-Server-ID': instanceData.id }
  const req = {
    service: 'sts',
    body,
    headers
  }

  // sign request
  const accessKeyId = instanceData.credentials.AccessKeyId
  const secretAccessKey = instanceData.credentials.SecretAccessKey
  const sessionToken = instanceData.credentials.Token
  aws4.sign(req, { accessKeyId, secretAccessKey, sessionToken })

  // normalize data for vault
  return {
    iam_http_request_method: 'POST',
    iam_request_url: Buffer
      .from(url).toString('base64'),
    iam_request_body: Buffer
      .from(body).toString('base64'),
    iam_request_headers: Buffer
      .from(JSON.stringify(req.headers)).toString('base64')
  }
}

const awsEc2IamLogin = async (vault) => {
  // execute login operation
  const signedGetCallerIdentityRequest = await getSignedEc2Request()
  const { body } = signedGetCallerIdentityRequest
  const authResult = await vault.awsIamLogin(body)

  // login with the returned token into node-vault
  vault.login(authResult.auth.client_token)

  // return the authenticated module
  return vault
}

// creates a logged in instance of node-vault
module.exports = async () => {
  const vault = nodeVault()
  return awsEc2IamLogin(vault)
}
