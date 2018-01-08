const Promise = require('bluebird')
const request = require('request-promise-native')
// https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
const aws4 = require('aws4')

// constant
const METADATA_URL = 'http://169.254.169.254/latest/'

// obtains, parses and formats the relevant data
// from the EC2 instance metadata service
const getInstanceData = () => Promise.props({
  document: request(`${METADATA_URL}dynamic/instance-identity/document`)
    .then(JSON.parse),
  role: request(`${METADATA_URL}meta-data/iam/security-credentials/`)
}).then(async data => Object.assign(data, {
  id: data.document.instanceId,
  region: data.document.region,
  credentials: await request(`${METADATA_URL}meta-data/iam/security-credentials/${data.role}`)
    .then(JSON.parse)
}))

// creates a signed request by inferring data from the
// EC2 instance metadata service and signing it with
// AWS signature version 4
const getSignedEc2Request = async () => {
  // get instance data
  const instanceData = await getInstanceData()
  const { role, region, id, credentials } = instanceData

  // construct request
  const url = 'https://sts.amazonaws.com/'
  const body = 'Action=GetCallerIdentity&Version=2011-06-15'
  const headers = { 'X-Vault-AWS-IAM-Server-ID': id }
  const req = {
    service: 'sts',
    body,
    headers,
    region
  }

  // sign request
  const accessKeyId = credentials.AccessKeyId
  const secretAccessKey = credentials.SecretAccessKey
  const sessionToken = credentials.Token
  aws4.sign(req, { accessKeyId, secretAccessKey, sessionToken })

  // construct request for vault
  return {
    role,
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
  const authResult =
    await vault.awsIamLogin(signedGetCallerIdentityRequest)

  // login with the returned token into node-vault
  vault.login(authResult.auth.client_token)

  // return the authenticated module
  return vault
}

// creates a logged in instance of node-vault
module.exports = awsEc2IamLogin
