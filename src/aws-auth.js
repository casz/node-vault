const request = require('request-promise-native')
// https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
const aws4 = require('aws4')

// constant
const METADATA_URL = 'http://169.254.169.254/latest/'

// obtains, parses and formats the relevant data
// from the EC2 instance metadata service
const getInstanceData = async () => {
  // get role
  const role =
    await request(`${METADATA_URL}meta-data/iam/security-credentials/`)

  // get credentials using role
  const credentials =
    await request(`${METADATA_URL}meta-data/iam/security-credentials/${role}`)
      .then(JSON.parse)

  // return instance data
  return {
    role,
    credentials
  }
}

// creates a signed request to the GetCallerIdentity method
// from the STS service by inferring credentials data from
// the EC2 instance metadata service and signing it with
// AWS signature version 4
const getSignedEc2IamRequest = async () => {
  // get instance data
  const instanceData = await getInstanceData()
  const { role, credentials } = instanceData

  // construct request
  const url = 'https://sts.amazonaws.com/'
  const body = 'Action=GetCallerIdentity&Version=2011-06-15'
  // TODO: rethink 'X-Vault-AWS-IAM-Server-ID' implementation (env variable?)
  const headers = {
    // 'X-Vault-AWS-IAM-Server-ID': '<vault-id>'
  }
  const req = {
    service: 'sts',
    region: 'us-east-1', // https://github.com/hashicorp/vault-ruby/pull/161#issuecomment-355723269
    doNotModifyHeaders: false, // DISABLED temporal workaround to https://github.com/hashicorp/vault/issues/2810#issuecomment-306530386
    body,
    headers
  }

  // sign request
  const { AccessKeyId, SecretAccessKey, Token } = credentials
  const accessKeyId = AccessKeyId
  const secretAccessKey = SecretAccessKey
  const sessionToken = Token
  aws4.sign(req, { accessKeyId, secretAccessKey, sessionToken })

  // Content-Length header workaround for Vault v0.9.1 and lower
  // https://github.com/hashicorp/vault/issues/3763/
  req.headers['Content-Length'] = req.headers['Content-Length'].toString()

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
  const request = await getSignedEc2IamRequest()
  const authResult = await vault.awsIamLogin(request)

  // login with the returned token into node-vault
  vault.login(authResult.auth.client_token)

  // return the authenticated module
  return vault
}

// creates a logged in instance of node-vault
module.exports = awsEc2IamLogin
