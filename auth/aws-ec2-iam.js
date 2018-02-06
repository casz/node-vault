const nodeVault = require('../src/main')
const awsEc2IamLogin = require('../src/aws-auth')

module.exports = () => awsEc2IamLogin(nodeVault())
