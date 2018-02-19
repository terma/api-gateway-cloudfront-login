# api-gateway-cloudfront-login

[![npm version](https://badge.fury.io/js/api-gateway-cloudfront-login.svg)](https://badge.fury.io/js/api-gateway-cloudfront-login)
[![Build Status](https://travis-ci.org/terma/api-gateway-cloudfront-login.svg?branch=master)](https://travis-ci.org/terma/api-gateway-cloudfront-login)
[![Coverage Status](https://coveralls.io/repos/github/terma/api-gateway-cloudfront-login/badge.svg?branch=master)](https://coveralls.io/github/terma/api-gateway-cloudfront-login?branch=master)

## How to use

### Add dependency

```npm i api-gateway-cloudfront-login --save```

### Handler for lambda

```Handler: node_modules/api-gateway-cloudfront-login/index.handler```

### Configuration

For CloudFormation configure properties as env variables [More](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-environment)

```
DOMAIN_NAME
COGNITO_IDENTITY_POOL_ID
REGION - optional default 'us-west-2'
ASSUME_ROLE - optional if specified additional assume provided role and return credentials
CLOUD_FRONT_KEY_ID
CLOUD_FRONT_PRIVATE_KEY
OPEN_ID_DISCOVER_URL
OPEN_ID_LOGIN
OPEN_ID_CLIENT_ID
OPEN_ID_LOGIN_URL
OPEN_ID_TARGET_URL
DEBUG - optional by default false
```

### Example 

```yaml
Type: "AWS::Lambda::Function"
Properties: 
  Code:
    Code
  Environment:
    DOMAIN_NAME: X
    COGNITO_IDENTITY_POOL_ID: pool-id
    CLOUD_FRONT_KEY_ID: AAA
    CLOUD_FRONT_PRIVATE_KEY: BBB
    OPEN_ID_DISCOVER_URL: X
    OPEN_ID_LOGIN: X
    OPEN_ID_CLIENT_ID: X
    OPEN_ID_LOGIN_URL: X
    OPEN_ID_TARGET_URL: X
  FunctionName: MyFunction
  Handler: node_modules/api-gateway-cloudfront-login/index.handler
```

## Result

After successeful login provide cookies:

CloudFront Signed Cookies [More](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-cookies.html)
HttpOnly not accessible by JavaScript
```
CloudFront-Policy
CloudFront-Key-Pair-Id
CloudFront-Signature
```

Cognito User Credentials:
```
AWS-Access-Key-Id
AWS-Secret-Access-Key
AWS-Session-Token
```

Assumed role credentials only if ```ASSUME_ROLE``` specified:
```
Assume-AWS-Access-Key-Id
Assume-AWS-Secret-Access-Key
Assume-AWS-Session-Token  
```
