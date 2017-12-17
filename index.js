'use strict';

process.env.NODE_TLS_REJECT_UNATHORIZED = '0';

const AWS = require('aws-sdk');
const Issuer = require('openid-client').Issuer;

function getConfig() {
    const config = {
        domain: process.env.DOMAIN_NAME,
        cognitoIdentityPoolId: process.env.COGNITO_IDENTTITY_POOL_ID,
        awsRegion: process.env.REGION || 'us-west-2',
        roleToAssume: process.env.ASSUME_ROLE,
        cloudFrontKeyId: process.env.CLOUD_FRONT_KEY_ID,
// todo check if not specified
        cloudFrontPrivateKey: process.env.CLOUD_FRONT_PRIVATE_KEY ? process.env.CLOUD_FRONT_PRIVATE_KEY.replace(/\\n/g, '\n') : void 0,

        openId: {
            discoverUrl: process.env.OPEN_ID_DISCOVER_URL,
            clientId: process.env.OPEN_ID_CLIENT_ID,
            loginUrl: process.env.OPEN_ID_LOGIN_URL,
            targetUrl: process.env.OPEN_ID_TARGET_URL
        }
    };
    console.log('Configuration:');
    console.log(JSON.stringify(config));
    return config;
}

function createCookieBuilder(url, maxAgeSec) {
    const secure = url.indexOf('https://') === 0;
    const m = url.match(/http[s]?:\/\/([a-z-0-9.]+)/i);
    if (m.length < 2) throw new Error('Cant extract domian from ' + url);
    const domain = m[1];
    return function (name, value, isSecure) {
        return name + '=' + value + ';Domain=' + domain + ';Max-Age=' + maxAgeSec + ';Path=/;' + (secure ? 'Secure' : '') + (isSecure ? 'HttpOnly' : '');
    }
}

function createCloudFrontSignedCookie(callback) {
    const cloudFrontSigner = new AWS.CloudFront.Signer(cloudFrontKeyId, cloudFrontPrivateKey);
    cloudFrontSigner.getSignedCookie({
        policy: JSON.stringify({
            Statement: [
                {
                    Resource: 'https://' + domain + '/*',
                    Condition: {
                        DateLessThan: {'AWS:EpochTime': Math.round(Date.now() / 1000) + loginDuration}
                    }
                }
            ]
        })
    }, callback);
}

function responseError(err, callback) {
    console.log(err);
    callback(null, {
        statusCode: 500,
        body: JSON.stringify(err)
    });
}

function exchangeOpenIdTokenToAwsUser(idToken, callback) {
    AWS.config.region = awsRegion;
    AWS.config.credentials = new Aws.CognitoIdentityCredentials({
        IdentityPoolId: cognitoIdentityPoolId,
        Logins: {'...': idToken}
    });
    AWS.config.credentials.get(function (err) {
        console.log('AWS Cognito Identity Expire Time: ' + AWS.config.credentials.expireTime);
        callback(err);
    });
}

function assumeRole(callback) {
    if (!roleToAssume) {
        callback();
    } else {
        const sts = AWS.STS();
        // default expiration time for assumed credentials is 1 h
        sts.assumeRole({
            RoleArn: roleToAssume,
            RoleSessionName: 'under-assume'
        }, callback);
    }
}

let issuerPromise;

function getOpenIdClient(config, callback) {
    if (!config.openId.discoverUrl) {
        callback('process.env.OPEN_ID_DISCOVER_URL not configured!');
    } else {
        if (!issuerPromise) issuerPromise = Issuer.discover(config.openId.discoverUrl);
        issuerPromise.then(function (issuer) {
            const client = new issuer.Client({client_id: config.openId.clientId});
            callback(null, client);
        }, function (err) {
            callback('' + err);
        });
    }
}

function responseRedirectByHtmlPage(url, callback) {
    const response = {
        statusCode: 200,
        headers: {
            'Content-Type': 'text/html'
        },
        body:
        '<html>' +
        '<head><meta http-equiv="refresh" content="0; url=' + url + '"/></head>' +
        '<body>Wait a second or <a href="' + url + '">proceed to login</a></body>' +
        '</html>'
    };
    console.log('responseRedirectByHtmlPage: ' + JSON.stringify(response));
    callback(null, response);
}

function getAuthorizationUrl(config, openIdClient, customTargetUrl, callback) {
    if (config.openId.loginUrl) {
        const authorizationUrl = openIdClient.authorizationUrl({
            redirect_uri: config.openId.loginUrl + (customTargetUrl ? '?customTargetUrl=' + customTargetUrl : ''),
            scope: 'openid',
            response_type: 'id_token',
            nonce: 'f'
        });
        callback(null, authorizationUrl);
    } else {
        callback('env.OPEN_ID_LOGIN_URL variable is not configured!');
    }
}

function responseRedirectWithData(cloudFrontSignedCookies, assumeAwsCredentials, customTargetUrl, callback) {
    const url = customTargetUrl ? customTargetUrl : openId.targetUrl;
    const toCookie = createCookieBuilder(url, loginDuration);

    const cookies = [
        toCookie('CloudFront-Policy', cloudFrontSignedCookies['CloudFront-Policy'], true),
        toCookie('CloudFront-Key-Pair-Id', cloudFrontSignedCookies['CloudFront-Key-Pair-Id'], true),
        toCookie('CloudFront-Signature', cloudFrontSignedCookies['CloudFront-Signature'], true),
        toCookie('AWS-Access-Key-Id', AWS.config.credentials.accessKeyId),
        toCookie('AWS-Secret-Access-Key', AWS.config.credentials.secretAccessKey),
        toCookie('AWS-Session-Token', AWS.config.credentials.sessionToken)
    ];

    if (assumeAwsCredentials) {
        cookies.push(toCookie('Assume-AWS-Access-Key-Id', assumeAwsCredentials.Credentials.AccessKeyId));
        cookies.push(toCookie('Assume-AWS-Secret-Access-Key', assumeAwsCredentials.Credentials.SecretAccessKey));
        cookies.push(toCookie('Assume-AWS-Session-Token', assumeAwsCredentials.Credentials.SessionToken));
    }

    if (customTargetUrl) {
        callback(null, {
            statusCode: 301,
            headers: {
                Location: url + '#loginCookies' + cookies.join('|')
            },
            body: null
        });
    } else {
        const response = {
            statusCode: 301,
            headers: {
                Location: url,
                'Access-Control-Allow-Origin': '*',
                'Set-cookie': cookies[0],
                'sEt-cookie': cookies[1],
                'seT-cookie': cookies[2],
                'set-Cookie': cookies[3],
                'set-cOokie': cookies[4],
                'set-coOkie': cookies[5]
            },
            body: null
        };

        if (assumeAwsCredentials) {
            response.headers['set-cooKie'] = cookies[6];
            response.headers['set-cookIe'] = cookies[7];
            response.headers['set-cookiE'] = cookies[8];
        }

        callback(null, response);
    }
}

exports.handler = function (event, context, callback) {
    if (!event) throw new Error('Event parameter can\'t be null!');

    const config = getConfig();
    const customTargetUrl = event.queryStringParameters ? event.queryStringParameters.customTargetUrl : void 0;
    const idToken = event.queryStringParameters ? event.queryStringParameters.id_token : void 0;
    if (!idToken) {
        getOpenIdClient(config, function (err, openIdClient) {
            if (err) responseError(err, callback);
            else getAuthorizationUrl(config, openIdClient, customTargetUrl, function (err, authorizationUrl) {
                if (err) responseError(err, callback);
                else responseRedirectByHtmlPage(authorizationUrl, callback);
            });
        });
    } else {
        exchangeOpenIdTokenToAwsUser(idToken, function (err) {
            if (err) responseError(err, callback);
            else createCloudFrontSignedCookie(function (err, cloudFrontSignedCookies) {
                if (err) responseError(err, callback);
                else assumeRole(function (err, assumeAwsCredentials) {
                    if (err) responseError(err, callback);
                    else responseRedirectWithData(cloudFrontSignedCookies, assumeAwsCredentials, customTargetUrl, callback);
                });
            });
        });
    }
};