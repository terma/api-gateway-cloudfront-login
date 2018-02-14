'use strict';

process.env.DISABLE_CONFIG_CACHE = true;

const assert = require('assert');
const proxyquire = require('proxyquire').noCallThru();

const assumeAwsCredentials = {Credentials: {AccessKeyId: ''}};
const stsMock = {};
let cognitoIdentityCredentialsMock = {};
const cloudFrontSignerMock = {};

const awsSdkMock = {
    config: {},
    CloudFront: {
        Signer: function () {
            return cloudFrontSignerMock;
        }
    },

    STS: function () {
        return stsMock;
    },

    CognitoIdentityCredentials: function () {
        return cognitoIdentityCredentialsMock;
    }
};

const clientMock = {
    authorizationUrl: function (options) {
        return 'http://open-id.test/authorization?redirect_uri=' + options.redirect_uri;
    }
};

const issuerMock = {
    Client: function () {
        return clientMock;
    }
};

const openIdClientMock = {
    Issuer: {}
};

proxyquire('./index', {
    'aws-sdk': awsSdkMock,
    'openid-client': openIdClientMock
});

const login = require('./index');

function assertStatusCodeAndBody(event, done, statusCode, body) {
    assertResponse(event, done, function (response) {
        assert.equal(response.body, body);
        assert.equal(response.statusCode, statusCode);
    });
}

function assertResponse(event, done, asserter) {
    login.handler(event || {}, null, function (ignore, response) {
        try {
            asserter(response);
            done();
        } catch (e) {
            done(e);
        }
    });
}

const loginProviderHost = 'http://login-provider.test';

beforeEach(function () {
    stsMock.assumeRole = function (options, callback) {
        callback(null, assumeAwsCredentials);
    };

    cloudFrontSignerMock.getSignedCookie = function (config, callback) {
        const cloudFrontSignedCookies = {};
        callback(null, cloudFrontSignedCookies);
    };

    cognitoIdentityCredentialsMock = {};
    cognitoIdentityCredentialsMock.expireTime = 10000;
    cognitoIdentityCredentialsMock.get = function (callback) {
        callback();
    };

    openIdClientMock.Issuer.discover = function () {
        return new Promise(function (resolve) {
            resolve(issuerMock);
        });
    };

    process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
    delete process.env.OPEN_ID_LOGIN_URL;
    delete process.env.OPEN_ID_TARGET_URL;
    delete process.env.ASSUME_ROLE;
    delete process.env.COGNITO_IDENTITY_POOL_ID;
});

describe('api-gateway-cloudfront-login', function () {

    it('throw error if event is null', function (done) {
        try {
            login.handler(null, null, null);
            done('Where is my error!');
        } catch (e) {
            done();
        }
    });

    it('throw error if callback is null', function (done) {
        try {
            login.handler({}, null, null);
            done('Where is my error!');
        } catch (e) {
            done();
        }
    });

    it('response with error if env.OPEN_ID_DISCOVER_URL not configured', function (done) {
        delete process.env.OPEN_ID_DISCOVER_URL;
        assertStatusCodeAndBody({}, done, 500, 'env.OPEN_ID_DISCOVER_URL is not configured!');
    });

    it('response error if env.OPEN_ID_LOGIN_URL not configured', function (done) {
        assertStatusCodeAndBody(null, done, 500, 'env.OPEN_ID_LOGIN_URL is not configured!');
    });

    it('response error if env.OPEN_ID_TARGET_URL and customTargetUrl are not configured', function (done) {
        const event = {queryStringParameters: {id_token: 'sss'}};
        assertStatusCodeAndBody(event, done, 500, 'env.OPEN_ID_TARGET_URL or customTargetUrl not configured!');
    });

    it('response error if fails during OpenID discover', function (done) {
        openIdClientMock.Issuer.discover = function () {
            return new Promise(function (_, reject) {
                reject('Test error!');
            });
        };
        assertStatusCodeAndBody(null, done, 500, 'Test error!');
    });

    it('response error if invalid env.OPEN_ID_TARGET_URL', function (done) {
        process.env.OPEN_ID_LOGIN_URL = 'login.url';
        process.env.OPEN_ID_TARGET_URL = 'aa';
        const event = {queryStringParameters: {id_token: 'sss'}};
        assertStatusCodeAndBody(event, done, 500, 'Can\'t extract domain from aa!');
    });

    it('response error if fails during cognito', function (done) {
        process.env.OPEN_ID_TARGET_URL = 'http://target.url';
        process.env.COGNITO_IDENTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';
        cognitoIdentityCredentialsMock.get = function (callback) {
            callback('Cognito error!');
        };
        const event = {queryStringParameters: {id_token: 'sss'}};
        assertStatusCodeAndBody(event, done, 500, 'Cognito error!');
    });

    it('response error if fails during signed cookie creation', function (done) {
        process.env.OPEN_ID_TARGET_URL = 'http://target.url';
        process.env.COGNITO_IDENTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';
        cloudFrontSignerMock.getSignedCookie = function (config, callback) {
            callback('CloudFront error!', null);
        };
        const event = {queryStringParameters: {id_token: 'sss'}};
        assertStatusCodeAndBody(event, done, 500, 'CloudFront error!');
    });

    it('response error if fails during assume role', function (done) {
        process.env.OPEN_ID_TARGET_URL = 'http://target.url';
        process.env.COGNITO_IDENTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';
        process.env.ASSUME_ROLE = 'assume-role';
        stsMock.assumeRole = function (options, callback) {
            callback('Assume error!', null);
        };
        const event = {queryStringParameters: {id_token: 'sss'}};
        assertStatusCodeAndBody(event, done, 500, 'Assume error!');
    });

    describe('redirect to openId provider login', function () {
        it('when id_token not specified', function (done) {
            process.env.OPEN_ID_LOGIN_URL = 'back';
            assertStatusCodeAndBody(null, done, 200, '<html><head><meta http-equiv="refresh" content="0; url=http://open-id.test/authorization?redirect_uri=back"/></head><body>Wait a second or <a href="http://open-id.test/authorization?redirect_uri=back">proceed to login</a></body></html>');
        });

        it('when id_token not specified and customTargetUrl configured', function (done) {
            process.env.OPEN_ID_LOGIN_URL = 'back';
            assertStatusCodeAndBody({
                queryStringParameters: {customTargetUrl: 'custom-target-url'}
            }, done, 200, '<html><head><meta http-equiv="refresh" content="0; url=http://open-id.test/authorization?redirect_uri=back?customTargetUrl=custom-target-url"/></head><body>Wait a second or <a href="http://open-id.test/authorization?redirect_uri=back?customTargetUrl=custom-target-url">proceed to login</a></body></html>');
        });

        it('pass correct options to authorizationUrl', function (done) {
            process.env.OPEN_ID_LOGIN_URL = 'backi';
            let authorizationUrlOptions = {};
            clientMock.authorizationUrl = function (options) {
                authorizationUrlOptions = options;
                return 'r-uri';
            };
            assertResponse({}, done, function (response) {
                assert.equal(response.statusCode, 200);
                assert.deepEqual(authorizationUrlOptions, {
                    redirect_uri: 'backi',
                    scope: 'openid',
                    response_type: 'id_token',
                    nonce: 'z'
                });
            });
        });
    });

    describe('when valid id_token received redirect with signed cookies and AWS credentials', function () {
        it('regular', function (done) {
            process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
            process.env.OPEN_ID_LOGIN_URL = '???';
            process.env.OPEN_ID_TARGET_URL = 'http://target.url';
            process.env.COGNITO_IDENTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';
            cognitoIdentityCredentialsMock.accessKeyId = 'accessKeyId';
            cognitoIdentityCredentialsMock.secretAccessKey = 'secretAccessKey';
            cognitoIdentityCredentialsMock.sessionToken = 'sessionToken';
            cloudFrontSignerMock.getSignedCookie = function (config, callback) {
                callback(null, {
                    'CloudFront-Policy': 'cloudFrontPolicy',
                    'CloudFront-Key-Pair-Id': 'cloudFrontKeyPairId',
                    'CloudFront-Signature': 'cloudFrontSignature'
                });
            };
            const event = {queryStringParameters: {id_token: 'sss'}};
            assertResponse(event, done, function (response) {
                assert.equal(response.body, null);
                assert.equal(response.statusCode, 301);
                assert.deepEqual(response.headers, {
                    "Location": "http://target.url",
                    "Access-Control-Allow-Origin": "*",
                    "Set-cookie": "CloudFront-Policy=cloudFrontPolicy;Domain=target.url;Max-Age=10;Path=/;HttpOnly",
                    "sEt-cookie": "CloudFront-Key-Pair-Id=cloudFrontKeyPairId;Domain=target.url;Max-Age=10;Path=/;HttpOnly",
                    "seT-cookie": "CloudFront-Signature=cloudFrontSignature;Domain=target.url;Max-Age=10;Path=/;HttpOnly",
                    "set-Cookie": "AWS-Access-Key-Id=accessKeyId;Domain=target.url;Max-Age=10;Path=/;",
                    "set-cOokie": "AWS-Secret-Access-Key=secretAccessKey;Domain=target.url;Max-Age=10;Path=/;",
                    "set-coOkie": "AWS-Session-Token=sessionToken;Domain=target.url;Max-Age=10;Path=/;"
                });
            });
        });

        it('pass correct parameters to Cognito credentials', function (done) {
            process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
            process.env.OPEN_ID_LOGIN_URL = '???';
            process.env.OPEN_ID_TARGET_URL = 'http://target.url';
            process.env.OPEN_ID_LOGIN = 'logins';
            process.env.COGNITO_IDENTITY_POOL_ID = 'pool-id';
            const event = {queryStringParameters: {id_token: 'id-token'}};
            let cognitoIdentityCredentailsOptions = {};
            awsSdkMock.CognitoIdentityCredentials = function (options) {
                cognitoIdentityCredentailsOptions = options;
                return cognitoIdentityCredentialsMock;
            };
            assertResponse(event, done, function (response) {
                assert.equal(response.statusCode, 301);
                assert.deepEqual(cognitoIdentityCredentailsOptions, {
                    IdentityPoolId: 'pool-id',
                    Logins: {'logins': 'id-token'}
                });
            });
        });

        describe('cookie age and signed policy depends on API login expiration', function () {
            it('10 sec', function (done) {
                process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
                process.env.OPEN_ID_LOGIN_URL = '???';
                process.env.OPEN_ID_TARGET_URL = 'http://target.url';
                process.env.COGNITO_IDENTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';
                const event = {queryStringParameters: {id_token: 'sss'}};
                login.handler(event, null, function (ignore, response) {
                    try {
                        assert.equal(response.statusCode, 301);
                        assert.deepEqual(response.headers, {
                            "Location": "http://target.url",
                            "Access-Control-Allow-Origin": "*",
                            "Set-cookie": "CloudFront-Policy=undefined;Domain=target.url;Max-Age=10;Path=/;HttpOnly",
                            "sEt-cookie": "CloudFront-Key-Pair-Id=undefined;Domain=target.url;Max-Age=10;Path=/;HttpOnly",
                            "seT-cookie": "CloudFront-Signature=undefined;Domain=target.url;Max-Age=10;Path=/;HttpOnly",
                            "set-Cookie": "AWS-Access-Key-Id=undefined;Domain=target.url;Max-Age=10;Path=/;",
                            "set-cOokie": "AWS-Secret-Access-Key=undefined;Domain=target.url;Max-Age=10;Path=/;",
                            "set-coOkie": "AWS-Session-Token=undefined;Domain=target.url;Max-Age=10;Path=/;"
                        });
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
            });

            it('25 sec', function (done) {
                process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
                process.env.OPEN_ID_LOGIN_URL = '???';
                process.env.OPEN_ID_TARGET_URL = 'http://target.url';
                process.env.COGNITO_IDENTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';
                const event = {queryStringParameters: {id_token: 'sss'}};
                cognitoIdentityCredentialsMock.expireTime = 25000;
                login.handler(event, null, function (ignore, response) {
                    try {
                        assert.equal(response.statusCode, 301);
                        assert.deepEqual(response.headers, {
                            "Location": "http://target.url",
                            "Access-Control-Allow-Origin": "*",
                            "Set-cookie": "CloudFront-Policy=undefined;Domain=target.url;Max-Age=25;Path=/;HttpOnly",
                            "sEt-cookie": "CloudFront-Key-Pair-Id=undefined;Domain=target.url;Max-Age=25;Path=/;HttpOnly",
                            "seT-cookie": "CloudFront-Signature=undefined;Domain=target.url;Max-Age=25;Path=/;HttpOnly",
                            "set-Cookie": "AWS-Access-Key-Id=undefined;Domain=target.url;Max-Age=25;Path=/;",
                            "set-cOokie": "AWS-Secret-Access-Key=undefined;Domain=target.url;Max-Age=25;Path=/;",
                            "set-coOkie": "AWS-Session-Token=undefined;Domain=target.url;Max-Age=25;Path=/;"
                        });
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
            });
        });

        it('target URL is case insensitive', function (done) {
            process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
            process.env.OPEN_ID_LOGIN_URL = '???';
            process.env.OPEN_ID_TARGET_URL = 'hTTP://tarGET.url';
            process.env.COGNITO_IDENTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';

            const event = {queryStringParameters: {id_token: 'sss'}};
            assertStatusCodeAndBody(event, done, 301, null);
        });

        it('target URL could be https', function (done) {
            process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
            process.env.OPEN_ID_LOGIN_URL = '???';
            process.env.OPEN_ID_TARGET_URL = 'https://target.url';
            process.env.COGNITO_IDENTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';

            const event = {queryStringParameters: {id_token: 'sss'}};
            assertStatusCodeAndBody(event, done, 301, null);
        });

        it('provide additional AWS assumed if requested', function (done) {
            process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
            process.env.OPEN_ID_LOGIN_URL = '???';
            process.env.OPEN_ID_TARGET_URL = 'http://target.url';
            process.env.COGNITO_IDENTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';
            process.env.ASSUME_ROLE = 'assume-role';
            stsMock.assumeRole = function (options, callback) {
                callback(null, {
                    Credentials: {
                        AccessKeyId: 'assumeAccessKeyId',
                        SecretAccessKey: 'assumeSecretAccessKey',
                        SessionToken: 'assumeSessionToken'
                    }
                });
            };
            const event = {queryStringParameters: {id_token: 'sss'}};
            assertResponse(event, done, function (response) {
                assert.equal(response.statusCode, 301);
                assert.deepEqual(response.headers, {
                    "Location": "http://target.url",
                    "Access-Control-Allow-Origin": "*",
                    "Set-cookie": "CloudFront-Policy=undefined;Domain=target.url;Max-Age=10;Path=/;HttpOnly",
                    "sEt-cookie": "CloudFront-Key-Pair-Id=undefined;Domain=target.url;Max-Age=10;Path=/;HttpOnly",
                    "seT-cookie": "CloudFront-Signature=undefined;Domain=target.url;Max-Age=10;Path=/;HttpOnly",
                    "set-Cookie": "AWS-Access-Key-Id=undefined;Domain=target.url;Max-Age=10;Path=/;",
                    "set-cOokie": "AWS-Secret-Access-Key=undefined;Domain=target.url;Max-Age=10;Path=/;",
                    "set-coOkie": "AWS-Session-Token=undefined;Domain=target.url;Max-Age=10;Path=/;",
                    "set-cooKie": "Assume-AWS-Access-Key-Id=assumeAccessKeyId;Domain=target.url;Max-Age=10;Path=/;",
                    "set-cookIe": "Assume-AWS-Secret-Access-Key=assumeSecretAccessKey;Domain=target.url;Max-Age=10;Path=/;",
                    "set-cookiE": "Assume-AWS-Session-Token=assumeSessionToken;Domain=target.url;Max-Age=10;Path=/;"
                });
            });
        });

        it('pass correct options to assume when requested', function (done) {
            process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
            process.env.OPEN_ID_LOGIN_URL = '???';
            process.env.OPEN_ID_TARGET_URL = 'http://target.url';
            process.env.COGNITO_IDENTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';
            process.env.ASSUME_ROLE = 'assume-role';
            let assumeRoleOptions = {};
            stsMock.assumeRole = function (options, callback) {
                assumeRoleOptions = options;
                callback(null, {Credentials: {}});
            };
            const event = {queryStringParameters: {id_token: 'sss'}};
            assertResponse(event, done, function (response) {
                assert.equal(response.statusCode, 301);
                assert.deepEqual(assumeRoleOptions, {
                    RoleArn: 'assume-role',
                    RoleSessionName: 'under-assume'
                });
            });
        });

        it('redirect to customTargetUrl if specified', function (done) {
            process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
            process.env.OPEN_ID_LOGIN_URL = '???';
            process.env.OPEN_ID_TARGET_URL = 'http://target.url';
            process.env.COGNITO_IDENTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';

            const event = {
                queryStringParameters: {
                    id_token: 'sss',
                    customTargetUrl: 'http://custom-target.test'
                }
            };
            assertResponse(event, done, function (response) {
                assert.equal(response.statusCode, 301);
                assert.deepEqual(response.headers, {
                    "Location": "http://custom-target.test#loginCookiesCloudFront-Policy=undefined;Domain=custom-target.test;Max-Age=10;Path=/;HttpOnly|CloudFront-Key-Pair-Id=undefined;Domain=custom-target.test;Max-Age=10;Path=/;HttpOnly|CloudFront-Signature=undefined;Domain=custom-target.test;Max-Age=10;Path=/;HttpOnly|AWS-Access-Key-Id=undefined;Domain=custom-target.test;Max-Age=10;Path=/;|AWS-Secret-Access-Key=undefined;Domain=custom-target.test;Max-Age=10;Path=/;|AWS-Session-Token=undefined;Domain=custom-target.test;Max-Age=10;Path=/;"
                });
            });
        });
    });

});