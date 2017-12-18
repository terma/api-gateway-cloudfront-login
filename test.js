'use strict';

const assert = require('assert');

const proxyquire = require('proxyquire').noCallThru();

const assumeAwsCredentials = {
    Credentials: {
        AccessKeyId: '',
    }

};
const stsMock = {
    assumeRole: function (options, callback) {
        callback(null, assumeAwsCredentials);
    }
};

const awsSdkMock = {
    config: {},
    CloudFront: {
        Signer: function () {
            return {
                getSignedCookie: function (config, callback) {
                    const cloudFrontSignedCookies = {};
                    callback(null, cloudFrontSignedCookies);
                }
            }
        }
    },

    STS: function () {
        return stsMock;
    },

    CognitoIdentityCredentials: function () {
        return {
            get: function (callback) {
                callback();
            }
        }
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

function assertResponse(event, done, statusCode, body) {
    login.handler(event || {}, null, function (ignore, response) {
        try {
            assert.equal(response.body, body);
            assert.equal(response.statusCode, statusCode);
            done();
        } catch (e) {
            done(e);
        }
    });
}

const loginProviderHost = 'http://login-provider.test';

beforeEach(function () {
    openIdClientMock.Issuer.discover = function () {
        return new Promise(function (resolve, reject) {
            resolve(issuerMock);
        });
    };

    process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
    delete process.env.OPEN_ID_LOGIN_URL;
    delete process.env.OPEN_ID_TARGET_URL;
    delete process.env.ASSUME_ROLE;
    delete process.env.COGNITO_IDENTTITY_POOL_ID;
});

describe('api-gateway-cloudfront-login', function () {

    it('response with error if env.OPEN_ID_DISCOVER_URL not configured', function (done) {
        delete process.env.OPEN_ID_DISCOVER_URL;
        assertResponse({}, done, 500, 'env.OPEN_ID_DISCOVER_URL is not configured!');
    });

    it('response error if env.OPEN_ID_LOGIN_URL not configured', function (done) {
        assertResponse(null, done, 500, 'env.OPEN_ID_LOGIN_URL is not configured!');
    });

    it('response error if env.OPEN_ID_TARGET_URL and customTargetUrl are not configured', function (done) {
        const event = {queryStringParameters: {id_token: 'sss'}};
        assertResponse(event, done, 500, 'env.OPEN_ID_TARGET_URL or customTargetUrl not configured!');
    });

    it('response error if fails during OpenID discover', function (done) {
        openIdClientMock.Issuer.discover = function () {
            return new Promise(function (_, reject) {
                reject('Test error!');
            });
        };
        assertResponse(null, done, 500, 'Test error!');
    });

    it('redirect to login provider when id_token not specified', function (done) {
        process.env.OPEN_ID_LOGIN_URL = 'back';
        assertResponse(null, done, 200, '<html><head><meta http-equiv="refresh" content="0; url=http://open-id.test/authorization?redirect_uri=back"/></head><body>Wait a second or <a href="http://open-id.test/authorization?redirect_uri=back">proceed to login</a></body></html>');
    });

    describe('when valid id_token received redirect with signed cookies and AWS credentials', function () {
        it('regular', function (done) {
            process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
            process.env.OPEN_ID_LOGIN_URL = '???';
            process.env.OPEN_ID_TARGET_URL = 'http://target.url';
            process.env.COGNITO_IDENTTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';

            const event = {
                queryStringParameters: {
                    id_token: 'sss'
                }
            };
            assertResponse(event, done, 301, null);
        });

        it('provide additional AWS assumed if requested', function (done) {
            process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
            process.env.OPEN_ID_LOGIN_URL = '???';
            process.env.OPEN_ID_TARGET_URL = 'http://target.url';
            process.env.COGNITO_IDENTTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';
            process.env.ASSUME_ROLE = 'assume-role';

            const event = {
                queryStringParameters: {
                    id_token: 'sss'
                }
            };
            assertResponse(event, done, 301, null);
        });

        it('redirect to customTargetUrl if specifiec', function (done) {
            process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
            process.env.OPEN_ID_LOGIN_URL = '???';
            process.env.OPEN_ID_TARGET_URL = 'http://target.url';
            process.env.COGNITO_IDENTTITY_POOL_ID = 'us-east-1:f0fdfdcd-a5b5-4978-ab5c-a49c48d4db60';

            const event = {
                queryStringParameters: {
                    id_token: 'sss',
                    customTargetUrl: 'http://custom-target.test'
                }
            };
            assertResponse(event, done, 301, null);
        });
    });

});