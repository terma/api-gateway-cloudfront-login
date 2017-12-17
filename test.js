'use strict';

const nock = require('nock');
const assert = require('assert');
const login = require('./index');

function assert500(httpMock, done, error) {
    login.handler({}, null, function (ignore, response) {
        try {
            if (httpMock) httpMock.done();
            assert.equal(response.body, error);
            assert.equal(response.statusCode, 500);
            done();
        } catch (e) {
            done(e);
        }
    });
}

const loginProviderHost = 'http://login-provider.test';
const openIdConfiguration = {
    "issuer": loginProviderHost,
    "authorization_endpoint": loginProviderHost + "/oauth/auz/authorize",
    "token_endpoint": loginProviderHost + "/oauth/oauth20/token",
    "userinfo_endpoint": loginProviderHost + "/oauth/userinfo",
    "jwks_uri": loginProviderHost + "/oauth/jwks",
    "scopes_supported": [
        "READ",
        "WRITE",
        "DELETE",
        "openid",
        "scope",
        "profile",
        "email",
        "address",
        "phone"
    ],
    "response_types_supported": ["id_token"],
    "grant_types_supported": [
        "authorization_code",
        "implicit",
        "password",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    ],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["HS256"],
    "id_token_encryption_alg_values_supported": ["RSA1_5"],
    "id_token_encryption_enc_values_supported": ["A128CBC-HS256"],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt"
    ],
    "token_endpoint_auth_signing_alg_values_supported": ["HS256", "RS256"],
    "claims_parameter_supported": false,
    "request_parameter_supported": false,
    "request_uri_parameter_supported": false
};

beforeEach(function () {
    delete process.env.OPEN_ID_DISCOVER_URL;
    delete process.env.OPEN_ID_LOGIN_URL;
});

describe('api-gateway-cloudfront-login', function () {

    it('response with error if env.OPEN_ID_DISCOVER_URL not configured', function (done) {
        assert500(null, done, '"process.env.OPEN_ID_DISCOVER_URL not configured!"');
    });

    it('response error if env.OPEN_ID_LOGIN_URL not configured', function (done) {
        const a = nock(loginProviderHost).log(console.log)
            .get('/.well-known/openid-configuration').reply(200, openIdConfiguration);
        process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
        assert500(a, done, '"env.OPEN_ID_LOGIN_URL variable is not configured!"');
    });

    it('redirect to login provider when id_token not specified', function (done) {
        // given
        const a = nock(loginProviderHost).log(console.log)
            .get('/.well-known/openid-configuration').reply(200, openIdConfiguration);
        process.env.OPEN_ID_DISCOVER_URL = loginProviderHost;
        process.env.OPEN_ID_LOGIN_URL = '???';

        // when
        login.handler({}, null, function (ignore, response) {
            try {
                a.done();
                assert.equal(response.body, '"SyntaxError: Unexpected token x"');
                assert.equal(response.statusCode, 200);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

});