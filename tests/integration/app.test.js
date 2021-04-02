const request = require('supertest')
const jwt = require('jsonwebtoken')
const jwksClient = require('jwks-rsa')
const {baseUrl, hasField, claimsNamespace} = require('./utils')

const getPublicKey = async (jwksUri) => {
    const client = jwksClient({
        strictSsl: false,
        jwksUri,
    })

    const keys = await client.getSigningKeys()
    if(!keys || !keys.length) throw new Error('No keys found at JWKS endpoint.')
    return keys[0].getPublicKey()
}

test('Can get a JWT.', () => {
    const account = {a: 'AAA'}
    const permissions = ['BBB']
    const roles = ['CCC']
    const groups = ['DDD']

    return request(baseUrl)
        .post('/jwt')
        .send({account, permissions, roles, groups})
        .expect(200)
        .expect(hasField('token'))
        .then(res => jwt.decode(res.body.token))
        .then(token => {
            expect(token[claimsNamespace].account).toEqual(account)
            expect(token[claimsNamespace].permissions).toEqual(permissions)
            expect(token[claimsNamespace].roles).toEqual(roles)
            expect(token[claimsNamespace].groups).toEqual(groups)
        })
})

test('Can get an account JWT.', () => {
    const account = {a: 'AAA'}
    const permissions = ['BBB']
    const roles = ['CCC']
    const groups = ['DDD']

    return request(baseUrl)
        .post('/api/v1/account/authenticate')
        .send({account, permissions, roles, groups})
        .expect(200)
        .expect(hasField('token'))
        .then(res => jwt.decode(res.body.token))
        .then(token => {
            expect(token[claimsNamespace].account).toEqual(account)
            expect(token[claimsNamespace].permissions).toEqual(permissions)
            expect(token[claimsNamespace].roles).toEqual(roles)
            expect(token[claimsNamespace].groups).toEqual(groups)
        })
})

test('Can get an application JWT.', () => {
    const application = {a: 'AAA'}
    const permissions = ['BBB']
    const roles = ['CCC']
    const groups = ['DDD']

    return request(baseUrl)
        .post('/api/v1/application/authenticate')
        .send({application, permissions, roles, groups})
        .expect(200)
        .expect(hasField('token'))
        .then(res => jwt.decode(res.body.token))
        .then(token => {
            expect(token[claimsNamespace].application).toEqual(application)
            expect(token[claimsNamespace].permissions).toEqual(permissions)
            expect(token[claimsNamespace].roles).toEqual(roles)
            expect(token[claimsNamespace].groups).toEqual(groups)
        })
})

test('JWT is valid, using the JWKS endpoint.', () => {
    return Promise.all([
        request(baseUrl)
            .post('/jwt')
            .then(res => res.body.token),
        getPublicKey(baseUrl + '/jwks.json'),
    ])
        .then(([tokenJwt, publicKey]) => {
            try {
                jwt.verify(tokenJwt, publicKey)
            }
            catch(_) {
                throw Error('Could not verify jwt.')
            }
        })
})

test("JWT 'lasts' parameter is used correctly.", () => {
    const lasts = 5555555

    return request(baseUrl)
        .post('/jwt')
        .send({lasts})
        .expect(200)
        .expect(hasField('token'))
        .then(res => jwt.decode(res.body.token))
        .then(token => {
            const now = Math.floor(Date.now() / 1000)

            expect(Math.abs(now - token.exp)).toBeGreaterThan(lasts - 30) // give it some wiggle room
        })
})

test("JWT audience and issuer are both set to 'wkr-auth-mock'.", () => {
    return request(baseUrl)
        .post('/jwt')
        .expect(200)
        .expect(hasField('token'))
        .then(res => jwt.decode(res.body.token))
        .then(token => {
            expect(token.aud).toBe('wkr-auth-mock')
            expect(token.iss).toBe('wkr-auth-mock')
        })
})

test('Can get all groups and roles.', () => {
    return request(baseUrl)
        .get('/api/v1/.well-known/all-roles-groups')
        .expect(200)
})
