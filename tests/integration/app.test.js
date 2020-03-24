const request = require('supertest')
const jwt = require('jsonwebtoken')
const jwksClient = require('jwks-rsa')
const {baseUrl, hasField, claimsNamespace} = require('./utils')

const getPublicKey = jwksUri => {
    return new Promise((resolve, reject) => {
        const client = jwksClient({
            strictSsl: false,
            jwksUri,
        })

        client.getSigningKeys((err, keys) => {
            if(err) reject(err)
            else if(!keys || !keys.length) reject(new Error('No keys found at JWKS endpoint.'))
            else resolve(keys[0].publicKey)
        })
    })
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
        .post('/account/authenticate')
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
        .post('/application/authenticate')
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
