#!/usr/bin/env node

const path = require('path')
const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const {get} = require('@cullylarson/f')
const {getCertAndKeys, readKeys, signAccountJwt, signApplicationJwt} = require(path.join(__dirname, 'utils'))

const argv = require('yargs')
    .usage('Usage: $0 -p <num> -c <string>')
    .demandOption(['p', 'c'])
    .help('h')
    .describe('p', 'The port to listen on.')
    .describe('c', 'The claims namespace where custom parameters (e.g. permissions) will be stored in the JWT.')
    .argv

const port = argv.p
const claimsNamespace = argv.c
const issuer = 'wkr-auth-mock'
const {publicKey, privateKey} = readKeys(path.join(__dirname, 'keys/public_key.pem'), path.join(__dirname, 'keys/private_key.pem'))
const secrets = getCertAndKeys(issuer, publicKey, privateKey)
const jwksKey = {
    alg: 'RSA256',
    kty: 'RSA',
    use: 'sig',
    x5c: [secrets.cert.certDer],
    e: String(secrets.cert.exponent),
    n: secrets.cert.modulus.toString('base64'),
    kid: secrets.cert.kid,
    x5t: secrets.cert.thumbprintEncoded,
}

const handleAccountJwt = (req, res) => {
    const account = get('account', {}, req.body)
    const permissions = get('permissions', [], req.body)
    const roles = get('roles', [], req.body)
    const groups = get('groups', [], req.body)
    const lasts = get('lasts', 3600, req.body)

    signAccountJwt(account, permissions, roles, groups, lasts, {
        privateKey: secrets.pair.priv,
        kid: secrets.cert.kid,
        issuer,
        audience: issuer,
        claimsNamespace,
    })
        .then(tokenJwt => res.json({token: tokenJwt}))
        .catch(_ => {
            res
                .status(500)
                .json({})
        })
}

const app = express()

app.use(cors({
    origin: '*',
    methods: 'GET',
}))

app.use(bodyParser.json())

app.post('/jwt', handleAccountJwt)

// mocks the account authentication endpoint, but allows for setting own permissions
app.post('/account/authenticate', handleAccountJwt)

// mocks the application authentication endpoint, but allows for setting own permissions
app.post('/application/authenticate', (req, res) => {
    const application = get('application', {}, req.body)
    const permissions = get('permissions', [], req.body)
    const roles = get('roles', [], req.body)
    const groups = get('groups', [], req.body)
    const lasts = get('lasts', 3600, req.body)

    signApplicationJwt(application, permissions, roles, groups, lasts, {
        privateKey: secrets.pair.priv,
        kid: secrets.cert.kid,
        issuer,
        audience: issuer,
        claimsNamespace,
    })
        .then(tokenJwt => res.json({token: tokenJwt}))
        .catch(_ => {
            res
                .status(500)
                .json({})
        })
})

app.get('/jwks.json', (req, res) => {
    res.json({
        keys: [
            jwksKey,
        ],
    })
})

app.listen(port)
