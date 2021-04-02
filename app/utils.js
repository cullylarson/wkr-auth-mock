const {readFileSync} = require('fs')
const {createHash} = require('crypto')
const forge = require('node-forge')
const NodeRSA = require('node-rsa')
const {sign} = require('jsonwebtoken')
const base64url = require('base64url')

// taken from: https://github.com/juanelas/bigint-conversion
function bigintToBuf(num) {
    if(num < 0) throw RangeError('Value should be a non-negative integer. Negative values are not supported.')

    let hexStr = num.toString(16)
    hexStr = !(hexStr.length % 2) ? hexStr : '0' + hexStr

    return Buffer.from(hexStr, 'hex')
}

// num can be a Number, BigInt, or Buffer
function base64UrlUIntEncode(num) {
    const buff = Buffer.isBuffer(num)
        ? num
        : bigintToBuf(num)

    return base64url.fromBase64(buff.toString('base64'))
}

const readKeys = (publicKeyPath, privateKeyPath) => {
    let publicKeyPem
    let privateKeyPem

    try {
        publicKeyPem = readFileSync(publicKeyPath)
    }
    catch(err) {
        console.error(`Exception while reading public key (${publicKeyPath}): [${err.name} -- ${err.message}]`)
        process.exit(1)
    }

    try {
        privateKeyPem = readFileSync(privateKeyPath)
    }
    catch(err) {
        console.error(`Exception while reading private key (${privateKeyPath}): [${err.name} -- ${err.message}]`)
        process.exit(2)
    }

    return {
        publicKey: forge.pki.publicKeyFromPem(publicKeyPem),
        privateKey: forge.pki.privateKeyFromPem(privateKeyPem),
    }
}

const getCertAndKeys = (issuer, publicKey, privateKey) => {
    const {modulus, exponent} = getModulusExponent(publicKey)
    const certPem = getCertificatePem(publicKey, privateKey, issuer)
    const certDer = getCertificateDer(certPem)
    const thumbprintEncoded = getCertThumbprintEncoded(certDer)

    return {
        pair: {
            pub: publicKey,
            priv: privateKey,
        },
        cert: {
            modulus,
            exponent,
            certPem,
            certDer,
            thumbprintEncoded,
            kid: thumbprintEncoded,
        },
    }
}

const getModulusExponent = publicKey => {
    const nodeRsa = new NodeRSA()
    nodeRsa.importKey(forge.pki.publicKeyToPem(publicKey))

    const {n: modulus, e: exponent} = nodeRsa.exportKey('components-public')

    return {
        modulus,
        exponent,
    }
}

const getCertificatePem = (publicKey, privateKey, jwksOrigin) => {
    const nextYear = (new Date()).getFullYear() + 1
    const validNotBefore = new Date('2019-08-16:00:00')
    const validNotAfter = new Date(`${nextYear}-08-16:00:00`)

    const attrs = [
        {
            name: 'commonName',
            value: `${jwksOrigin}`,
        },
    ]

    const cert = forge.pki.createCertificate()
    cert.publicKey = publicKey
    cert.serialNumber = '777' // every service that generates this certificate needs to be the same, so using the same serial number
    cert.validity.notBefore = validNotBefore
    cert.validity.notAfter = validNotAfter
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)
    cert.setSubject(attrs)
    cert.sign(privateKey)

    return forge.pki.certificateToPem(cert)
}

const getCertificateDer = certPem => {
    return forge.util.encode64(
        forge.asn1
            .toDer(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(certPem)))
            .getBytes(),
    )
}

const getCertThumbprint = certDer => {
    const derBinaryStr = Buffer.from(certDer).toString('binary')

    const shasum = createHash('sha1')
    shasum.update(derBinaryStr)

    return shasum.digest('base64')
}

const getCertThumbprintEncoded = certDer => base64url.encode(getCertThumbprint(certDer))

const signAccountJwt = (account, permissions, roles, groups, expiresIn, {
    privateKey,
    kid,
    issuer,
    audience,
    claimsNamespace,
}) => {
    return new Promise((resolve, reject) => {
        const payload = {
            [claimsNamespace]: {
                account,
                permissions,
                roles,
                groups,
            },
        }

        const options = {
            algorithm: 'RS256',
            keyid: kid,
            issuer,
            audience,
            expiresIn,
        }

        sign(payload, forge.pki.privateKeyToPem(privateKey), options, (err, theJwt) => {
            if(err) reject(err)
            else resolve(theJwt)
        })
    })
}

const signApplicationJwt = (application, permissions, roles, groups, expiresIn, {
    privateKey,
    kid,
    issuer,
    audience,
    claimsNamespace,
}) => {
    return new Promise((resolve, reject) => {
        const payload = {
            [claimsNamespace]: {
                application,
                permissions,
                roles,
                groups,
            },
        }

        const options = {
            algorithm: 'RS256',
            keyid: kid,
            issuer,
            audience,
            expiresIn,
        }

        sign(payload, forge.pki.privateKeyToPem(privateKey), options, (err, theJwt) => {
            if(err) reject(err)
            else resolve(theJwt)
        })
    })
}

module.exports = {
    base64UrlUIntEncode,
    readKeys,
    getCertAndKeys,
    signAccountJwt,
    signApplicationJwt,
}
