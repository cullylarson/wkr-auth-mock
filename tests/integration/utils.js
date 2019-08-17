const {curry, get} = require('@cullylarson/f')

const baseUrl = `http://localhost:${process.env.PORT}`
const claimsNamespace = process.env.CLAIMS_NS

// can be passed to request.expect. will check if field present in response body and is not empty
const hasField = curry((fieldName, res) => {
    if(!get(fieldName, undefined, res.body)) throw Error(`Did not find field [${fieldName}] in response body.`)
})

module.exports = {
    baseUrl,
    claimsNamespace,
    hasField,
}
