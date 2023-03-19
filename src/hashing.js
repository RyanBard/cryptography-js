const {createHash} = require('crypto')

function verifyStringOrBuffer(data) {
    if (typeof data !== 'string' && !Buffer.isBuffer(data)) {
        throw new Error('Input must be a string or buffer')
    }
}

function md5Hash(data) {
    verifyStringOrBuffer(data)
    return createHash('md5').update(data).digest('hex')
}

function sha1Hash(data) {
    verifyStringOrBuffer(data)
    return createHash('sha1').update(data).digest('hex')
}

function sha256Hash(data) {
    verifyStringOrBuffer(data)
    return createHash('sha256').update(data).digest('hex')
}

function sha512Hash(data) {
    verifyStringOrBuffer(data)
    return createHash('sha512').update(data).digest('hex')
}

module.exports = {
    md5Hash,
    sha1Hash,
    sha256Hash,
    sha512Hash,
}
