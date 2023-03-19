const {createHmac} = require('crypto')

function verifyMessageAndKey(message, key) {
    if (typeof message !== 'string' && !Buffer.isBuffer(message)) {
        throw new Error('Input message must be a string or buffer!')
    }
    if (typeof key !== 'string' && !Buffer.isBuffer(key)) {
        throw new Error('Input key must be a string or buffer!')
    }
    if (!key) {
        throw new Error('Must specify a key!')
    }
}

function sha256Hmac(message, key) {
    verifyMessageAndKey(message, key)
    return createHmac('sha256', key).update(message).digest('hex')
}

function sha512Hmac(message, key) {
    verifyMessageAndKey(message, key)
    return createHmac('sha512', key).update(message).digest('hex')
}

module.exports = {
    sha256Hmac,
    sha512Hmac,
}
