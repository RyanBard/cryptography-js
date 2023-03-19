const {
    createCipheriv,
    randomBytes,
    createDecipheriv,
} = require('crypto')

function aes256GenerateKey() {
    return randomBytes(32)
}

function aes256GenerateIv() {
    return randomBytes(16)
}

function aes256Encrypt(key, iv, message) {
    const cipher = createCipheriv('aes256', key, iv)
    return cipher.update(message, 'utf8', 'hex') + cipher.final('hex')
}

function aes256Decrypt(key, iv, cipherText) {
    const decipher = createDecipheriv('aes256', key, iv)
    return decipher.update(cipherText, 'hex', 'utf8') + decipher.final('utf8')
}

module.exports = {
    aes256GenerateKey,
    aes256GenerateIv,
    aes256Encrypt,
    aes256Decrypt,
}
