const {
    md5Hash,
    sha1Hash,
    sha256Hash,
    sha512Hash,
} = require('./hashing')

const {
    sha256Hmac,
    sha512Hmac,
} = require('./hmac')

const {
    createUserRecord,
    userPasswordMatches,
} = require('./salting')

const {
    aes256GenerateKey,
    aes256GenerateIv,
    aes256Encrypt,
    aes256Decrypt,
} = require('./symmetric-encryption')

module.exports = {
    // hashing
    md5Hash,
    sha1Hash,
    sha256Hash,
    sha512Hash,

    // hmac
    sha256Hmac,
    sha512Hmac,

    // salting
    createUserRecord,
    userPasswordMatches,

    // symmetric-encryption
    aes256GenerateKey,
    aes256GenerateIv,
    aes256Encrypt,
    aes256Decrypt,

    // asymmetric-encryption
}
