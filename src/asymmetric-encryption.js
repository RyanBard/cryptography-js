const {
    generateKeyPairSync,
    publicEncrypt,
    privateDecrypt,
    createSign,
    createVerify,
} = require('crypto')

function rsaGenerateKeyPairSync(passphrase) {
    const options = {
        modulusLength: 4096,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
        },
    }
    if (passphrase) {
        options.privateKeyEncoding.cipher = 'aes-256-cbc'
        options.privateKeyEncoding.passphrase = passphrase
    }
    return generateKeyPairSync('rsa', options)
}

function rsaEncryptMessage(publicKey, message) {
    return publicEncrypt(publicKey, Buffer.from(message, 'ascii'))
        .toString('hex')
}

function rsaDecryptMessage(privateKey, cipherText) {
    return privateDecrypt(
        privateKey,
        Buffer.from(cipherText, 'hex'),
    ).toString('ascii')
}

function rsaSig(privateKey, message) {
    const signer = createSign('rsa-sha256')
    signer.update(message)
    return signer.sign(privateKey, 'hex')
}

function rsaVerifySig(publicKey, message, sig) {
    const verifier = createVerify('rsa-sha256')
    verifier.update(message)
    return verifier.verify(publicKey, sig, 'hex')
}

module.exports = {
    rsaGenerateKeyPairSync,
    rsaEncryptMessage,
    rsaDecryptMessage,
    rsaSig,
    rsaVerifySig,
}
