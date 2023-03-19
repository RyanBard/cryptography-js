const {expect} = require('chai')

const {
    rsaGenerateKeyPairSync,
    rsaEncryptMessage,
    rsaDecryptMessage,
    rsaSig,
    rsaVerifySig,
} = require('../src/asymmetric-encryption')

describe('asymmetric-encryption', () => {

    let keyPair1
    let keyPair2
    let encryptedKeyPair

    before(function () {
        this.timeout(15000)
        keyPair1 = rsaGenerateKeyPairSync()
        keyPair2 = rsaGenerateKeyPairSync()
        encryptedKeyPair = rsaGenerateKeyPairSync('secret')
    })

    describe('rsaGenerateKeyPairSync', () => {
        it('should generate a public/private key pair', () => {
            expect(keyPair1.publicKey.trim().replaceAll('\n', ' ')).to.match(/-----BEGIN PUBLIC KEY-----.*-----END PUBLIC KEY-----/)
            expect(keyPair1.privateKey.trim().replaceAll('\n', ' ')).to.match(/-----BEGIN PRIVATE KEY-----.*-----END PRIVATE KEY-----/)
        }).timeout(5000)

        it('should generate a public/private key pair and encrypt the private key', () => {
            expect(encryptedKeyPair.publicKey.trim().replaceAll('\n', ' ')).to.match(/-----BEGIN PUBLIC KEY-----.*-----END PUBLIC KEY-----/)
            expect(encryptedKeyPair.privateKey.trim().replaceAll('\n', ' ')).to.match(/-----BEGIN ENCRYPTED PRIVATE KEY-----.*-----END ENCRYPTED PRIVATE KEY-----/)
        }).timeout(5000)
    })

    describe('rsaEncryptMessage / rsaDecryptMessage', () => {

        let inputMessage
        let cipherText1
        let cipherText2
        let cipherText3

        beforeEach(() => {
            inputMessage = 'this is a test'
            cipherText1 = rsaEncryptMessage(keyPair1.publicKey, inputMessage)
            cipherText2 = rsaEncryptMessage(keyPair2.publicKey, inputMessage)
            cipherText3 = rsaEncryptMessage(encryptedKeyPair.publicKey, inputMessage)
        })

        it('should decrypt when the key is correct', () => {
            expect(rsaDecryptMessage(keyPair1.privateKey, cipherText1)).to.eql(inputMessage)
            expect(rsaDecryptMessage(keyPair2.privateKey, cipherText2)).to.eql(inputMessage)
            expect(rsaDecryptMessage({
                key: encryptedKeyPair.privateKey,
                passphrase: 'secret',
            }, cipherText3)).to.eql(inputMessage)
        })

        it('should not repeat the same cipherText', () => {
            const cipher1 = rsaEncryptMessage(keyPair1.publicKey, inputMessage)
            const cipher2 = rsaEncryptMessage(keyPair1.publicKey, inputMessage)
            const cipher3 = rsaEncryptMessage(keyPair1.publicKey, inputMessage)
            expect(cipher1).not.to.eql(cipherText1)
            expect(cipher1).not.to.eql(cipher2)
            expect(cipher1).not.to.eql(cipher3)
            expect(cipher2).not.to.eql(cipherText1)
            expect(cipher2).not.to.eql(cipher3)
            expect(cipher3).not.to.eql(cipherText1)
        })

        it('should throw when the secret for an encrypted key is incorrect', () => {
            expect(() => rsaEncryptMessage({
                key: encryptedKeyPair.privateKey,
                passphrase: 'wrong-secret',
            }, inputMessage)).to.throw()
            expect(() => rsaDecryptMessage({
                key: encryptedKeyPair.privateKey,
                passphrase: 'wrong-secret',
            }, cipherText3)).to.throw()
        })

        it('should not decrypt when the key is incorrect', () => {
            expect(() => rsaDecryptMessage(keyPair1.privateKey, cipherText2)).to.throw()
            expect(() => rsaDecryptMessage(keyPair1.privateKey, cipherText3)).to.throw()

            expect(() => rsaDecryptMessage(keyPair2.privateKey, cipherText1)).to.throw()
            expect(() => rsaDecryptMessage(keyPair2.privateKey, cipherText3)).to.throw()

            expect(() => rsaDecryptMessage({
                key: encryptedKeyPair.privateKey,
                passphrase: 'secret',
            }, cipherText1)).to.throw()
            expect(() => rsaDecryptMessage({
                key: encryptedKeyPair.privateKey,
                passphrase: 'secret',
            }, cipherText2)).to.throw()
        })
    })

    describe('rsaSig / rsaVerifySig', () => {
        let message1
        let message2
        let sig1
        let sig2
        let sig3

        beforeEach(() => {
            message1 = 'this is a test 1'
            message2 = 'this is a test 2'
            sig1 = rsaSig(keyPair1.privateKey, message1)
            sig2 = rsaSig(keyPair1.privateKey, message2)
            sig3 = rsaSig(keyPair2.privateKey, message1)
            sig4 = rsaSig({
                key: encryptedKeyPair.privateKey,
                passphrase: 'secret',
            }, message1)
        })

        it('should verify when the key, message, and signature match', () => {
            expect(rsaVerifySig(keyPair1.privateKey, message1, sig1)).to.eql(true)
            expect(rsaVerifySig(keyPair1.privateKey, message2, sig2)).to.eql(true)
            expect(rsaVerifySig(keyPair2.privateKey, message1, sig3)).to.eql(true)
            expect(rsaVerifySig({
                key: encryptedKeyPair.privateKey,
                passphrase: 'secret',
            }, message1, sig4)).to.eql(true)
        })

        it('should not verify when the key does not match', () => {
            expect(rsaVerifySig(keyPair2.privateKey, message1, sig1)).to.eql(false)
            expect(rsaVerifySig(keyPair2.privateKey, message2, sig2)).to.eql(false)
            expect(rsaVerifySig(keyPair1.privateKey, message1, sig3)).to.eql(false)
            expect(rsaVerifySig(keyPair1.privateKey, message1, sig4)).to.eql(false)
        })

        it('should not verify when the message does not match', () => {
            expect(rsaVerifySig(keyPair1.privateKey, message2, sig1)).to.eql(false)
            expect(rsaVerifySig(keyPair1.privateKey, message1, sig2)).to.eql(false)
            expect(rsaVerifySig(keyPair2.privateKey, message2, sig3)).to.eql(false)
            expect(rsaVerifySig({
                key: encryptedKeyPair.privateKey,
                passphrase: 'secret',
            }, message2, sig4)).to.eql(false)
        })

        it('should not verify when the signature does not match', () => {
            expect(rsaVerifySig(keyPair1.privateKey, message1, sig2)).to.eql(false)
            expect(rsaVerifySig(keyPair1.privateKey, message2, sig1)).to.eql(false)
            expect(rsaVerifySig(keyPair2.privateKey, message1, sig4)).to.eql(false)
            expect(rsaVerifySig({
                key: encryptedKeyPair.privateKey,
                passphrase: 'secret',
            }, message1, sig3)).to.eql(false)
        })

        it('should repeat the same signature', () => {
            const s1 = rsaSig(keyPair1.privateKey, message1)
            const s2 = rsaSig(keyPair1.privateKey, message1)
            const s3 = rsaSig(keyPair1.privateKey, message1)
            expect(s1).to.eql(sig1)
            expect(s1).to.eql(s2)
            expect(s1).to.eql(s3)
        })

        it('should throw when the secret for an encrypted key is incorrect', () => {
            expect(() => rsaSig({
                key: encryptedKeyPair.privateKey,
                passphrase: 'wrong-secret',
            }, message1)).to.throw()
            expect(() => rsaVerifySig({
                key: encryptedKeyPair.privateKey,
                passphrase: 'wrong-secret',
            }, message1, sig1)).to.throw()
        })
    })
})
