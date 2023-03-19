const {expect} = require('chai')

const {
    aes256GenerateKey,
    aes256GenerateIv,
    aes256Encrypt,
    aes256Decrypt,
} = require('../src/symmetric-encryption')

describe('symmetric-encryption', () => {

    describe('aes256', () => {
        const inputMessage = 'this is a test'
        const key1 = aes256GenerateKey()
        const key2 = aes256GenerateKey()
        const iv1 = aes256GenerateIv()
        const iv2 = aes256GenerateIv()
        const cipherText1 = aes256Encrypt(key1, iv1, inputMessage)
        const cipherText2 = aes256Encrypt(key1, iv1, inputMessage)
        const cipherText3 = aes256Encrypt(key1, iv2, inputMessage)

        it('should decrypt when the key and iv are correct', () => {
            expect(cipherText1).to.eql(cipherText2)
            const decryptedMessage1 = aes256Decrypt(key1, iv1, cipherText1)
            const decryptedMessage2 = aes256Decrypt(key1, iv1, cipherText2)
            const decryptedMessage3 = aes256Decrypt(key1, iv2, cipherText3)
            expect(decryptedMessage1).to.eql(inputMessage)
            expect(decryptedMessage2).to.eql(inputMessage)
            expect(decryptedMessage3).to.eql(inputMessage)
        })

        it('should not decrypt with different cipherText', () => {
            expect(cipherText1).not.to.eql(cipherText3)
            expect(() => aes256Decrypt(key1, iv1, cipherText3)).to.throw()
        })

        it('should not decrypt with different key', () => {
            expect(() => aes256Decrypt(key2, iv1, cipherText1)).to.throw()
        })

        it('should not decrypt with different iv', () => {
            expect(() => aes256Decrypt(key1, iv2, cipherText1)).to.throw()
        })
    })

})
