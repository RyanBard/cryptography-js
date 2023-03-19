const {expect} = require('chai')

const {
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
} = require('../src/index')

describe('exports', () => {
    it('should export all of the things', () => {
        // hashing
        expect(typeof md5Hash).to.eql('function')
        expect(typeof sha1Hash).to.eql('function')
        expect(typeof sha256Hash).to.eql('function')
        expect(typeof sha512Hash).to.eql('function')

        // hmac
        expect(typeof sha256Hmac).to.eql('function')
        expect(typeof sha512Hmac).to.eql('function')

        // salting
        expect(typeof createUserRecord).to.eql('function')
        expect(typeof userPasswordMatches).to.eql('function')

        // symmetric-encryption
        expect(typeof aes256GenerateKey).to.eql('function')
        expect(typeof aes256GenerateIv).to.eql('function')
        expect(typeof aes256Encrypt).to.eql('function')
        expect(typeof aes256Decrypt).to.eql('function')

        // asymmetric-encryption
        // expect(typeof userPasswordMatches).to.eql('function')
    })
})
