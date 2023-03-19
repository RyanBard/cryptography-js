const {expect} = require('chai')

const {
    md5Hash,
    sha1Hash,
    sha256Hash,
    sha512Hash,
} = require('../src/hashing')

describe('hashing', () => {

    describe('md5', () => {
        // https://en.wikipedia.org/wiki/MD5
        const testCases = [
            {expected: '9e107d9d372bb6826bd81d3542a419d6', input: 'The quick brown fox jumps over the lazy dog'},
            {expected: 'e4d909c290d0fb1ca068ffaddf22cbd0', input: 'The quick brown fox jumps over the lazy dog.'},
            {expected: 'd41d8cd98f00b204e9800998ecf8427e', input: ''},
        ]

        it('should produce known hashes for known string values', () => {
            testCases.forEach(testCase => {
                expect(md5Hash(testCase.input)).to.eql(testCase.expected)
            })
        })

        it('should handle buffers', () => {
            testCases.forEach(testCase => {
                expect(md5Hash(Buffer.from(testCase.input, 'ascii'))).to.eql(testCase.expected)
            })
        })

        it('should throw on number', () => {
            expect(() => md5Hash(123)).to.throw(/must be a string or buffer/)
        })

        it('should throw on null', () => {
            expect(() => md5Hash(null)).to.throw(/must be a string or buffer/)
        })

        it('should throw on undefined', () => {
            expect(() => md5Hash(undefined)).to.throw(/must be a string or buffer/)
        })
    })

    describe('sha1', () => {
        // https://en.wikipedia.org/wiki/SHA-1
        const testCases = [
            {expected: '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12', input: 'The quick brown fox jumps over the lazy dog'},
            {expected: 'de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3', input: 'The quick brown fox jumps over the lazy cog'},
            {expected: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', input: ''},
        ]

        it('should produce known hashes for known string values', () => {
            testCases.forEach(testCase => {
                expect(sha1Hash(testCase.input)).to.eql(testCase.expected)
            })
        })

        it('should handle buffers', () => {
            testCases.forEach(testCase => {
                expect(sha1Hash(Buffer.from(testCase.input, 'ascii'))).to.eql(testCase.expected)
            })
        })

        it('should throw on number', () => {
            expect(() => sha1Hash(123)).to.throw(/must be a string or buffer/)
        })

        it('should throw on null', () => {
            expect(() => sha1Hash(null)).to.throw(/must be a string or buffer/)
        })

        it('should throw on undefined', () => {
            expect(() => sha1Hash(undefined)).to.throw(/must be a string or buffer/)
        })
    })

    describe('sha256', () => {
        // https://en.wikipedia.org/wiki/SHA-2
        // https://www.di-mgt.com.au/sha_testvectors.html
        const testCases = [
            {expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', input: 'abc'},
            {expected: 'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1', input: 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'},
            {expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', input: ''},
        ]

        it('should produce known hashes for known string values', () => {
            testCases.forEach(testCase => {
                expect(sha256Hash(testCase.input)).to.eql(testCase.expected)
            })
        })

        it('should handle buffers', () => {
            testCases.forEach(testCase => {
                expect(sha256Hash(Buffer.from(testCase.input, 'ascii'))).to.eql(testCase.expected)
            })
        })

        it('should throw on number', () => {
            expect(() => sha256Hash(123)).to.throw(/must be a string or buffer/)
        })

        it('should throw on null', () => {
            expect(() => sha256Hash(null)).to.throw(/must be a string or buffer/)
        })

        it('should throw on undefined', () => {
            expect(() => sha256Hash(undefined)).to.throw(/must be a string or buffer/)
        })
    })

    describe('sha512', () => {
        // https://www.di-mgt.com.au/sha_testvectors.html
        const testCases = [
            {expected: 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f', input: 'abc'},
            {expected: '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909', input: 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'},
            {expected: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', input: ''},
        ]

        it('should produce known hashes for known string values', () => {
            testCases.forEach(testCase => {
                expect(sha512Hash(testCase.input)).to.eql(testCase.expected)
            })
        })

        it('should handle buffers', () => {
            testCases.forEach(testCase => {
                expect(sha512Hash(Buffer.from(testCase.input, 'ascii'))).to.eql(testCase.expected)
            })
        })

        it('should throw on number', () => {
            expect(() => sha512Hash(123)).to.throw(/must be a string or buffer/)
        })

        it('should throw on null', () => {
            expect(() => sha512Hash(null)).to.throw(/must be a string or buffer/)
        })

        it('should throw on undefined', () => {
            expect(() => sha512Hash(undefined)).to.throw(/must be a string or buffer/)
        })
    })

})
