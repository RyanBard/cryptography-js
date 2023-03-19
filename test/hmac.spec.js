const {expect} = require('chai')

const {
    sha256Hmac,
    sha512Hmac,
} = require('../src/hmac')

describe('hmac', () => {

    // https://www.rfc-editor.org/rfc/rfc4231
    const testCases = [
        {
            expectedSha256: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
            expectedSha512: '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
            asciiCompatible: true,
            inputMessage: Buffer.from('Hi There', 'ascii'),
            inputKey: Buffer.from('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex'),
        },
        {
            expectedSha256: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
            expectedSha512: '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
            asciiCompatible: true,
            inputMessage: Buffer.from('what do ya want for nothing?', 'ascii'),
            inputKey: Buffer.from('Jefe', 'ascii'),
        },
        {
            expectedSha256: '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
            expectedSha512: 'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
            asciiCompatible: false,
            inputMessage: Buffer.from('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', 'hex'),
            inputKey: Buffer.from('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'hex'),
        },
        {
            expectedSha256: '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
            expectedSha512: 'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
            asciiCompatible: false,
            inputMessage: Buffer.from('cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd', 'hex'),
            inputKey: Buffer.from('0102030405060708090a0b0c0d0e0f10111213141516171819', 'hex'),
        },
        {
            expectedSha256: 'a3b6167473100ee06e0c796c2955552b',
            expectedSha512: '415fad6271580a531d4179bc891d87a6',
            asciiCompatible: true,
            truncateBits: 128,
            inputMessage: Buffer.from('Test With Truncation', 'ascii'),
            inputKey: Buffer.from('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c', 'hex'),
        },
        {
            expectedSha256: '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
            expectedSha512: '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
            asciiCompatible: false,
            inputMessage: Buffer.from('Test Using Larger Than Block-Size Key - Hash Key First', 'ascii'),
            inputKey: Buffer.from('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'hex'),
        },
        {
            expectedSha256: '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
            expectedSha512: 'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
            asciiCompatible: false,
            inputMessage: Buffer.from('This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.', 'ascii'),
            inputKey: Buffer.from('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'hex'),
        },
    ]

    describe('sha256Hmac', () => {
        it('should produce known hmac hashes for known buffer inputs', () => {
            testCases.forEach(testCase => {
                let result = sha256Hmac(testCase.inputMessage, testCase.inputKey)
                if (testCase.truncateBits) {
                    result = result.slice(0, ((testCase.truncateBits / 8) * 2))
                }
                expect(result).to.eql(testCase.expectedSha256)
            })
        })

        it('should produce known hmac hashes for known ascii inputs', () => {
            testCases.forEach(testCase => {
                if (!testCase.asciiCompatible) {
                    return
                }
                let result = sha256Hmac(testCase.inputMessage.toString('ascii'), testCase.inputKey.toString('ascii'))
                if (testCase.truncateBits) {
                    result = result.slice(0, ((testCase.truncateBits / 8) * 2))
                }
                expect(result).to.eql(testCase.expectedSha256)
            })
        })

        it('should throw on empty key', () => {
            const inputMessage = 'foo'
            const inputKey = ''
            expect(() => sha256Hmac(inputMessage, inputKey)).to.throw(/specify a key/)
        })

        it('should throw when key is a number', () => {
            const inputMessage = 'foo'
            const inputKey = 123
            expect(() => sha256Hmac(inputMessage, inputKey)).to.throw(/key must be a string or buffer/)
        })

        it('should throw when key is null', () => {
            const inputMessage = 'foo'
            const inputKey = null
            expect(() => sha256Hmac(inputMessage, inputKey)).to.throw(/key must be a string or buffer/)
        })

        it('should throw when key is undefined', () => {
            const inputMessage = 'foo'
            const inputKey = undefined
            expect(() => sha256Hmac(inputMessage, inputKey)).to.throw(/key must be a string or buffer/)
        })

        it('should throw when message is a number', () => {
            const inputMessage = 123
            const inputKey = 'foo'
            expect(() => sha256Hmac(inputMessage, inputKey)).to.throw(/message must be a string or buffer/)
        })

        it('should throw when message is null', () => {
            const inputMessage = null
            const inputKey = 'foo'
            expect(() => sha256Hmac(inputMessage, inputKey)).to.throw(/message must be a string or buffer/)
        })

        it('should throw when message is undefined', () => {
            const inputMessage = undefined
            const inputKey = 'foo'
            expect(() => sha256Hmac(inputMessage, inputKey)).to.throw(/message must be a string or buffer/)
        })
    })

    describe('sha512Hmac', () => {
        it('should produce known hmac hashes for known buffer inputs', () => {
            testCases.forEach(testCase => {
                let result = sha512Hmac(testCase.inputMessage, testCase.inputKey)
                if (testCase.truncateBits) {
                    result = result.slice(0, ((testCase.truncateBits / 8) * 2))
                }
                expect(result).to.eql(testCase.expectedSha512)
            })
        })

        it('should produce known hmac hashes for known ascii inputs', () => {
            testCases.forEach(testCase => {
                if (!testCase.asciiCompatible) {
                    return
                }
                let result = sha512Hmac(testCase.inputMessage.toString('ascii'), testCase.inputKey.toString('ascii'))
                if (testCase.truncateBits) {
                    result = result.slice(0, ((testCase.truncateBits / 8) * 2))
                }
                expect(result).to.eql(testCase.expectedSha512)
            })
        })

        it('should throw on empty key', () => {
            const inputMessage = 'foo'
            const inputKey = ''
            expect(() => sha512Hmac(inputMessage, inputKey)).to.throw(/specify a key/)
        })

        it('should throw when key is a number', () => {
            const inputMessage = 'foo'
            const inputKey = 123
            expect(() => sha512Hmac(inputMessage, inputKey)).to.throw(/key must be a string or buffer/)
        })

        it('should throw when key is null', () => {
            const inputMessage = 'foo'
            const inputKey = null
            expect(() => sha512Hmac(inputMessage, inputKey)).to.throw(/key must be a string or buffer/)
        })

        it('should throw when key is undefined', () => {
            const inputMessage = 'foo'
            const inputKey = undefined
            expect(() => sha512Hmac(inputMessage, inputKey)).to.throw(/key must be a string or buffer/)
        })

        it('should throw when message is a number', () => {
            const inputMessage = 123
            const inputKey = 'foo'
            expect(() => sha512Hmac(inputMessage, inputKey)).to.throw(/message must be a string or buffer/)
        })

        it('should throw when message is null', () => {
            const inputMessage = null
            const inputKey = 'foo'
            expect(() => sha512Hmac(inputMessage, inputKey)).to.throw(/message must be a string or buffer/)
        })

        it('should throw when message is undefined', () => {
            const inputMessage = undefined
            const inputKey = 'foo'
            expect(() => sha512Hmac(inputMessage, inputKey)).to.throw(/message must be a string or buffer/)
        })
    })

})
