const {expect} = require('chai')

const {
    createUserRecord,
    userPasswordMatches,
} = require('../src/salting')

describe('salting', () => {

    describe('createUserRecord', () => {
        it('should salt and hash a users password', () => {
            const inputUsername = 'foo'
            const inputPassword = 'Bar123^^'
            const dbRecord1 = createUserRecord(inputUsername, inputPassword)
            expect(dbRecord1.username).to.eql(inputUsername)
            expect(dbRecord1.salt.length).to.eql(32)
            expect(dbRecord1.hashedPassword).to.not.eql(inputPassword)
            expect(dbRecord1.hashedPassword.length).to.eql(128)

            const dbRecord2 = createUserRecord(inputUsername, inputPassword)
            expect(dbRecord2.username).to.eql(inputUsername)
            expect(dbRecord2.salt.length).to.eql(32)
            expect(dbRecord2.hashedPassword).to.not.eql(inputPassword)
            expect(dbRecord2.hashedPassword.length).to.eql(128)

            expect(dbRecord1.hashedPassword).to.not.eql(dbRecord2.hashedPassword)
        })

        it('should throw missing username', () => {
            const inputUsername = ''
            const inputPassword = 'Bar123^^'
            expect(() => createUserRecord(inputUsername, inputPassword)).to.throw(/username and password/)
        })

        it('should throw on missing password', () => {
            const inputUsername = 'foo'
            const inputPassword = ''
            expect(() => createUserRecord(inputUsername, inputPassword)).to.throw(/username and password/)
        })

        it('should throw on short passwords', () => {
            const inputUsername = 'foo'
            const inputPassword = 'Bar123^'
            expect(() => createUserRecord(inputUsername, inputPassword)).to.throw(/must be at least 8 characters/)
        })

        it('should throw on weak passwords', () => {
            const inputUsername = 'foo'
            const inputPassword = 'Bar12345'
            expect(() => createUserRecord(inputUsername, inputPassword)).to.throw(/must have at least one/)
        })
    })

    describe('userPasswordMatches', () => {
        it('should return true if the username and password both match', () => {
            const inputUsername = 'foo'
            const inputPassword = 'Bar123^^'
            const dbRecord = createUserRecord(inputUsername, inputPassword)
            expect(userPasswordMatches(inputUsername, inputPassword, dbRecord)).to.eql(true)
        })

        it('should return false if the password does not match', () => {
            const inputUsername = 'foo'
            const inputPassword = 'Bar123^^'
            const dbRecord = createUserRecord(inputUsername, inputPassword)
            expect(userPasswordMatches(inputUsername, inputPassword + '000', dbRecord)).to.eql(false)
        })

        it('should throw on invalid input if the username does not match the dbRecord', () => {
            const inputUsername = 'foo'
            const inputPassword = 'Bar123^^'
            const dbRecord = createUserRecord(inputUsername, inputPassword)
            expect(() => userPasswordMatches(inputUsername + 'bar', inputPassword, dbRecord)).to.throw(/Wrong db record/)
        })
    })

})
