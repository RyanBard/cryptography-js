const {
    scryptSync,
    randomBytes,
    timingSafeEqual,
} = require('crypto')

function createUserRecord(username, password) {
    if (!username || !password) {
        throw new Error('Must supply a username and password!')
    }
    if (password.length < 8) {
        throw new Error('Password must be at least 8 characters!')
    }
    const strong = /[a-z]/.test(password) &&
        /[A-Z]/.test(password) &&
        /[0-9]/.test(password) &&
        /[-!@#$%^&*()=_+,.?<>;:'"{}|?`~]/.test(password)
    if (!strong) {
        throw new Error('Password must have at least one lower, one upper, one number, and one special character!')
    }

    const salt = randomBytes(16).toString('hex')
    const hashedPassword = scryptSync(password, salt, 64).toString('hex')
    return {
        username,
        salt,
        hashedPassword,
    }
}

function userPasswordMatches(username, password, dbRecord) {
    if (username !== dbRecord.username) {
        throw new Error('Wrong db record looked up!')
    }
    const hashedToCheckBuffer = scryptSync(password, dbRecord.salt, 64)
    const hashedPasswordBuffer = Buffer.from(dbRecord.hashedPassword, 'hex')
    return timingSafeEqual(hashedToCheckBuffer, hashedPasswordBuffer)
}

module.exports = {
    createUserRecord,
    userPasswordMatches,
}
