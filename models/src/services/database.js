const {User} = require('../..')

const findAllUsers = async () => {
    return await User.findAll()
}

module.exports = {findAllUsers}