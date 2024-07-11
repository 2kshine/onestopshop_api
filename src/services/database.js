const { User } = require('../../models');

const findAUser = async (payload) => {
  return await User.findOne({
    where: payload
  });
};

const updateAUser = async (user, payload) => {
  return await user.update(payload);
};

const createAUser = async (payload) => {
  return await User.create(payload);
};
const deleteAUser = async (payload) => {
  return await User.destroy({
    where: payload
  });
};

module.exports = { findAUser, updateAUser, createAUser, deleteAUser };
