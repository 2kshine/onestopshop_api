'use strict';
const {
  Model
} = require('sequelize');
const { v4: uuidv4 } = require('uuid');
const UserInfo = require('./userinfo');
const Socials = require('./socials');
module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
      User.hasOne(UserInfo, {
        as: 'user_user_info',
        foreignKey: 'userId'
      })
      User.hasMany(Socials, {
        as: 'user_socials',
        foreignKey: 'userId'
      })
    }
  }
  User.init({
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4, // Default value generated using UUIDV4
      primaryKey: true,
      unique:true
    },
    user_name: DataTypes.STRING,
    email_address: DataTypes.STRING,
    password: DataTypes.STRING,
  }, {
    sequelize,
    modelName: 'User',
    paranoid: true
  });

  User.beforeCreate((user) => {
    user.id = uuidv4(); // Assign a new UUID using the uuid() function from 'uuid' package
  });

  return User;
};