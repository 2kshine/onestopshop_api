'use strict';
const {
  Model
} = require('sequelize');
const { v4: uuidv4 } = require('uuid');
const User = require('./user');
module.exports = (sequelize, DataTypes) => {
  class UserInfo extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate (models) {
      // define association here
      UserInfo.belongsTo(models.User, {
        foreignKey: 'userId'
      });
    }
  }
  UserInfo.init({
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4, // Default value generated using UUIDV4
      primaryKey: true,
      unique: true
    },
    first_name: DataTypes.STRING,
    last_name: DataTypes.STRING,
    date_of_birth: DataTypes.DATE,
    country: DataTypes.STRING,
    userId: { // Foreign key
      type: DataTypes.UUID,
      unique: true
    }
  }, {
    sequelize,
    modelName: 'UserInfo'
  });

  UserInfo.beforeCreate((user) => {
    UserInfo.id = uuidv4(); // Assign a new UUID using the uuid() function from 'uuid' package
  });

  return UserInfo;
};
