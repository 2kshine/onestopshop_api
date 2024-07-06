'use strict';
const {
  Model
} = require('sequelize');
const { v4: uuidv4 } = require('uuid');
const User = require('./user');
module.exports = (sequelize, DataTypes) => {
  class Socials extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
      Socials.belongsTo(User, {
        foreignKey: 'userId'
      })
    }
  }
  Socials.init({
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4, // Default value generated using UUIDV4
      primaryKey: true,
      unique:true
    },
    instagram_access_token: DataTypes.STRING,
    userId: { // Foreign key
      type: DataTypes.UUID,
      allowNull: false,
    }
  }, {
    sequelize,
    modelName: 'Socials',
  });

  Socials.beforeCreate((user) => {
    socials.id = uuidv4(); // Assign a new UUID using the uuid() function from 'uuid' package
  });

  return Socials;
};