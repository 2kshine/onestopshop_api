'use strict';
/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('Socials', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4, // Default value generated using UUIDV4
        primaryKey: true,
        unique:true
      },
      instagram_access_token: {
        type: Sequelize.TEXT
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE
      }
    });
  },
  async down(queryInterface, Sequelize) {
    await queryInterface.dropTable('Socials');
  }
};