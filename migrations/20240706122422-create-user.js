'use strict';
/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up (queryInterface, Sequelize) {
    await queryInterface.createTable('Users', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4, // Default value generated using UUIDV4
        primaryKey: true,
        unique: true
      },
      username: {
        type: Sequelize.STRING
      },
      email_address: {
        type: Sequelize.STRING
      },
      password: {
        type: Sequelize.STRING
      },
      is_email_verified: {
        type: Sequelize.BOOLEAN
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      deletedAt: {
        type: Sequelize.DATE
      }
    });
  },
  async down (queryInterface, Sequelize) {
    await queryInterface.dropTable('Users');
  }
};
