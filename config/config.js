require('dotenv').config(); 

module.exports = {
  development: {
    username: process.env.DB_USER,
    password: process.env.MYSQL_ROOT_PASSWORD,
    database: process.env.DB_DATABASE,
    host: 'host.docker.internal',
    dialect: 'mysql',
    port: process.env.DB_PORT
  },
  test: {
    username: process.env.DB_USER,
    password: process.env.MYSQL_ROOT_PASSWORD,
    database: process.env.DB_DATABASE,
    host: 'host.docker.internal',
    dialect: 'mysql',
    port: process.env.DB_PORT
  },
  production: {
    username: process.env.DB_USER,
    password: process.env.MYSQL_ROOT_PASSWORD,
    database: process.env.DB_DATABASE,
    host: 'host.docker.internal',
    dialect: 'mysql',
    port: process.env.DB_PORT
  }
};