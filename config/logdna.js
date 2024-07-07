const logdna = require('@logdna/logger')
require('dotenv').config()
const options = {
  app: 'onestopshop',
  level: 'warn' // set a default for when level is not provided in function calls
}

const logger = logdna.createLogger(process.env.LOGDNA_KEY, options)

module.exports = {logger}