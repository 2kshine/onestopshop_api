const logger = require('../../config/cloudwatch-logs')

const authenticate = (req, res)=> {
    logger.log('authentication', 'Random message test', req, 'info', {payload: 'sampledata'})
}

module.exports = {authenticate}