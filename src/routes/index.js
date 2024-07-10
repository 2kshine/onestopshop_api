const express = require('express')
const router = express();
const authenticateRoutes = require('./authentication-routes')
router.use('/auth', authenticateRoutes)

module.exports = router