const authenticationController = require('../controllers/authentication-controller')
const express = require("express");
const router = express.Router();
router.get('/',  authenticationController.authenticate)

module.exports = router