const { createClient, defineScript } = require('redis');
const { sendSixDigitCodeScript } = require('../helpers/lua-scripts');

const REDIS_EXPIRY_TIME = 2 * 60 * 60; // IN SECONDS
const sixDigitCodeRedis = async (userId, operation, value = '') => {
  const client = createClient({
    scripts: {
      sendSixDigitCode: defineScript({
        NUMBER_OF_KEYS: 1,
        SCRIPT: sendSixDigitCodeScript,
        transformArguments (userId, operation, value, REDIS_EXPIRY_TIME) {
          return [userId, operation, value, REDIS_EXPIRY_TIME];
        },
        transformReply (reply) {
          return reply;
        }
      })
    }
  });
  // Open connection
  await client.connect();
  // action
  const response = await client.sendSixDigitCode(userId, operation, value, REDIS_EXPIRY_TIME.toString());
  // close connection gracefully
  client.quit();
  return response;
};

module.exports = { sixDigitCodeRedis };
