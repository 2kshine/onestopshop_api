const crypto = require('crypto');
const getRandomSixDigitInteger = () => {
  const randomBytes = crypto.randomBytes(3); // A random 3-byte hexadecimal number (6 hex digits)
  const randomNumber = parseInt(randomBytes.toString('hex'), 16); // parse it to integer

  // Ensure the number is six digits by taking modulo 1000000
  const sixDigitNumber = randomNumber % 1000000;

  return sixDigitNumber;
};

module.exports = { getRandomSixDigitInteger };
