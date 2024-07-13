const { passwordStrength } = require('check-password-strength');

const isEmailValid = (emailAddress) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(emailAddress);
};

const isUsernameValid = (username) => {
  const usernameRegex = /\S\s+\S/;
  return !usernameRegex.test(username); // username test passed means it has spaces
};

const isPasswordStrong = (password) => {
  return passwordStrength(password).value?.toLowerCase() === 'strong';
};

module.exports = {
  isEmailValid,
  isUsernameValid,
  isPasswordStrong
};
