const crypto = require('crypto');

/**
 * generates random string of characters i.e salt
 * @function
 * @param {number} length - Length of the random string.
 */
const generateSalt = (length) => crypto.randomBytes(Math.ceil(length/2))
    .toString('hex')
    .slice(0,length);

/**
 * hash password with sha512.
 * @function
 * @param {string} password - List of required fields.
 * @param {string} salt - Data to be validated.
 */
const hash = (password, salt) => {
  const hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
  hash.update(password);
  const value = hash.digest('hex');
  return {
    salt,
    passwordHash: value
  };
};

const saltHashPassword = (password) =>  {
  const salt = generateSalt(16);
  return hash(password, salt);
};

const fromBase64 = token => new Buffer(token, 'base64').toString('ascii');

const getCredentialsFromAuthToken = token => {
  const decoded = fromBase64(token);
  const [ username, password ] = decoded.split(':');
  return {
    username, password
  }
};

const validatePassword = (input, hashedPassword, passwordSalt) => {
  const hashedInput = hash(input, passwordSalt);

  console.log("input", input);
  console.log("hashedInput", hashedInput);
  console.log("hashedPassword", hashedPassword);
  console.log("passwordSalt", passwordSalt);

  return hashedInput.passwordHash === hashedPassword;
};

module.exports = {
  getCredentialsFromAuthToken,
  validatePassword,
  saltHashPassword
};


