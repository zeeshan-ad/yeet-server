require('dotenv').config();
const jwt = require('jsonwebtoken');

function generateAccessToken(userInfo) {
  return jwt.sign(userInfo, process.env.JWT_SECRET_SAUCE, { expiresIn: '1800s' });
}

module.exports = generateAccessToken;