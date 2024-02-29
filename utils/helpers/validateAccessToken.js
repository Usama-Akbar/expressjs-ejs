// authMiddleware.js

const jwt = require("jsonwebtoken");
const cryprto = require("crypto");

// Middleware to validate access token
const validateAccessToken = (token) => {
  // Get the token from the Authorization header

  try {
    // Verify the token using the secret key

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded) {
      return true;
    } else {
      return false;
    }
  } catch (error) {
    console.log("error", error);
  }
};

module.exports = validateAccessToken;
