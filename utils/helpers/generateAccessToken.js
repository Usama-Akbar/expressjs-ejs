var express = require("express");
var router = express.Router();
require("dotenv").config();
const jwt = require("jsonwebtoken");
const cryprto = require("crypto");

// Generate Access Token

const generateAccessToken = (data) => {
  try {
    // set token expiration time
    const expiresIn = "1d";
    // create a payload object
    const payload = data;

    // sign the payload with your secret key
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: expiresIn,
    });
    // return the token
    return token;
  } catch (e) {
    console.log(e);
  }
};

module.exports = generateAccessToken;
