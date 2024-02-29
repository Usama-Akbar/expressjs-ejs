var express = require("express");
var router = express.Router();
require("dotenv").config();

const UserController = require("../controllers/UserController");

// Sign-up User

router.post("/sign-up", UserController.signUp);

//  Sign-in User

router.post("/sign-in", UserController.signIn);

// get all users

router.get("/list", UserController.getAllUsers);

// Sign-out User

router.post("/sign-out", UserController.signOut);

module.exports = router;
