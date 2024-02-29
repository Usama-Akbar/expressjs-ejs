const getConnection = require("../utils/config/db");
const bcrypt = require("bcrypt");
const validator = require("validator");
const generateAccessToken = require("../utils/helpers/generateAccessToken");
const validateAccessToken = require("../utils/helpers/validateAccessToken");
const userValidation = require("../utils/helpers/UserValidation/userValidation");

const validatePassword = (password) => {
  // Password validation (one uppercase, one lowercase, one special character, one number, minimum 8 length)
  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
};

// Function to record login activity
const recordLoginActivity = (userID, loginSuccess, ipAddress) => {
  getConnection((err, connection) => {
    if (err) {
      console.error("Error connecting to the database:", err);
      return;
    }

    const insertLoginActivityQuery = `
      INSERT INTO login_activities (userID, loginTimestamp, ipAddress, loginSuccess)
      VALUES (?, CURRENT_TIMESTAMP, ?, ?)
    `;

    connection.query(
      insertLoginActivityQuery,
      [userID, ipAddress, loginSuccess],
      (insertErr, insertResults) => {
        connection.release(); // Release the connection back to the pool

        if (insertErr) {
          console.error("Error recording login activity:", insertErr);
        } else {
          console.log("Login activity recorded successfully");
        }
      }
    );
  });
};

module.exports = {
  signUp: async function (req, res, next) {
    try {
      const userData = req.body;

      // Validate user data using Joi
      const { error } = userValidation(userData);
      if (error) {
        return res.status(400).json({
          message: error.details[0].message,
          result: false,
        });
      }

      // Email validation
      if (!validator.isEmail(userData.email)) {
        return res.status(400).json({
          message: "Invalid email format",
          result: false,
        });
      }

      // Password validation
      if (!validatePassword(userData.password)) {
        return res.status(400).json({
          message:
            "Password must contain at least one uppercase letter, one lowercase letter, one special character, one number, and be a minimum of 8 characters long",
          result: false,
        });
      }

      getConnection((err, connection) => {
        if (err) {
          res.status(500).send("Error connecting to the database");
          return;
        }

        // Check if the email is already registered
        const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
        connection.query(
          checkEmailQuery,
          [userData.email],
          (emailErr, emailResults) => {
            if (emailErr) {
              connection.release();
              console.error("Error checking email existence:", emailErr);
              return res.status(500).json({
                message: "Error checking email existence",
                result: false,
              });
            }

            if (emailResults.length > 0) {
              connection.release();
              return res.status(400).json({
                message: "Email already registered",
                result: false,
              });
            }

            // Hash the password
            bcrypt.hash(userData.password, 10, (hashErr, hashedPassword) => {
              if (hashErr) {
                connection.release();
                console.error("Error hashing password: ", hashErr);
                return res.status(500).send("Error hashing password");
              }

              // SQL query to insert user data into the 'users' table
              const insertQuery =
                "INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)";

              // Execute the query
              connection.query(
                insertQuery,
                [
                  userData.firstname,
                  userData.lastname,
                  userData.email,
                  hashedPassword,
                ],
                (insertErr, results) => {
                  connection.release(); // Release the connection back to the pool

                  if (insertErr) {
                    console.error("Error registering user:", insertErr);
                    return res.status(500).json({
                      message: "Error registering user",
                      result: false,
                    });
                  }

                  res.status(200).json({
                    message: "User registered successfully",
                    result: true,
                  });
                }
              );
            });
          }
        );
      });
    } catch (e) {
      console.log("ERROR is", e);
      res.status(500).json({
        message: "There was a problem registering the user, please try again.",
        result: false,
      });
    }
  },
  signIn: async function (req, res, next) {
    try {
      const { email, password } = req.body;

      // Input validation
      if (!email) {
        return res.status(400).json({
          message: "Email is required",
          result: false,
        });
      } else if (!password) {
        return res.status(400).json({
          message: "Password is required",
          result: false,
        });
      }

      // Email validation
      if (!validator.isEmail(email)) {
        return res.status(400).json({
          message: "Invalid email format",
          result: false,
        });
      }

      getConnection((err, connection) => {
        if (err) {
          res.status(500).send("Error connecting to the database");
          return;
        }

        const insertAuthQuery = `INSERT INTO auth_tokens (user_id, token, expiration_timestamp) VALUES (?, ?, ?)`;
        const updateAuthQuery = `UPDATE auth_tokens SET token = ?, expiration_timestamp = ? WHERE user_id = ?`;
        const getAuthQuery = `SELECT * FROM auth_tokens WHERE user_id = ?`;
        // SQL query to insert user data into the 'users' table
        const selectQuery = "SELECT * FROM users WHERE email = ?";

        // Execute the query
        connection.query(selectQuery, [email], (err, results) => {
          connection.release(); // Release the connection back to the pool

          if (err) {
            console.error("Error retrieving user data: ", err);
            res.status(500).send("Error retrieving user data");
            return;
          }

          if (results.length === 0) {
            // Record unsuccessful login activity
            recordLoginActivity(email, false, req.ip);
            res.status(401).json({
              message: "Invalid Credentials ",
              result: false,
            });
            return;
          }

          const hashedPassword = results[0].password;

          bcrypt.compare(password, hashedPassword, (bcryptErr, isMatch) => {
            if (bcryptErr) {
              console.error("Error comparing passwords: ", bcryptErr);
              res.status(500).send("Error comparing passwords");
              return;
            }

            if (!isMatch) {
              // Record unsuccessful login activity
              recordLoginActivity(results[0].user_id, false, req.ip);
              res.status(401).json({
                message: "Invalid Credentials",
                result: false,
              });
              return;
            }

            // Generate a JWT token for authentication
            // Adjust as needed
            connection.query(
              getAuthQuery,
              [results[0].user_id],
              (getAuthErr, authResults) => {
                if (getAuthErr) {
                  console.error("Error checking auth token: ", getAuthErr);
                  res.status(500).send("Error checking auth token");
                  return;
                }

                const token = generateAccessToken(results[0]);
                const expirationTimestamp = new Date(
                  Date.now() + 24 * 60 * 60 * 1000
                );

                if (authResults.length > 0) {
                  // If a record exists, update it
                  connection.query(
                    updateAuthQuery,
                    [token, expirationTimestamp, results[0].user_id],
                    (updateErr, updateResults) => {
                      if (updateErr) {
                        console.error("Error updating token: ", updateErr);
                        res.status(500).send("Error updating token");
                        return;
                      }
                      // Record successful login activity
                      recordLoginActivity(results[0].user_id, true, req.ip);
                      res.status(200).json({ message: "Logged in Successfully", token });
                    }
                  );
                } else {
                  // If no record exists, insert a new one
                  connection.query(
                    insertAuthQuery,
                    [results[0].user_id, token, expirationTimestamp],
                    (insertErr, insertResults) => {
                      if (insertErr) {
                        console.error("Error inserting token: ", insertErr);
                        res.status(500).send("Error inserting token");
                        return;
                      }
                      // Record successful login activity
                      recordLoginActivity(results[0].user_id, true, req.ip);
                      res.status(200).json({ message: "Logged in Successfully", token });
                    }
                  );
                }
              }
            );
          });
        });
      });
    } catch (e) {
      console.log("ERROR is", e);
      res.status(500).json({
        message:
          "There was a problem in Logging In the user, please try again.",
        result: false,
      });
    }
  },

  getAllUsers: async function (req, res, next) {
    try {
      getConnection((err, connection) => {
        if (err) {
          res.status(500).send("Error connecting to the database");
          return;
        }
  
        // SQL query to retrieve user data from 'login_activities' and 'users' tables
        const getQuery = `
          SELECT la.*, u.firstname, u.lastname, u.email
          FROM login_activities la
          INNER JOIN users u ON la.userID = u.user_id
        `;
  
        // Execute the query
        connection.query(getQuery, (err, results) => {
          connection.release(); // Release the connection back to the pool
          if (err) {
            console.error("Error retrieving user data:", err);
            res.status(500).json({
              message: "There was a problem in retrieving the users list, please try again.",
              result: false,
            });
            return;
          }
          // IP ADDRESS WILL BE ::1 in development environment and will be changed when server is pushed to production
          res.status(200).render("list", {
            users: results,
            result: true,
          });
        });
      });
    } catch (e) {
      console.log("ERROR is", e);
      res.status(500).json({
        message: "There was a problem in registering the users list, please try again.",
        result: false,
      });
    }
  },  
  signOut: async function (req, res, next) {
    try {
      getConnection((err, connection) => {
        if (err) {
          res.status(500).send("Error connecting to the database");
          return;
        }

        const token = req.header("x-access-token");
        if (!token) {
          return res
            .status(401)
            .json({ message: "Unauthorized - Missing token" });
        }

        // SQL queries to delete the token and corresponding entry
        const deleteTokenQuery = "DELETE FROM auth_tokens WHERE token = ?";

        // Execute the queries
        connection.query(
          deleteTokenQuery,
          [token],
          (deleteErr, deleteResults) => {
            if (deleteErr) {
              console.error("Error deleting token:", deleteErr);
              res.status(500).send("Error deleting token");
              return;
            }

            // Check if any rows were affected (indicating a successful deletion)
            if (deleteResults.affectedRows > 0) {
              res.status(200).json({
                message: "User signed out successfully",
                result: true,
              });
            } else {
              res.status(401).json({
                message: "Unauthorized - Invalid token",
                result: false,
              });
            }
          }
        );
      });
    } catch (e) {
      console.log("ERROR is", e);
      res.status(500).json({
        message: "There was a problem signing out the user, please try again.",
        result: false,
      });
    }
  },
};
