// db.js
require("dotenv").config(); // Load environment variables first
const mysql = require("mysql2");

// MySQL Connection Configuration
const dbConfig = {
  host: process.env.DB_HOSTNAME,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
};

// db.js
console.log("DB Configuration:", dbConfig);


// Create a pool to handle multiple connections
const pool = mysql.createPool(dbConfig);

// Function to get a connection from the pool
const getConnection = (callback) => {
  pool.getConnection((err, connection) => {
    if (err) {
      console.error("Error connecting to MySQL: ", err);
      return callback(err, null);
    }
    callback(null, connection);
  });
};

module.exports = getConnection;
