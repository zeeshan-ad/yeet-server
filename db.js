const Pool = require('pg').Pool;

const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "yeet",
  password: "p$qladmin2k23",
  port:5432, // default PostgreSQL port
});

module.exports = pool;