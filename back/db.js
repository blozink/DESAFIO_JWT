const { Pool } = require("pg");

const pool = new Pool({
    user: "juanca",
    host: "localhost",
    database: "softjobs",
    password: "",
    port: 5432,
});

module.exports = pool;
