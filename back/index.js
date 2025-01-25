const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("./db");
const cors = require("cors");

const app = express();
app.use(cors({ origin: "http://localhost:5173" }));
app.use(express.json());

const JWT_SECRET = "mi_secreto";
const PORT = 3000;

app.post("/usuarios", async (req, res) => {
    try {
        const { email, password, rol, lenguage } = req.body;

        const queryCheck = "SELECT * FROM usuarios WHERE email = $1";
        const { rows } = await pool.query(queryCheck, [email]);
        if (rows.length > 0) {
            return res.status(400).send("El email ya está registrado");
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        const queryInsert = "INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4)";
        await pool.query(queryInsert, [email, hashedPassword, rol, lenguage]);

        res.status(201).send("Usuario registrado con éxito");
    } catch (error) {
        console.error(error);
        res.status(500).send("Error al registrar usuario");
    }
});

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const query = "SELECT * FROM usuarios WHERE email = $1";
        const { rows } = await pool.query(query, [email]);
        const usuario = rows[0];

        if (!usuario || !bcrypt.compareSync(password, usuario.password)) {
            return res.status(401).send("Credenciales incorrectas");
        }

        const token = jwt.sign({ email: usuario.email }, JWT_SECRET);
        res.send({ token });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error al iniciar sesión");
    }
});


app.get("/usuarios", async (req, res) => {
    try {
        const authHeader = req.headers["authorization"];
        const token = authHeader && authHeader.split(" ")[1];

        if (!token) {
            return res.status(401).json({ error: "Token requerido" });
        }

        jwt.verify(token, JWT_SECRET, async (err, decoded) => {
            if (err) {
                return res.status(403).json({ error: "Token inválido" });
            }

            const query = "SELECT email, rol, lenguage FROM usuarios WHERE email = $1";
            const { rows } = await pool.query(query, [decoded.email]);

            if (rows.length === 0) {
                return res.status(404).json({ error: "Usuario no encontrado" });
            }

            res.json(rows[0]);
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error al obtener usuario" });
    }
});
