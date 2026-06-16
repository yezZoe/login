const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = 3000;



app.use(express.urlencoded({ extended: true }));
app.use(express.json());


app.use(express.static(path.join(__dirname, 'public')));


const db = new sqlite3.Database('./usuarios.db', (err) => {
    if (err) console.error("Error al conectar a la base de datos:", err);
    else console.log("Conectado con éxito a SQLite");
});


db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE,
    contrasena TEXT
)`);





app.post('/registro', async (req, res) => {
    const { usuario, contrasena } = req.body;

    try {
       
        const contrasenaEncriptada = await bcrypt.hash(contrasena, 10);

        const sql = `INSERT INTO usuarios (usuario, contrasena) VALUES (?, ?)`;
        db.run(sql, [usuario, contrasenaEncriptada], function(err) {
            if (err) {
                if (err.message.includes("UNIQUE")) {
                    return res.send("El nombre de usuario ya existe. Intenta con otro.");
                }
                return res.status(500).send("Error al registrar el usuario.");
            }
            
            res.redirect('/login.html');
        });
    } catch {
        res.status(500).send("Error en el servidor.");
    }
});


app.post('/login', (req, res) => {
    const { usuario, contrasena } = req.body;

    const sql = `SELECT * FROM usuarios WHERE usuario = ?`;
    db.get(sql, [usuario], async (err, row) => {
        if (err) return res.status(500).send("Error en el servidor.");
        if (!row) return res.send("Usuario o contraseña incorrectos.");

        
        const coinciden = await bcrypt.compare(contrasena, row.contrasena);

        if (coinciden) {
            
            res.redirect('/bienvenido.html');
        } else {
            res.send("Usuario o contraseña incorrectos.");
        }
    });
});


app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});