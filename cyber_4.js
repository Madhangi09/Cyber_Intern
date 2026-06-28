const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();

app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: "secure_secret_key",
    resave: false,
    saveUninitialized: false
}));

// MySQL Connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "password",
    database: "secure_login"
});

db.connect(err => {
    if (err) throw err;
    console.log("Connected to MySQL");
});

// Home
app.get("/", (req, res) => {
    if (req.session.user) {
        res.send(`
            <h2>Welcome ${req.session.user}</h2>
            <a href="/logout">Logout</a>
        `);
    } else {
        res.send(`
            <a href="/register">Register</a><br><br>
            <a href="/login">Login</a>
        `);
    }
});

// Register Page
app.get("/register", (req, res) => {
    res.send(`
        <h2>Register</h2>
        <form method="POST">
            Username: <input type="text" name="username"><br><br>
            Password: <input type="password" name="password"><br><br>
            <button type="submit">Register</button>
        </form>
    `);
});

// Register
app.post("/register", async (req, res) => {

    let { username, password } = req.body;

    if (!username || !password)
        return res.send("All fields are required.");

    if (password.length < 6)
        return res.send("Password must be at least 6 characters.");

    const hash = await bcrypt.hash(password, 10);

    db.query(
        "INSERT INTO users(username,password) VALUES(?,?)",
        [username, hash],
        (err) => {
            if (err)
                return res.send("Username already exists.");

            res.send("Registration Successful! <a href='/login'>Login</a>");
        }
    );
});

// Login Page
app.get("/login", (req, res) => {
    res.send(`
        <h2>Login</h2>
        <form method="POST">
            Username: <input type="text" name="username"><br><br>
            Password: <input type="password" name="password"><br><br>
            <button type="submit">Login</button>
        </form>
    `);
});

// Login
app.post("/login", (req, res) => {

    let { username, password } = req.body;

    db.query(
        "SELECT * FROM users WHERE username=?",
        [username],
        async (err, result) => {

            if (result.length == 0)
                return res.send("Invalid Username");

            const user = result[0];

            const match = await bcrypt.compare(password, user.password);

            if (!match)
                return res.send("Invalid Password");

            req.session.user = username;

            res.redirect("/");
        }
    );

});

// Logout
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

// Server
app.listen(3000, () => {
    console.log("Server running at http://localhost:3000");
});