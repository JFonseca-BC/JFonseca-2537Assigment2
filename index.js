'use strict';

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient, ServerApiVersion } = require('mongodb');
const path = require('path');
const fs = require('fs');

const port = process.env.PORT

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

if (!mongodb_host || !mongodb_user || !mongodb_password || !mongodb_database || !mongodb_session_secret || !node_session_secret) {
    console.error("FATAL ERROR: Missing required environment variables. Check your .env file.");
    process.exit(1);
}

const mongoUri = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority&appName=Assignment1`;

const client = new MongoClient(mongoUri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

let db;
let userCollection;

async function connectDB() {
    try {
        await client.connect();
        console.log("Successfully connected to MongoDB Atlas");
        db = client.db(mongodb_database);
        userCollection = db.collection("users");
    } catch (err) {
        console.error("Failed to connect to MongoDB", err);
        process.exit(1);
    }
}

const app = express();

app.use(express.urlencoded({ extended: false }));

const mongoStore = MongoStore.create({
    mongoUrl: mongoUri,
    crypto: {
        secret: mongodb_session_secret
    },
    dbName: mongodb_database,
    collectionName: 'sessions',
    ttl: 60 * 60
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: 60 * 60 * 1000
    }
}));

function sendErrorPage(res, message, backLink, statusCode = 400) {
    fs.readFile(path.join(__dirname, 'html', 'error.html'), 'utf8', (err, data) => {
        if (err) {
            console.error("Error reading error.html:", err);
            return res.status(500).send("Internal Server Error");
        }
        let htmlContent = data.replace('{{errorMessage}}', message);
        htmlContent = htmlContent.replace('{{back}}', backLink);
        res.status(statusCode).send(htmlContent);
    });
}

app.get('/', (req, res) => {
    if (req.session.authenticated) {
        fs.readFile(path.join(__dirname, 'html', 'index-loggedIn.html'), 'utf8', (err, data) => {
            if (err) {
                console.error("Error reading logged in home:", err);
                return res.status(500).send("Internal Server Error");
            }
            const htmlContent = data.replace('{{user}}', req.session.name);
            res.send(htmlContent);
        });
    } else {
        res.sendFile(path.join(__dirname, 'html', 'index-logged_out.html'));
    }
});

app.get('/signup', (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.sendFile(path.join(__dirname, 'html', 'signUp.html'));
});

app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    const schema = Joi.object({
        name: Joi.string().alphanum().min(3).max(30).required(),
        email: Joi.string().email().required(),
        password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')).required()
    });

    const validationResult = schema.validate({ name, email, password });

    if (validationResult.error) {
        const errorMessage = validationResult.error.details.map(d => d.message).join(', ');
        console.log("Signup validation error:", errorMessage);
        return sendErrorPage(res, `Invalid input: ${errorMessage}`, '/signup');
    }

    try {
        const existingUser = await userCollection.findOne({ email: email });
        if (existingUser) {
            return sendErrorPage(res, 'Email already exists. Please use a different email or log in.', '/signup');
        }

        const hashedPassword = await bcrypt.hash(password, 10); // Salt rounds = 10

        await userCollection.insertOne({ name: name, email: email, password: hashedPassword });
        console.log("User added:", name, email);

        req.session.authenticated = true;
        req.session.name = name;
        req.session.email = email;
        req.session.cookie.maxAge = 60 * 60 * 1000;
        res.redirect('/members');

    } catch (err) {
        console.error("Signup error:", err);
        sendErrorPage(res, 'An error occurred during signup. Please try again later.', '/signup', 500);
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'logIn.html'));
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const validationResult = schema.validate({ email, password });

    if (validationResult.error) {
        const errorMessage = validationResult.error.details.map(d => d.message).join(', ');
        console.log("Login validation error:", errorMessage);
        return sendErrorPage(res, `Invalid input: ${errorMessage}`, '/login');
    }

    try {
        const user = await userCollection.findOne({ email: email });
        if (!user) {
            console.log("Login failed: User not found -", email);
            return sendErrorPage(res, 'Invalid email or password.', '/login', 401);
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            console.log("Login successful for:", user.email);
            req.session.authenticated = true;
            req.session.name = user.name;
            req.session.email = user.email;
            req.session.cookie.maxAge = 60 * 60 * 1000;

            res.redirect('/members');
        } else {
            console.log("Login failed: Incorrect password for -", email);
            return sendErrorPage(res, 'Invalid email or password.', '/login', 401);
        }

    } catch (err) {
        console.error("Login error:", err);
        sendErrorPage(res, 'An error occurred during login. Please try again later.', '/login', 500);
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        console.log("Access denied to /members: Not authenticated.");
        return res.redirect('/');
    }

    const imageWebPaths = ['/images/image1.png', '/images/image2.jpg', '/images/image3.gif'];
    const randomImagePath = imageWebPaths[Math.floor(Math.random() * imageWebPaths.length)];

    fs.readFile(path.join(__dirname, 'html', 'members.html'), 'utf8', (err, data) => {
        if (err) {
            console.error("Error reading members.html:", err);
            return res.status(500).send("Internal Server Error");
        }
        let htmlContent = data.replace('{{user}}', req.session.name);

        htmlContent = htmlContent.replace('{{randomImg}}', randomImagePath);

        res.send(htmlContent);
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
            return res.status(500).send("Could not log out.");
        }
        console.log("User logged out.");
        res.redirect('/');
    });
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'html')));

app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'html', '404.html'));
});


connectDB().then(() => {
    app.listen(port, '0.0.0.0', () => {
        console.log(`Server listening on ${port}`);
    });
}).catch(err => {
    console.error("Server failed to start due to DB connection issue:", err);
    process.exit(1);
});