'use strict';

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const path = require('path');
const ejs = require('ejs');

const port = process.env.PORT || 3001;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const requiredEnvVars = {
    mongodb_host, mongodb_user, mongodb_password, mongodb_database,
    mongodb_session_secret, node_session_secret
};
for (const [key, value] of Object.entries(requiredEnvVars)) {
    if (!value) {
        console.error(`FATAL ERROR: Missing required environment variable ${key}. Check your .env file.`);
        process.exit(1);
    }
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

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false }));

app.use(express.static(path.join(__dirname, 'public')));


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

function isAuthenticated(req, res, next) {
    if (req.session.authenticated) {
        return next();
    }
    res.redirect('/login');
}

function isAdmin(req, res, next) {
    if (req.session.user_type === 'admin') {
        return next();
    }
    res.status(403).render('error', {
        errorTitle: "Access Denied",
        errorMessage: "You do not have permission to view this page.",
        backLink: "/members",
        user: req.session.name,
        isLoggedIn: req.session.authenticated,
        isAdmin: false
    });
}

app.get('/', (req, res) => {
    res.render('index', {
        user: req.session.name,
        isLoggedIn: req.session.authenticated,
        isAdmin: req.session.user_type === 'admin'
    });
});

// Signup Routes
app.get('/signup', (req, res) => {
    res.render('signup', {
         user: req.session.name,
         isLoggedIn: req.session.authenticated,
         isAdmin: req.session.user_type === 'admin'
     });
});

app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    const schema = Joi.object({
        name: Joi.string().trim().min(1).max(50).required(),
        email: Joi.string().trim().email().required(),
        password: Joi.string().min(8).max(100).required()
    });

    const validationResult = schema.validate({ name, email, password });

    if (validationResult.error) {
        const errorMessage = validationResult.error.details.map(d => d.message).join(', ');
        console.log("Signup validation error:", errorMessage);
        return res.status(400).render('error', {
            errorTitle: "Invalid Input",
            errorMessage: `Invalid input: ${errorMessage}`,
            backLink: '/signup',
            user: req.session.name,
            isLoggedIn: req.session.authenticated,
            isAdmin: req.session.user_type === 'admin'
        });
    }

    try {
        const existingUser = await userCollection.findOne({ email: email });
        if (existingUser) {
            return res.status(409).render('error', {
                errorTitle: "Signup Failed",
                errorMessage: 'Email already exists. Please use a different email or log in.',
                backLink: '/signup',
                 user: req.session.name,
                 isLoggedIn: req.session.authenticated,
                 isAdmin: req.session.user_type === 'admin'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const newUser = {
            name: name,
            email: email,
            password: hashedPassword,
            user_type: 'user'
        };
        await userCollection.insertOne(newUser);
        console.log("User added:", name, email);

        req.session.authenticated = true;
        req.session.name = name;
        req.session.email = email;
        req.session.user_type = 'user';
        req.session.userId = (await userCollection.findOne({email: email}))._id;
        req.session.cookie.maxAge = 60 * 60 * 1000;

        res.redirect('/members');

    } catch (err) {
        console.error("Signup error:", err);
        res.status(500).render('error', {
             errorTitle: "Server Error",
             errorMessage: 'An error occurred during signup. Please try again later.',
             backLink: '/signup',
             user: req.session.name,
             isLoggedIn: req.session.authenticated,
             isAdmin: req.session.user_type === 'admin'
         });
    }
});

// Login Routes
app.get('/login', (req, res) => {
     res.render('login', {
         user: req.session.name,
         isLoggedIn: req.session.authenticated,
         isAdmin: req.session.user_type === 'admin'
     });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const schema = Joi.object({
        email: Joi.string().trim().email().required(),
        password: Joi.string().required()
    });

    const validationResult = schema.validate({ email, password });

    if (validationResult.error) {
        const errorMessage = validationResult.error.details.map(d => d.message).join(', ');
        console.log("Login validation error:", errorMessage);
        return res.status(400).render('error', {
            errorTitle: "Invalid Input",
            errorMessage: `Invalid input: ${errorMessage}`,
            backLink: '/login',
            user: req.session.name,
            isLoggedIn: req.session.authenticated,
            isAdmin: req.session.user_type === 'admin'
        });
    }

    try {
        const user = await userCollection.findOne({ email: email });
        if (!user) {
            console.log("Login failed: User not found -", email);
            return res.status(401).render('error', {
                 errorTitle: "Login Failed",
                 errorMessage: 'Invalid email or password.',
                 backLink: '/login',
                 user: req.session.name,
                 isLoggedIn: req.session.authenticated,
                 isAdmin: req.session.user_type === 'admin'
             });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            console.log("Login successful for:", user.email);
            req.session.authenticated = true;
            req.session.name = user.name;
            req.session.email = user.email;
            req.session.user_type = user.user_type;
            req.session.userId = user._id;
            req.session.cookie.maxAge = 60 * 60 * 1000;

            res.redirect('/members');
        } else {
            console.log("Login failed: Incorrect password for -", email);
            return res.status(401).render('error', {
                 errorTitle: "Login Failed",
                 errorMessage: 'Invalid email or password.',
                 backLink: '/login',
                 user: req.session.name,
                 isLoggedIn: req.session.authenticated,
                 isAdmin: req.session.user_type === 'admin'
             });
        }

    } catch (err) {
        console.error("Login error:", err);
         res.status(500).render('error', {
             errorTitle: "Server Error",
             errorMessage: 'An error occurred during login. Please try again later.',
             backLink: '/login',
             user: req.session.name,
             isLoggedIn: req.session.authenticated,
             isAdmin: req.session.user_type === 'admin'
         });
    }
});

app.get('/members', isAuthenticated, (req, res) => {
    const imagePaths = ['/images/image1.png', '/images/image2.jpg', '/images/image3.gif'];

    res.render('members', {
        user: req.session.name,
        images: imagePaths,
        isLoggedIn: req.session.authenticated,
        isAdmin: req.session.user_type === 'admin'
    });
});

// Admin Route
app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const users = await userCollection.find({}, { projection: { name: 1, email: 1, user_type: 1, _id: 1 } }).toArray();

        res.render('admin', {
            user: req.session.name,
            users: users,
            isLoggedIn: req.session.authenticated,
            isAdmin: true
        });
    } catch (err) {
        console.error("Admin page error:", err);
        res.status(500).render('error', {
            errorTitle: "Server Error",
            errorMessage: 'Failed to load admin page.',
            backLink: '/members',
            user: req.session.name,
            isLoggedIn: req.session.authenticated,
            isAdmin: req.session.user_type === 'admin'
        });
    }
});


app.post('/promote/:userId', isAuthenticated, isAdmin, async (req, res) => {
    const userIdToPromote = req.params.userId;

     if (!ObjectId.isValid(userIdToPromote)) {
        return res.status(400).send("Invalid user ID format.");
     }


    try {
        const result = await userCollection.updateOne(
            { _id: new ObjectId(userIdToPromote) },
            { $set: { user_type: 'admin' } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).send("User not found.");
        }
        if (result.modifiedCount === 1) {
            console.log(`User ${userIdToPromote} promoted to admin.`);
             // Check if the promoted user is the currently logged-in admin
            if (req.session.userId.equals(new ObjectId(userIdToPromote))) {
                req.session.user_type = 'admin';
            }
        } else {
            console.log(`User ${userIdToPromote} already admin or update failed.`);
        }

        res.redirect('/admin');
    } catch (err) {
        console.error("Promote user error:", err);
        res.status(500).render('error', {
             errorTitle: "Server Error",
             errorMessage: 'Failed to promote user.',
             backLink: '/admin',
             user: req.session.name,
             isLoggedIn: req.session.authenticated,
             isAdmin: true
         });
    }
});

// Demote User Route
app.post('/demote/:userId', isAuthenticated, isAdmin, async (req, res) => {
    const userIdToDemote = req.params.userId;

     if (!ObjectId.isValid(userIdToDemote)) {
        return res.status(400).send("Invalid user ID format.");
     }


    try {
        // Use updateOne to set user_type to 'user'
        const result = await userCollection.updateOne(
            { _id: new ObjectId(userIdToDemote) },
            { $set: { user_type: 'user' } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).send("User not found.");
        }
         if (result.modifiedCount === 1) {
            console.log(`User ${userIdToDemote} demoted to user.`);
             // Check if the demoted user is the currently logged-in admin
             if (req.session.userId.equals(new ObjectId(userIdToDemote))) {
                 req.session.user_type = 'user';
                  return res.redirect('/members');
             }
        } else {
            console.log(`User ${userIdToDemote} already user or update failed.`);
        }

        res.redirect('/admin');
    } catch (err) {
        console.error("Demote user error:", err);
         res.status(500).render('error', {
             errorTitle: "Server Error",
             errorMessage: 'Failed to demote user.',
             backLink: '/admin',
             user: req.session.name,
             isLoggedIn: req.session.authenticated,
             isAdmin: true
         });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
            return res.status(500).render('error', {
                 errorTitle: "Logout Error",
                 errorMessage: 'Could not log out properly. Please clear your browser cookies.',
                 backLink: '/',
                 user: null,
                 isLoggedIn: false,
                 isAdmin: false
             });
        }
        console.log("User logged out.");
        res.redirect('/');
    });
});

app.use((req, res, next) => {
    res.status(404).render('404', {
        errorTitle: "Page Not Found",
        errorMessage: "Sorry, the page you are looking for does not exist.",
        backLink: "/",
        user: req.session.name,
        isLoggedIn: req.session.authenticated,
        isAdmin: req.session.user_type === 'admin'
    });
});

connectDB().then(() => {
    app.listen(port, () => {
        console.log(`Server listening on port ${port}`);
    });
}).catch(err => {
    console.error("Server failed to start due to DB connection issue:", err);
    process.exit(1);
});