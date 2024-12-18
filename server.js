const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const requestIp = require('request-ip');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const xss = require('xss-clean');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

const app = express();
const port = 3000; // Runs on port 3000, can be changed

// Thank you for cloning my Account Backend Boilerplate! To make it work for your use case, find all comments that include !CHANGE and change the values accordingly.


// CORS configuration ------------------------------------------------------------
app.use(cors({
    origin: [
        "http://localhost:3000", // For testing
        "https://input-your-domain.com" // !CHANGE this to your domain, add more domains if needed. Performing requests from unlisted websites will result in CORS errors.
    ]
}));

// Middleware -------------------------------------------------------------------------------------
app.use(bodyParser.json()); // parse incoming json requests automatically
app.use(requestIp.mw()); // apply the requestIp middleware to get the actual ip and not the ip of the proxy. Used for rate limiting
app.use(xss()); // prevent xss attacks

// MySQL Database Connection ----------------------------------------------------------------------------

const RETRY_INTERVAL = 5000;
let pool;

function createDBPool() {
    // Create a connection pool - needed for high-throughput operations,
    // as one connection can become a bottleneck

    // !CHANGE these details to match your Database config
    return mysql.createPool({
        host: "your-db-ip-or-domain",
        port: 3306,
        user: "your-db-user",
        password: "your-db-password",
        database: "your-db-name",
        waitForConnections: true,
        connectionLimit: 10,    // Adjust based on your expected concurrency - a regular MySQL db can handle up to ~75
        queueLimit: 0           // No limit on queued connection requests
    });
}

function getDB() {
    // Return the pool instance instead of a single connection
    if (!pool) {
        console.error("Database pool is not initialized.");
    }
    return pool;
}

function connectDB() {
    // Create the pool
    pool = createDBPool();

    // Test the connection when starting the pool
    pool.getConnection((err, connection) => {
        if (err) {
            console.error('Error connecting to MySQL pool:', err);
            console.log(`Connection failed. Retrying in ${RETRY_INTERVAL / 1000} seconds...`);
            setTimeout(connectDB, RETRY_INTERVAL); // Retry pool creation
            return;
        }

        console.log('Connected to MySQL pool');
        connection.release(); // Release the test connection back to the pool
    });

    pool.on('error', (err) => {
        console.error('Database pool error:', err);
        console.log('Attempting to recreate the pool...');
        setTimeout(connectDB, RETRY_INTERVAL); // Attempt to recreate the pool on error
    });
}

// Initialize Database connection
connectDB();

// Password checking and hash generation ------------------------------------------------------------------------------------------------------

// A hash is a large string that can be created from a user password and validated against a user password, but cannot be "decrypted" into the original password.

// for Register - generate hash of password
async function getEncodedPassword(plainPassword) {
    const saltRounds = 15; // Number of salt rounds to use for hashing
    try {
        const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
        return hashedPassword;
    } catch (error) {
        console.error('Error hashing password:', error);
        throw error;
    }
}

// for Login - compare hash with password
async function isPasswordValid(plainPassword, hashedPassword) {
    try {
        const isValid = await bcrypt.compare(plainPassword, hashedPassword);
        return isValid;
    } catch (error) {
        console.error('Error validating password:', error);
        throw error;
    }
}

// JWT Authentication with Bearer Token ------------------------------------------------------------------------------------------------
// A bearer token is a token used to authenticate requests. When the user logs in, this token will be sent back in the response of the login request and should be stored as a cookie in the frontend.

const SECRET_KEY = "YOUR_KEY"; // !CHANGE input a jwt secret key. Simply come up with a long string of numbers and characters, ideally up to 32 chars long. For better security, make sure to use a .env file and store your keys there

function createNewJwtToken(user) {
    let accessToken = '';

    try {
        const jwtTokenExpirationTime = Math.floor(Date.now() / 1000) + (24 * 60 * 60); // !CHANGE expiration period of the bearer token, currently set to 24h (24 * 60 * 60 = 86400 seconds = 1d). Can be extended if needed

        accessToken = jwt.sign(
            {
                sub: user.email, // Subject (email)
                userId: user.id // Custom claim for user ID
            },
            SECRET_KEY,
            {
                expiresIn: jwtTokenExpirationTime
            }
        );
    } catch (e) {
        accessToken = '';
        console.error('Token generation error: ', e.message);
    }

    console.info('JWT token generated successfully.');
    return accessToken;
}

// Check if the id from the bearer token matches the ip passed in the request. This is to make sure the token belongs to this user and not just any user.
// Use this middleware for all requests that include the "id" of the user as well as the bearer token in the Authorization header to ensure it's really them
function authenticateTokenWithId(req, res, next) {
    const authorizationHeader = req.headers['authorization'];

    if (authorizationHeader && authorizationHeader.startsWith('Bearer ')) {
        const token = authorizationHeader.substring('Bearer '.length);

        jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err) {
                return res.status(403).json({ status: 403, error: "An error occurred decoding the Authentication token." });
            }

            if (!decoded || !decoded.userId) {
                return res.status(403).json({ status: 403, error: "Access token lacks user id." });
            }

            const tokenUserId = decoded.userId;
            const requestUserId = req.body.id ? req.body.id : req.params.id; // get id from params or from body, depending on what exists !CHANGE this if you want to use /:id as a request parameter for different use cases

            // Compare token userId with the requested userId
            if (tokenUserId != requestUserId) {
                console.error("User ID from access token does not match user id. Id from Token: " + tokenUserId + ", Id from request: " + requestUserId);
                return res.status(403).json({ status: 403, error: "User ID from access token does not match requested user id." });
            }

            next();
        });
    } else {
        return res.status(401).json({ status: 401, error: "No authentication token in request. Try signing out and in again." });
    }
}

// Rate Limiters -----------------------------------------------------------------------------------------------------------------------------------

// Rate limiting is important to ensure that nobody is sending a huge amount of requests that would slow down your server and/or database

const loginLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    keyGenerator: (req) => req.clientIp, // use correct ip and not the one of the proxy. This uses request-ip, a package that checks various aspects of the request to get the correct ip address.
    max: 5,
    message: 'Too many login attempts from this IP, please try again later.'
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    keyGenerator: (req) => req.clientIp, // use correct ip 
    max: 10, // limit each IP to 10 register requests per windowMs
    message: { error: 'Too many accounts created from this IP, please try again after 24 hours.' }
});

const standardLimiter = rateLimit({
    windowMs: 1000, // 1 second
    keyGenerator: (req) => req.clientIp, // use correct ip 
    max: 5, // limit each IP to 5 standard requests per second
    message: { error: 'You are sending too many requests.' }
});

// Endpoints ---------------------------------------------------------------------------------------------------------------------------------------

// Register Endpoint
app.post('/accounts/register', registerLimiter, async (req, res) => {
    const db = getDB();

    let { userName, email, password } = req.body; // include these 3 properties in the request body
    const userIp = req.clientIp;

    if (!userName || !email || !password) {
        return res.status(400).json({ error: 'Username, email, and password are required.' });
    }

    userName = userName.trim(); // remove whitespaces from username
    email = email.trim(); // remove whitespaces from email

    try {
        // Check if email already exists
        const emailExistsQuery = 'SELECT id FROM accounts WHERE email = ?';
        const existingEmailUser = await new Promise((resolve, reject) => {
            db.query(emailExistsQuery, [email], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (existingEmailUser) {
            return res.status(409).json({ error: 'Email is already in use.' });
        }

        // Check if username already exists. !CHANGE this if you want to allow duplicate usernames (just remove the next 11 lines)
        const userNameExistsQuery = 'SELECT id FROM accounts WHERE user_name = ?';
        const existingUserNameUser = await new Promise((resolve, reject) => {
            db.query(userNameExistsQuery, [userName], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (existingUserNameUser) {
            return res.status(409).json({ error: 'Username is already taken.' });
        }

        // Generate hashed password
        const hashedPassword = await getEncodedPassword(password);

        // Get current timestamp
        const now = new Date();

        // Insert new user into the database
        const insertUserQuery = 'INSERT INTO accounts (user_name, email, password, created_at) VALUES (?, ?, ?, ?, ?)';
        const newUser = await new Promise((resolve, reject) => {
            db.query(insertUserQuery, [userName, email, hashedPassword, userIp, now], (err, results) => {
                if (err) return reject(err);
                resolve(results.insertId);
            });
        });

        res.status(201).json({ message: 'Registration successful.' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'An error occurred during registration.' });
    }
});

// Login Endpoint
app.post('/accounts/login', loginLimiter, async (req, res) => {
    const db = getDB();
    const { email, password } = req.body; // include these 2 properties in the request body

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        // Find user by email
        const userQuery = 'SELECT id, user_name, password FROM accounts WHERE email = ?';
        const user = await new Promise((resolve, reject) => {
            db.query(userQuery, [email], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        // Check password
        const isValidPassword = await isPasswordValid(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        // Generate JWT token
        const accessToken = createNewJwtToken({ email, id: user.id });

        res.json({
            message: 'Login successful',
            access_token: accessToken, // here, the bearer token is being returned. Save it in the frontend for future requests.
            id: user.id,
            userName: user.user_name
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'An error occurred during login.' });
    }
});

// Delete Account endpoint
app.delete('/accounts/delete', standardLimiter, async (req, res) => {
    const db = getDB();
    const { id, password } = req.body; // include these 2 properties in the request body

    if (!id || !password) {
        return res.status(400).json({ error: 'Id and password are required.' });
    }

    try {
        // Find user by email to retrieve password hash
        const userQuery = 'SELECT password FROM accounts WHERE id = ?';
        const user = await new Promise((resolve, reject) => {
            db.query(userQuery, [id], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials. User not found.' });
        }

        // Check password
        const isValidPassword = await isPasswordValid(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Invalid credentials.' });
        }

        // Delete user account
        const deleteUserQuery = 'DELETE FROM accounts WHERE id = ?';
        await new Promise((resolve, reject) => {
            db.query(deleteUserQuery, [id], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        res.json({ message: 'Account deleted successfully.' });
    } catch (error) {
        console.error('Error during account deletion:', error);
        res.status(500).json({ error: 'An error occurred during account deletion.' });
    }
});

// Password resets via email -----------------------------------------------------------------------------

// Configure your email service - !CHANGE these details to match your email provider
let transporter = nodemailer.createTransport({
    host: "smtp.example.com",
    port: 465,
    auth: {
        user: "email-address",
        pass: "password", // ideally store in a .env file
    },
});

// request password reset email endpoint
app.post('/accounts/reset-password-request', standardLimiter, async (req, res) => {
    const db = getDB();
    const { email } = req.body; // include this property in the request body

    if (!email) {
        return res.status(400).json({ error: 'Email is required.' });
    }

    try {
        // Find user by email
        const userQuery = 'SELECT id FROM accounts WHERE email = ?';
        const user = await new Promise((resolve, reject) => {
            db.query(userQuery, [email], (err, results) => {
                if (err) return reject(err);
                resolve(results[0]);
            });
        });

        if (!user) {
            return res.status(404).json({ error: 'No account with that email found.' });
        }

        // Create a password reset token
        const resetToken = jwt.sign({ email: email, id: user.id }, SECRET_KEY, { expiresIn: '1h' });

        // Send email with the reset token
        const resetUrl = `https://your-domain.com?token=${resetToken}`; // !CHANGE this to your domain and handle it in the frontend accordingly. You can get the query parameter using URLSearchParams https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams
        const mailOptions = {
            from: 'your-gmail-address@gmail.com', // !CHANGE this to your email
            to: email,
            subject: 'Password Reset',
            text: `Please click this link to reset your password: ${resetUrl}` // you can adjust the text as you wish
        };

        await transporter.sendMail(mailOptions);

        res.json({ message: 'Password reset email sent.' });
    } catch (error) {
        console.error('Error during password reset request:', error);
        res.status(500).json({ error: 'An error occurred during password reset request.' });
    }
});

// reset password endpoint
app.post('/accounts/reset-password', standardLimiter, async (req, res) => {
    const db = getDB();
    const { token, newPassword } = req.body; // include these 2 properties in the request body

    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Token and new password are required.' });
    }

    try {
        // Verify the reset token + get user Id from the token so that the correct account's password can be changed
        const decoded = jwt.verify(token, SECRET_KEY);

        // Hash the new password
        const hashedPassword = await getEncodedPassword(newPassword);

        // Update the user's password in the database
        const updatePasswordQuery = 'UPDATE accounts SET password = ? WHERE id = ?';
        await new Promise((resolve, reject) => {
            db.query(updatePasswordQuery, [hashedPassword, decoded.id], (err, results) => { // this takes the id from the authentication token to ensure only this account can be resetted
                if (err) return reject(err);
                resolve(results);
            });
        });

        res.json({ message: 'Password reset successfully.' });
    } catch (error) {
        console.error('Error during password reset:', error);
        res.status(500).json({ error: 'An error occurred during password reset.' });
    }
});

// Start the server ----------------------------------------------------------------------------------------------------------------------------------
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});