const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const User = require('./models/User.js');
const MongoStore = require('connect-mongo');
const { ObjectID } = require('mongodb');
const { GridFSBucket, MongoClient } = require('mongodb');
const Grid = require('gridfs-stream');
const app = express();
const flash = require('express-flash');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const csrf = require('csurf');
const sanitizeHtml = require('sanitize-html');

// Generate a secure session secret
const sessionSecret = crypto.randomBytes(32).toString('hex');

// Set up rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Apply rate limiting middleware
app.use(limiter);

// Use Helmet to set security-related HTTP headers
app.use(helmet());

// Start the server
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(flash());

app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        res.status(403).send('Form tampered with');
    } else {
        next(err);
    }
});

app.use(session({
    secret: sessionSecret, // Use the secure session secret
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: 'mongodb://localhost:27017/myapp' // Use a secure MongoDB connection string
    }),
    cookie: {
        secure: true, // Set secure cookie flag for HTTPS
        httpOnly: true, // Set HttpOnly cookie flag
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Enable CSRF protection
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(User.authenticate()));

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// MongoDB connection setup
mongoose.connect('mongodb://localhost:27017/myapp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('Error connecting to MongoDB:', err));

app.use(express.static('public'));

const storage = multer.memoryStorage();

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10 MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedMimeTypes = ['image/jpeg', 'image/png', 'application/pdf'];
        if (allowedMimeTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG and PDF are allowed.'));
        }
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

// Middleware to generate a nonce for each request
app.use((req, res, next) => {
    req.nonce = crypto.randomBytes(16).toString('hex');
    next();
});

app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Define routes and start server...
// app.js
//login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Find user by username in the database
        const user = await User.findOne({ username });

        // If user doesn't exist, return error
        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Compare password with hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);

        // If passwords don't match, return error
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        req.session.user = user;

        // Redirect to upload page on successful login
        return res.redirect('/upload');
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Registration route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Sanitize user input
        const sanitizedUsername = sanitizeHtml(username, { allowedTags: [], allowedAttributes: {} });
        const sanitizedPassword = sanitizeHtml(password, { allowedTags: [], allowedAttributes: {} });

        // Check if username already exists
        const existingUser = await User.findOne({ username: sanitizedUsername });
        if (existingUser) {
            // If username already exists, return an error
            return res.status(400).json({ success: false, message: 'Username already exists. Please choose a different username.' });
        }

        // Hash the password before saving the user object
        const saltRounds = 12; // Increase the salt rounds for better security
        const hashedPassword = await bcrypt.hash(sanitizedPassword, saltRounds);

        // Create a new user object with the hashed password
        const newUser = new User({ username: sanitizedUsername, password: hashedPassword });

        // Save the user object to the database
        await newUser.save();

        // Respond with a success message
        res.json({ success: true, message: 'Registration successful. Please log in.' });
    } catch (error) {
        // Handle registration errors
        console.error('Error registering user:', error);
        res.status(500).json({ success: false, message: 'Registration failed. Please try again.' });
    }
});

// Logout route
app.get('/logout', (req, res) => {
    req.logout(function(err) {
        if (err) {
            console.error('Error logging out:', err);
            res.status(500).send('Error logging out.');
        } else {
            req.session.destroy(); // Destroy the session
            res.redirect('/');
        }
    });
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    // Check if the user is authenticated based on your database authentication method
    if (req.session && req.session.user) {
        return next(); // User is authenticated, proceed to the next middleware/route handler
    } else {
        res.redirect('/login?error=Authentication required'); // User is not authenticated, send a 401 Unauthorized response
    }
}

// Example protected route
app.get('/upload', isAuthenticated,(req, res) => {
    // Check if user is authenticated
    res.sendFile(path.join(__dirname, 'public', 'upload.html'), { csrfToken: req.csrfToken() });
});

// Serve the login page
app.get('/login', async (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'), { csrfToken: req.csrfToken() });
});

// Inside your '/upload' route handler
app.post('/upload', isAuthenticated, csrfProtection, upload.array('diagrams', 10), async (req, res) => {
    try {
        console.log(req.files);
        const files = req.files;

        if (!files || files.length === 0) {
            return res.status(400).send('No files uploaded.');
        }

        // Sanitize user input
        const { name, company, contact, stack } = req.body;
        const sanitizedName = sanitizeHtml(name, { allowedTags: [], allowedAttributes: {} });
        const sanitizedCompany = sanitizeHtml(company, { allowedTags: [], allowedAttributes: {} });
        const sanitizedContact = sanitizeHtml(contact, { allowedTags: [], allowedAttributes: {} });
        const sanitizedStack = sanitizeHtml(stack, { allowedTags: [], allowedAttributes: {} });

        if (!sanitizedName || !sanitizedCompany || !sanitizedContact || !sanitizedStack) {
            return res.status(400).send('Missing required fields.');
        }

        // Connect to MongoDB
        MongoClient.connect('mongodb://localhost:27017/myapp', {
            useNewUrlParser: true,
            useUnifiedTopology: true
        })
        .then(async client => {
            console.log('Connected to MongoDB');

            const db = client.db('myapp');

            // Create a new GridFSBucket instance
            const gfsBucket = new GridFSBucket(db);

            // Store additional data along with each file
            const fileInfoPromises = files.map(async file => {
                try {
                    // Create a write stream to GridFS for each file
                    const uploadStream = gfsBucket.openUploadStream(file.originalname);

                    // Write file data to the GridFSBucket
                    uploadStream.write(file.buffer);
                    uploadStream.end();

                    // Wait for upload stream to finish
                    await new Promise((resolve, reject) => {
                        uploadStream.on('error', err => {
                            console.error('Error uploading file:', err);
                            reject(err);
                        });

                        uploadStream.on('finish', () => {
                            resolve();
                        });
                    });

                    // Insert file info into database
                    await db.collection('files').insertOne({
                        fileId: uploadStream.id,
                        filename: file.originalname,
                        name: sanitizedName,
                        companyName: sanitizedCompany,
                        contactNumber: sanitizedContact,
                        softwareStack: sanitizedStack, // Store the sanitized software stack
                        uploadDate: new Date(),
                        email: sanitizeHtml(req.session.user.username, { allowedTags: [], allowedAttributes: {} }) // Sanitize email
                    });
                } catch (error) {
                    console.error('Error handling file upload:', error);
                    throw error;
                }
            });

            // Wait for all file info to be stored
            await Promise.all(fileInfoPromises);

            res.send('Files uploaded successfully.');
        })
        .catch(error => {
            console.error('Error connecting to MongoDB:', error);
            res.status(500).send('Internal server error.');
        });
    } catch (error) {
        console.error('Error handling file upload:', error);
        res.status(500).send('Internal server error.');
    }
});