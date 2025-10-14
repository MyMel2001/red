// --- Configuration Loading (Must be first) ---
require('dotenv').config();

// --- Dependencies and Setup ---
const express = require('express');
const app = express();
const port = process.env.PORT || 3000; 

// File Upload Dependencies
const multer = require('multer');
const path = require('path');
const fs = require('fs'); // Node.js File System module

// Security and Session Dependencies
const bcrypt = require('bcrypt');
const saltRounds = 10;
const session = require('express-session');
const qdb = require('quick.db');
const db = new qdb.QuickDB({ filePath: process.env.DB_FILEPATH || './social_network_db.sqlite' });
// Set domain to localhost:port for local development
const domain = process.env.DOMAIN || `localhost:${port}`; 

// --- Multer Configuration for File Uploads ---

// Ensure the 'uploads' directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Files will be stored in the 'uploads/' folder
    },
    filename: (req, file, cb) => {
        // Create a unique filename: fieldname-timestamp.ext
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

// Configure Multer to accept a single image file named 'postImage'
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB file size limit
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Only images (jpeg, jpg, png, gif) are allowed.'));
    }
}).single('postImage');

// --- Initialization Block to Ensure Schema ---
async function initializeDatabase() {
    // 1. Ensure 'users' is an Object, and add default pfpUrl
    const users = await db.get('users');
    if (typeof users !== 'object' || Array.isArray(users) || users === null) {
        await db.set('users', {});
    } else {
        for (const userId in users) {
            if (!users[userId].pfpUrl) {
                users[userId].pfpUrl = 'https://i.imgur.com/example_default_pfp.png';
            }
        }
        await db.set('users', users);
    }
    
    // 2. Ensure 'posts' is an Array.
    const posts = await db.get('posts');
    if (!Array.isArray(posts)) {
        await db.set('posts', []);
    }

    // 3. Ensure 'messages' is an Array for DMs
    const messages = await db.get('messages');
    if (!Array.isArray(messages)) {
        await db.set('messages', []);
    }
}

// --- Configuration and Middleware ---

// Serve static files (uploaded images) - CRITICAL
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Use URL-encoded body parser to handle standard form submissions
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Set up sessions for state management
app.use(session({
    secret: process.env.SESSION_SECRET || 'default-secret-for-social-network', 
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, 
        httpOnly: true, 
        secure: false,
        sameSite: 'Lax',
    }
}));

function requireLogin(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

async function loadUser(req, res, next) {
    if (req.session.userId) {
        req.user = await db.get(`users.${req.session.userId}`);
    }
    next();
}

app.use(loadUser);

// --- IE5 Compatible HTML/CSS Utilities (Same as previous version) ---

// Utility to find and count hashtags
async function getTrendingTopics() {
    const postsRaw = await db.get('posts');
    const posts = Array.isArray(postsRaw) ? postsRaw : Object.values(postsRaw || {});
    
    const hashtagCounts = {};
    const hashtagRegex = /#(\w+)/g;

    const recentPosts = Array.from(posts).sort((a, b) => b.timestamp - a.timestamp).slice(0, 100);

    for (const post of recentPosts) {
        let match;
        while ((match = hashtagRegex.exec(post.content)) !== null) {
            const tag = match[1].toLowerCase();
            hashtagCounts[tag] = (hashtagCounts[tag] || 0) + 1;
        }
    }

    return Object.entries(hashtagCounts)
        .sort(([, countA], [, countB]) => countB - countA)
        .slice(0, 5)
        .map(([tag, count]) => ({ tag, count }));
}

// Utility to linkify hashtags
function linkifyContent(content) {
    return content.replace(/#(\w+)/g, (match, tag) => {
        return `<a href="/search?q=%23${tag}" style="color: #0077cc; text-decoration: none;">${match}</a>`;
    });
}

// Basic, IE5-compatible CSS for layout and style
const IE5_STYLES = `
    body { 
        font-family: Arial, sans-serif; 
        background-color: #a4e5ed;
        margin: 0; 
        padding: 0;
    }
    .header {
        background-color: #dbe9f6;
        padding: 10px 0; 
        margin-bottom: 20px; 
        text-align: left;
        border-bottom: 1px solid #cceeff;
        width: 900px;
        margin: 0 auto;
        padding-left: 10px;
        box-sizing: border-box;
    }
    .header h1 { 
        color: #0077cc; 
        margin: 0; 
        font-size: 20px;
        display: inline;
    }
    .header-right {
        float: right;
        font-size: 12px;
        padding-right: 10px;
        line-height: 20px;
    }
    .header-right a {
        background-color: #ff8c00;
        color: white;
        text-decoration: none;
        padding: 5px 10px;
        border: none;
    }
    .container {
        width: 900px;
        margin: 0 auto; 
        padding: 10px 0;
        overflow: hidden;
    }
    .nav-col {
        float: left; 
        width: 15%;
        padding-right: 10px;
        min-height: 400px;
        font-size: 14px;
    }
    .main-col {
        float: left; 
        width: 55%;
        padding: 0 10px;
        min-height: 400px;
        box-sizing: border-box;
    }
    .side-col {
        float: right; 
        width: 30%;
        padding-left: 10px;
        min-height: 400px;
        box-sizing: border-box;
    }
    .box {
        background-color: #ffffff; 
        border: 1px solid #ccc; 
        padding: 15px; 
        margin-bottom: 20px;
    }
    h2 {
        font-size: 16px;
        color: #333; 
        border-bottom: 1px solid #eee; 
        padding-bottom: 5px;
        margin-top: 0;
    }
    .nav-col h2, .nav-col p {
        color: #0077cc;
        margin: 5px 0;
        font-weight: bold;
    }
    .nav-col a {
        color: #0077cc;
        text-decoration: none;
        display: block;
        padding: 2px 0;
    }
    .post {
        border-bottom: 1px solid #eee; 
        padding: 10px 0;
    }
    .post:last-child {
        border-bottom: none;
    }
    .post-header {
        display: inline-block;
        vertical-align: top;
        margin-left: 5px;
    }
    .pfp {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        border: 1px solid #ccc;
        float: left;
    }
    .post-user { 
        font-weight: bold; 
        color: #0077cc; 
        font-size: 14px;
    }
    .post-text { 
        margin-top: 5px; 
        font-size: 14px; 
        white-space: pre-wrap;
        margin-left: 45px;
    }
    .post-image {
        max-width: 95%; /* Adjust for margin */
        height: auto;
        display: block;
        margin: 10px 0 10px 45px; /* Offset for PFP */
        border: 1px solid #eee;
    }
    input[type="text"], input[type="password"], textarea, input[type="file"] {
        width: 95%; 
        padding: 5px; 
        margin-bottom: 10px; 
        border: 1px solid #ccc;
        box-sizing: border-box; /* Necessary for width consistency */
    }
    input[type="submit"], button {
        background-color: #0077cc; 
        color: white; 
        border: none; 
        padding: 8px 15px; 
        cursor: pointer; 
        font-size: 14px;
        display: inline-block;
    }
    input[type="submit"]:hover {
        background-color: #005fa3;
    }
    .error {
        color: red; 
        font-weight: bold;
    }
    .post-actions {
        display: inline-block;
        font-size: 12px;
        color: #666;
        margin-left: 45px;
    }
    .like-button {
        color: #0077cc;
        cursor: pointer;
        background: none;
        border: none;
        padding: 0;
        text-decoration: underline;
        font-size: 12px;
        display: inline-block;
        margin-right: 10px;
    }
    .like-button:hover {
        color: #005fa3;
    }
    /* IE5/Mobile Dynamic Shim: Modern browsers will stack columns */
    /* @media only screen and (max-width: 600px) { */
    .flex-shim .nav-col, .flex-shim .main-col, .flex-shim .side-col {
        float: none;
        width: 100%;
        padding: 0 10px;
        box-sizing: border-box;
    }
    .flex-shim .container {
        width: 100%;
    }
    /* } */
`;

// Navigation Content HTML fragment
function navContent() {
    return `
        <div class="nav-col">
            <h2 style="color: #0077cc; font-size: 18px;">Navigation</h2>
            <a href="/">Home</a>
            <a href="/profile">Profile</a>
            <a href="/search">Search</a>
            <a href="/followers">Following</a>
            <a href="/followers">Followers</a>
            
            <h2 style="margin-top: 15px;">Trending</h2>
            <h2 style="margin-top: 15px;">Messages</h2>
            <a href="/inbox">Inbox</a>
            <a href="/compose">Compose</a>
        </div>
    `;
}

// Generic HTML structure generator
function createHtml(title, bodyContent, error = '', user = null) {
    const headerRight = user 
        ? `<span style="color:#333;">Welcome, ${user.username}</span> <a href="/logout">Logout</a>`
        : '';

    return `
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <title>x-erpt - ${title}</title>
    <style type="text/css">
        ${IE5_STYLES}
    </style>
</head>
<body>
    <div class="header">
        <h1>x-erpt</h1>
        <div class="header-right">${headerRight}</div>
        <div style="clear: both;"></div>
    </div>
    <div class="container flex-shim">
        ${error ? `<div class="box" style="background-color: #ffebeb; border-color: #ffcccc;"><p class="error">${decodeURIComponent(error)}</p></div>` : ''}
        ${bodyContent}
    </div>
    <div style="clear: both;"></div>
</body>
</html>
    `;
}


// --- Authentication Routes (Same as before) ---
async function hashPassword(password) {
    return await bcrypt.hash(password, saltRounds);
}

async function checkPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

app.get('/register', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    const content = `
        <div class="main-col" style="float: none; width: 100%; padding-right: 0;">
            <div class="box" style="width: 50%; margin: 40px auto; min-height: 0;">
                <h2>Register Account</h2>
                <form action="/register" method="POST">
                    <p>Username:</p>
                    <input type="text" name="username" required>
                    <p>Password (min 6 characters):</p>
                    <input type="password" name="password" required>
                    <input type="submit" value="Sign Up">
                </form>
                <p>Already have an account? <a href="/login">Login here</a>.</p>
            </div>
        </div>
    `;
    res.send(createHtml('Register', content, req.query.error));
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || username.length < 3 || password.length < 6) {
        return res.redirect('/register?error=Username%20must%20be%203+%20chars%20and%20password%206+%20chars.');
    }
    const users = await db.get('users');
    const existingUser = Object.values(users).find(u => u.username.toLowerCase() === username.toLowerCase());
    if (existingUser) {
        return res.redirect('/register?error=Username%20already%20taken.');
    }
    try {
        const hashedPassword = await hashPassword(password);
        const userId = Date.now().toString();
        const newUser = {
            id: userId,
            username: username,
            password: hashedPassword,
            bio: 'A new user on x-erpt!',
            joinDate: new Date().toLocaleDateString('en-US'),
            pfpUrl: 'https://i.imgur.com/example_default_pfp.png',
            followers: [],
            following: [],
        };
        await db.set(`users.${userId}`, newUser);
        req.session.userId = userId;
        res.redirect('/');
    } catch (e) {
        console.error('Registration error:', e);
        res.redirect('/register?error=An%20internal%20error%20occurred.');
    }
});

app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    const content = `
        <div class="main-col" style="float: none; width: 100%; padding-right: 0;">
            <div class="box" style="width: 50%; margin: 40px auto; min-height: 0;">
                <h2 style="text-align: center;">Welcome to x-erpt</h2>
                <p style="text-align: center;">What are you doing?</p>
                <form action="/login" method="POST">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <input type="submit" value="Login" style="width: 48%; margin-right: 2%; float: left;">
                    <a href="/register" style="width: 48%; float: right; display: block; text-align: center; background-color: #3cb371; color: white; padding: 8px 0; text-decoration: none;">Sign Up</a>
                    <div style="clear: both;"></div>
                </form>
            </div>
        </div>
    `;
    res.send(createHtml('Login', content, req.query.error));
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.redirect('/login?error=Please%20enter%20both%20username%20and%20password.');
    }
    const users = await db.get('users');
    const userEntry = Object.values(users).find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!userEntry) {
        return res.redirect('/login?error=Invalid%20username%20or%20password.');
    }
    try {
        const passwordMatch = await checkPassword(password, userEntry.password);
        if (passwordMatch) {
            req.session.userId = userEntry.id;
            res.redirect('/');
        } else {
            res.redirect('/login?error=Invalid%20username%20or%20password.');
        }
    } catch (e) {
        console.error('Login error:', e);
        res.redirect('/login?error=An%20internal%20error%20occurred.');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
        }
        res.redirect('/login');
    });
});


// --- Routes: Functionality (Updated POST /post) ---

// POST /post - Submit a new post (NOW HANDLES FILE UPLOAD)
app.post('/post', requireLogin, (req, res) => {
    // Wrap the core logic in the upload middleware
    upload(req, res, async (err) => {
        if (err instanceof multer.MulterError) {
            // A Multer error occurred (e.g., file size limit)
            return res.redirect(`/?error=${encodeURIComponent('File upload error: ' + err.message)}`);
        } else if (err) {
            // An unknown error occurred
            return res.redirect(`/?error=${encodeURIComponent('Upload failed: ' + err.message)}`);
        }
        
        // No file error, proceed with post creation
        const { content } = req.body;
        const filePath = req.file ? `/uploads/${req.file.filename}` : null; // Get the file path
        
        if (!content || content.trim() === '') {
            // If no content, but file was uploaded, clean up the file
            if (filePath) {
                fs.unlink(path.join(__dirname, req.file.path), (unlinkErr) => {
                    if (unlinkErr) console.error('Error cleaning up file:', unlinkErr);
                });
            }
            return res.redirect('/?error=Post%20content%20cannot%20be%20empty.');
        }

        // Extract hashtags (simple extraction for trending)
        const hashtagRegex = /#(\w+)/g;
        const hashtags = [];
        let match;
        while ((match = hashtagRegex.exec(content)) !== null) {
            hashtags.push(match[1].toLowerCase());
        }

        const newPost = {
            id: Date.now().toString(),
            userId: req.user.id,
            username: req.user.username,
            pfpUrl: req.user.pfpUrl, 
            content: content.substring(0, 280),
            imageUrl: filePath, // Stored path to the uploaded image
            hashtags: hashtags,
            timestamp: Date.now(),
            date: new Date().toLocaleString('en-US'),
            likes: 0,
            likedBy: [],
        };

        await db.push('posts', newPost);
        res.redirect('/');
    });
});


// POST /profile - Update user profile (bio/password/pfpUrl)
app.post('/profile', requireLogin, async (req, res) => {
    const { bio, newPassword, pfpUrl } = req.body;
    let error = '';

    const currentData = await db.get(`users.${req.user.id}`);
    let updateData = { ...currentData }; 

    if (bio !== undefined) {
        updateData.bio = bio.substring(0, 150);
    }
    
    // PFP URL Update (Simple text input, not file upload)
    if (pfpUrl !== undefined) {
        // Simple validation
        if (pfpUrl.startsWith('http') || pfpUrl === '') {
            updateData.pfpUrl = pfpUrl || 'https://i.imgur.com/example_default_pfp.png';
        } else {
             error = 'PFP URL must start with http/https or be left blank.';
        }
    }

    if (newPassword && newPassword.length >= 6) {
        try {
            updateData.password = await hashPassword(newPassword);
        } catch (e) {
            console.error('Password hash error:', e);
            error = 'Error updating password.';
        }
    } else if (newPassword && newPassword.length < 6) {
        error = 'New password must be at least 6 characters.';
    }

    await db.set(`users.${req.user.id}`, updateData);
    
    res.redirect(`/profile?error=${encodeURIComponent(error || 'Profile%20Updated!')}`);
});

// GET /profile - View and edit profile (Same as before)
app.get('/profile', requireLogin, async (req, res) => {
    const error = req.query.error || '';
    const user = req.user;

    const mainColContent = `
        <div class="main-col" style="float: none; width: 100%; padding: 0;">
            <div class="box">
                <h2>${user.username}'s Profile</h2>
                <img src="${user.pfpUrl}" class="pfp" style="margin-right: 10px;">
                <p style="margin-left: 55px; margin-top: 0; font-size: 14px;">
                    <strong>Bio:</strong> ${user.bio}<br>
                    <strong>Joined:</strong> ${user.joinDate}<br>
                    <strong>Followers:</strong> ${(user.followers || []).length}<br>
                    <strong>Following:</strong> ${(user.following || []).length}
                </p>
                <div style="clear: both;"></div>

                <h2 style="margin-top: 20px;">Update Profile</h2>
                <form action="/profile" method="POST">
                    <p>Profile Picture URL:</p>
                    <input type="text" name="pfpUrl" value="${user.pfpUrl || ''}" placeholder="URL starting with http:// or https://">
                    
                    <p>Bio (max 150 chars):</p>
                    <textarea name="bio" rows="4">${user.bio || ''}</textarea>
                    
                    <p>New Password:</p>
                    <input type="password" name="newPassword" placeholder="Leave blank to keep current">
                    
                    <input type="submit" value="Update Profile">
                </form>
            </div>
        </div>
    `;

    const finalContent = `
        ${navContent()}
        <div class="main-col">
            ${mainColContent}
        </div>
        <div class="side-col">
            <div class="box">
                <p>Welcome, ${req.user.username}</p>
                <p><a href="/">Back to Home Feed</a></p>
                <p><a href="/logout">Logout</a></p>
            </div>
        </div>
    `;

    res.send(createHtml('Profile', finalContent, error, req.user));
});


// --- Direct Messages (DM) Routes (Same as before) ---

// GET /inbox - View list of DMs
app.get('/inbox', requireLogin, async (req, res) => {
    const userId = req.user.id;
    const messagesRaw = await db.get('messages');
    const allMessages = Array.isArray(messagesRaw) ? messagesRaw : [];

    const receivedMessages = allMessages.filter(m => m.recipientId === userId)
        .sort((a, b) => b.timestamp - a.timestamp);

    const threads = {};
    for (const msg of receivedMessages) {
        if (!threads[msg.senderUsername]) {
            threads[msg.senderUsername] = [];
        }
        threads[msg.senderUsername].push(msg);
    }
    
    let inboxHtml = '';
    const users = await db.get('users');

    if (Object.keys(threads).length === 0) {
        inboxHtml = '<p>Your inbox is empty.</p>';
    } else {
        inboxHtml += '<h2>Message Threads</h2>';
        for (const senderUsername in threads) {
            const latestMsg = threads[senderUsername][0];
            const senderUser = Object.values(users).find(u => u.username === senderUsername);
            const senderId = senderUser ? senderUser.id : 'unknown';

            inboxHtml += `
                <div class="post">
                    <p><strong>From: <span class="post-user">${senderUsername}</span></strong> 
                    <small>(${latestMsg.date})</small></p>
                    <p class="post-text">${latestMsg.content.substring(0, 50)}...</p>
                    <p><a href="/compose?recipient=${senderUsername}">Reply</a> 
                    | <a href="/inbox/view/${senderId}">View Thread</a></p>
                </div>
            `;
        }
    }

    const mainColContent = `<div class="main-col"><div class="box">${inboxHtml}</div></div>`;

    const finalContent = `
        ${navContent()}
        ${mainColContent}
        <div class="side-col"><div class="box"><p><a href="/compose">Compose New Message</a></p></div></div>
    `;
    res.send(createHtml('Inbox', finalContent, req.query.error, req.user));
});

// GET /compose/:recipient? - Compose a new DM
app.get('/compose/:recipient?', requireLogin, async (req, res) => {
    const recipient = req.params.recipient || req.query.recipient || '';
    const error = req.query.error || '';

    const mainColContent = `
        <div class="main-col">
            <div class="box">
                <h2>Compose Direct Message</h2>
                <form action="/compose" method="POST">
                    <p>Recipient Username:</p>
                    <input type="text" name="recipient" value="${recipient}" required placeholder="Recipient's Username">
                    <p>Message:</p>
                    <textarea name="content" rows="6" required placeholder="Your message..."></textarea>
                    <input type="submit" value="Send Message">
                </form>
            </div>
        </div>
    `;

    const finalContent = `
        ${navContent()}
        ${mainColContent}
        <div class="side-col"><div class="box"><p><a href="/inbox">Back to Inbox</a></p></div></div>
    `;

    res.send(createHtml('Compose DM', finalContent, error, req.user));
});

// POST /compose - Send a DM
app.post('/compose', requireLogin, async (req, res) => {
    const { recipient, content } = req.body;

    if (!recipient || !content) {
        return res.redirect(`/compose?error=${encodeURIComponent('Recipient and content are required.')}`);
    }

    const users = await db.get('users');
    const recipientUser = Object.values(users).find(u => u.username.toLowerCase() === recipient.toLowerCase());

    if (!recipientUser) {
        return res.redirect(`/compose?error=${encodeURIComponent('Recipient user not found.')}`);
    }

    if (recipientUser.id === req.user.id) {
        return res.redirect(`/compose?error=${encodeURIComponent('Cannot send message to yourself.')}`);
    }

    const newMessage = {
        id: Date.now().toString(),
        senderId: req.user.id,
        senderUsername: req.user.username,
        recipientId: recipientUser.id,
        recipientUsername: recipientUser.username,
        content: content.substring(0, 500),
        timestamp: Date.now(),
        date: new Date().toLocaleString('en-US'),
    };

    await db.push('messages', newMessage);
    
    res.redirect(`/inbox?error=${encodeURIComponent('Message sent to ' + recipientUser.username + '!')}`);
});


// GET / - Home/Feed Page (Main View) - Updated post form
app.get('/', requireLogin, async (req, res) => {
    const error = req.query.error || '';
    const sharePostId = req.query.sharePostId; 
    
    // --- Side Column Content (Profile and Trending) ---
    const trendingTopics = await getTrendingTopics();
    let trendingHtml = '';

    if (trendingTopics.length > 0) {
        trendingTopics.forEach(topic => {
            trendingHtml += `<p style="margin: 5px 0;">
                <a href="/search?q=%23${topic.tag}">#${topic.tag}</a> 
                <small>(${topic.count})</small>
            </p>`;
        });
    } else {
        trendingHtml = '<p>No trending topics yet.</p>';
    }

    const sideColContent = `
        <div class="box">
            <img src="${req.user.pfpUrl}" class="pfp">
            <h2 style="margin-left: 45px; margin-top: 5px; border-bottom: none;">${req.user.username}</h2>
            <div style="clear: both;"></div>
            <p style="font-size: 14px; margin-top: 10px;">
                Followers: ${(req.user.followers || []).length} | Following: ${(req.user.following || []).length}
            </p>
            <p><a href="/profile">Edit Profile</a></p>
        </div>

        <div class="box">
            <h2>Trending Topics</h2>
            ${trendingHtml}
        </div>
    `;

    // --- Navigation Column ---
    let navHtml = navContent();
    navHtml = navHtml.replace('', trendingHtml);


    // --- Main Column Content (Posting and Feed) ---
    
    // 1. Post Update Form (UPDATED FOR FILE INPUT)
    const postForm = `
        <div class="box">
            <p style="font-weight: bold; margin-top: 0;">What are you doing?</p>
            
            <form action="/post" method="POST" enctype="multipart/form-data">
                <textarea name="content" rows="4" placeholder="Share something (max 280 chars)..." required style="width: 100%; border: 1px solid #ccc;"></textarea>
                
                <p style="margin-bottom: 5px; margin-top: 5px;">Attach Image (Optional, max 5MB):</p>
                <input type="file" name="postImage" accept="image/jpeg,image/png,image/gif" style="width: 100%; padding: 0; margin-bottom: 5px; border: none;">

                <div style="margin-top: 10px; padding-top: 5px; border-top: 1px solid #eee;">
                    <input type="submit" value="Update" style="float: right;">
                    <div style="clear: both;"></div>
                </div>
            </form>
        </div>
    `;

    // 2. Recent Updates Feed
    let feedContent = '<h2>Your Feed</h2>';
    
    const postsRaw = await db.get('posts');
    const posts = Array.isArray(postsRaw) ? postsRaw : Object.values(postsRaw || {});

    const recentPosts = Array.from(posts)
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, 50); 

    if (recentPosts.length > 0) {
        recentPosts.forEach(post => {
            const likeCount = post.likes || 0;
            const hasLiked = post.likedBy && post.likedBy.includes(req.user.id);
            const likeAction = hasLiked ? 'Unlike' : 'Like';

            const postPfpUrl = post.pfpUrl || 'https://i.imgur.com/example_default_pfp.png';
            // Image URL now uses the server's path
            const postImageHtml = post.imageUrl ? `<img src="${post.imageUrl}" class="post-image" alt="Post Image">` : '';

            let shareUrlBox = '';
            if (sharePostId && post.id === sharePostId) {
                const fullShareUrl = `http://${domain}/post/${post.id}`;
                shareUrlBox = `
                    <div style="margin-top: 10px; padding: 8px; border: 1px dashed #0077cc; background-color: #e6f7ff;">
                        <p style="margin: 0; font-size: 12px; color: #333; font-weight: bold;">
                            Share link: <a href="${fullShareUrl}" target="_blank" style="color: #0077cc; text-decoration: underline;">${fullShareUrl}</a>
                        </p>
                        <p style="margin: 5px 0 0 0;"><a href="/" style="font-size: 10px; color: #666; font-weight: bold;">[ CLOSE ]</a></p>
                    </div>
                `;
            }

            const linkedContent = linkifyContent(post.content);

            feedContent += `
                <div class="post">
                    <img src="${postPfpUrl}" class="pfp">
                    <div class="post-header">
                        <span class="post-user">${post.username}</span> <small>(${post.date})</small>
                    </div>
                    <div style="clear: both;"></div>

                    ${postImageHtml}
                    <p class="post-text">${linkedContent}</p>
                    
                    <div class="post-actions">
                        <form action="/like" method="POST" style="display: inline; margin-right: 10px;">
                            <input type="hidden" name="postId" value="${post.id}">
                            <input type="submit" class="like-button" value="${likeAction} (${likeCount})">
                        </form>

                        <form action="/share" method="POST" style="display: inline;">
                            <input type="hidden" name="postId" value="${post.id}">
                            <input type="submit" class="like-button" value="Share">
                        </form>
                    </div>
                    ${shareUrlBox}
                </div>
            `;
        });
    } else {
        feedContent += '<p>No updates yet! Be the first to post.</p>';
    }

    const mainColContent = `
        ${postForm}
        <div class="box">
            ${feedContent}
        </div>
    `;

    // Combine into final page
    const finalContent = `
        ${navHtml}
        <div class="main-col">
            ${mainColContent}
        </div>
        <div class="side-col">
            ${sideColContent}
        </div>
    `;

    res.send(createHtml('Home', finalContent, error, req.user));
});

app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/');
    } else {
        res.redirect('/login');
    }
});

// --- Server Start ---

initializeDatabase().then(() => {
    app.listen(port, () => {
        console.log(`[SERVER] x-erpt social network running at http://localhost:${port}`);
        console.log('[INFO] Designed for IE5+ compatibility using simple HTML/CSS and server-side rendering.');
    });
}).catch(e => {
    console.error('FATAL: Database initialization failed.', e);
});