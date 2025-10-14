// --- Configuration Loading (Must be first) ---
require('dotenv').config();

// --- Dependencies and Setup ---
const express = require('express');
const app = express();
const port = process.env.PORT || 3000; 
const postCharCount = process.env.POST_CHAR_COUNT || 280; 

// File Upload Dependencies
const multer = require('multer');
const path = require('path');
const fs = require('fs'); 

// Security and Session Dependencies
const bcrypt = require('bcrypt');
const saltRounds = 10;
const session = require('express-session');
const qdb = require('quick.db');
const db = new qdb.QuickDB({ filePath: process.env.DB_FILEPATH || './social_network_db.sqlite' });
const domain = process.env.DOMAIN || `localhost:${port}`; 

// --- Multer Configuration for File Uploads ---

// Ensure the 'uploads' directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// 1. Storage Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

    if (mimetype && extname) {
        return cb(null, true);
    }
    cb(new Error('Only images (jpeg, jpg, png, gif) are allowed.'));
};

// 2. Multer Handler for Post Images
const postUpload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: fileFilter
}).single('postImage');

// 3. Multer Handler for PFP Uploads
const pfpUpload = multer({
    storage: storage,
    limits: { fileSize: 1 * 1024 * 1024 },
    fileFilter: fileFilter
}).single('pfpImage');


// --- Initialization Block to Ensure Schema ---
async function initializeDatabase() {
    const users = await db.get('users');
    if (typeof users !== 'object' || Array.isArray(users) || users === null) {
        await db.set('users', {});
    } else {
        for (const userId in users) {
            if (!users[userId].pfpUrl) {
                users[userId].pfpUrl = 'https://i.imgur.com/example_default_pfp.png';
            }
            // Ensure follow arrays exist
            users[userId].followers = users[userId].followers || [];
            users[userId].following = users[userId].following || [];
        }
        await db.set('users', users);
    }
    
    const posts = await db.get('posts');
    if (!Array.isArray(posts)) {
        await db.set('posts', []);
    } else {
        // Ensure posts have necessary like properties
        const updatedPosts = posts.map(post => ({
            ...post,
            likes: post.likes || 0,
            likedBy: post.likedBy || []
        }));
        await db.set('posts', updatedPosts);
    }

    const messages = await db.get('messages');
    if (!Array.isArray(messages)) {
        await db.set('messages', []);
    }
}

// --- Configuration and Middleware ---

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

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

// --- IE5 Compatible HTML/CSS Utilities ---

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

    // This ensures the limit of 5 unique tags and is now the source of truth.
    return Object.entries(hashtagCounts)
        .sort(([, countA], [, countB]) => countB - countA)
        .slice(0, 5)
        .map(([tag, count]) => ({ tag, count }));
}

function linkifyContent(content) {
    return content.replace(/#(\w+)/g, (match, tag) => {
        return `<a href="/search?q=%23${tag}" style="color: #0077cc; text-decoration: none;">${match}</a>`;
    });
}

// NEW UTILITY: Get a user object by their username
async function getUserByUsername(username) {
    const users = await db.get('users');
    return Object.values(users).find(u => u.username.toLowerCase() === username.toLowerCase());
}

// NEW UTILITY: Get a user object by their ID
async function getUserById(userId) {
    return await db.get(`users.${userId}`);
}

// NEW UTILITY: Get all posts for a specific user ID
async function getPostsByUserId(userId) {
    const postsRaw = await db.get('posts');
    const allPosts = Array.isArray(postsRaw) ? postsRaw : Object.values(postsRaw || {});
    return allPosts
        .filter(post => post.userId === userId)
        .sort((a, b) => b.timestamp - a.timestamp);
}

// NEW UTILITY: Get a single post by ID
async function getPostById(postId) {
    const postsRaw = await db.get('posts');
    const allPosts = Array.isArray(postsRaw) ? postsRaw : Object.values(postsRaw || {});
    return allPosts.find(post => post.id === postId);
}


// Basic, IE5-compatible CSS for layout and style
const IE5_STYLES = `
    body { 
        font-family: Arial, sans-serif; 
        background-color: #a4e5ed;
        margin: 0; 
        padding: 0;
    }
    .header-wrapper {
        background-color: #ffffff;
        padding: 10px 0;
        margin-bottom: 20px;
        border-bottom: 1px solid #cceeff;
    }
    .header {
        background-color: #ffffff;
        padding: 0 10px; 
        text-align: left;
        width: 900px;
        margin: 0 auto;
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
        width: 18%; /* Keeps the width for proportion */
        min-height: 400px;
        font-size: 14px;
        /* CORRECT STYLES for White Box: */
        background-color: #ffffff; 
        padding: 15px; /* Padding inside the white box */
        margin-right: 20px; /* Space between nav-col and main-col */
        box-sizing: border-box; /* Include padding/border in width */
        border: 1px solid #ccc; /* Add border for distinct box look */
        text-align: left; /* Ensure content is left-aligned */
    }
    .main-col {
        float: left; 
        width: 64%; /* Adjusted to leave room for the nav and side columns */
        padding: 0 10px;
        padding-left: 20px;
        padding-right: 12px;
        min-height: 400px;
        box-sizing: border-box;
    }
    .side-col {
        float: right; 
        width: 30%;
        padding-left: 10px;
        min-height: 400px;
        text-align: right;
        align: right;
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
    /* FIX: Corrected internal nav styles to ensure links and headers are visually contained */
    .nav-col h2 {
        color: #0077cc;
        margin: 15px 0 5px 0; /* Add margin above to separate sections */
        font-weight: bold;
        border-bottom: 1px solid #cceeff; /* Lighter border for inner separators */
        padding-bottom: 3px;
        font-size: 16px;
    }
    .nav-col h2:first-child {
        margin-top: 0;
    }
    .nav-col p {
        color: #0077cc;
        margin: 5px 0;
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
        max-width: 95%;
        height: auto;
        display: block;
        margin: 10px 0 10px 45px;
        border: 1px solid #eee;
    }
    input[type="text"], input[type="password"], textarea, input[type="file"] {
        width: 95%; 
        padding: 5px; 
        margin-bottom: 10px; 
        border: 1px solid #ccc;
        box-sizing: border-box;
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
    /* IE5/Mobile Dynamic Shim */
    .flex-shim .flex-shim .main-col, .flex-shim .side-col {
        float: none;
        width: 100%;
        padding: 0 10px;
        box-sizing: border-box;
        margin-right: 0;
        border: none;
        background-color: transparent;
    }
    .flex-shim .container {
        width: 100%;
    }
`;

// Navigation Content HTML fragment
// UPDATED: Now conditionally adds the Trending section based on trendingHtml input.
function navContent(trendingHtml = '') {
    let trendingSection = '';
    if (trendingHtml) {
        trendingSection = `
            <h2 style="margin-top: 15px;">Trending</h2>
            ${trendingHtml}
        `;
    }

    return `
        <div class="nav-col">
            <h2 style="color: #0077cc; font-size: 18px;">Navigation</h2>
            <a href="/">Home</a>
            <a href="/profile">Profile</a>
            <a href="/search">Search</a>
            <a href="/followers">Following/Followers</a>
            
            ${trendingSection}

            <h2 style="margin-top: 15px;">Messages</h2>
            <a href="/inbox">Inbox</a>
            <a href="/compose">Compose</a>
        </div>
    `;
}

// Generic HTML structure generator (Same as previous version)
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
    <div class="header-wrapper">
        <div class="header">
            <h1>x-erpt</h1>
            <div class="header-right">${headerRight}</div>
            <div style="clear: both;"></div>
        </div>
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

// --- Authentication Routes (Same as previous version) ---
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


// --- Routes: Functionality (Posts, Profile, Follow) ---

// POST /post - Submit a new post (Same as previous version)
app.post('/post', requireLogin, (req, res) => {
    postUpload(req, res, async (err) => {
        if (err instanceof multer.MulterError) {
            return res.redirect(`/?error=${encodeURIComponent('File upload error: ' + err.message)}`);
        } else if (err) {
            return res.redirect(`/?error=${encodeURIComponent('Upload failed: ' + err.message)}`);
        }
        
        const { content } = req.body;
        const filePath = req.file ? `/uploads/${req.file.filename}` : null; 
        
        if (!content || content.trim() === '') {
            if (filePath) {
                fs.unlink(path.join(__dirname, req.file.path), (unlinkErr) => {
                    if (unlinkErr) console.error('Error cleaning up file:', unlinkErr);
                });
            }
            return res.redirect('/?error=Post%20content%20cannot%20be%20empty.');
        }

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
            content: content.substring(0, postCharCount),
            imageUrl: filePath, 
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

// POST /profile - Update user profile (Same as previous version)
app.post('/profile', requireLogin, (req, res) => {
    pfpUpload(req, res, async (err) => {
        let error = '';

        if (err instanceof multer.MulterError) {
            error = 'PFP upload error: ' + err.message;
        } else if (err) {
            error = 'PFP upload failed: ' + err.message;
        }
        
        const { bio, newPassword } = req.body;
        const currentData = await db.get(`users.${req.user.id}`);
        let updateData = { ...currentData }; 

        if (req.file) {
            if (updateData.pfpUrl && updateData.pfpUrl.startsWith('/uploads/')) {
                fs.unlink(path.join(__dirname, updateData.pfpUrl), (unlinkErr) => {
                    if (unlinkErr) console.error('Error deleting old PFP file:', unlinkErr);
                });
            }
            updateData.pfpUrl = `/uploads/${req.file.filename}`;
        }
        
        if (bio !== undefined) {
            updateData.bio = bio.substring(0, 150);
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
});

// GET /profile - View and edit profile 
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
                
                <form action="/profile" method="POST" enctype="multipart/form-data">
                    <p>Change Profile Picture (Max 1MB):</p>
                    <input type="file" name="pfpImage" accept="image/jpeg,image/png,image/gif" style="width: 100%; padding: 0; margin-bottom: 5px; border: none;">
                    
                    <p>Bio (max 150 chars):</p>
                    <textarea name="bio" rows="4">${user.bio || ''}</textarea>
                    
                    <p>New Password:</p>
                    <input type="password" name="newPassword" placeholder="Leave blank to keep current">
                    
                    <input type="submit" value="Update Profile">
                </form>
            </div>
        </div>
    `;

    // UPDATED: Nav Content called without trending
    const finalContent = `
        ${navContent('')} 
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


// NEW ROUTE: GET /user/:username - View another user's profile
app.get('/user/:username', requireLogin, async (req, res) => {
    const targetUsername = req.params.username;
    const error = req.query.error || '';
    
    const targetUser = await getUserByUsername(targetUsername);

    if (!targetUser) {
        return res.redirect(`/?error=${encodeURIComponent('User not found.')}`);
    }

    // Redirect if viewing your own profile
    if (targetUser.id === req.user.id) {
        return res.redirect('/profile');
    }

    const posts = await getPostsByUserId(targetUser.id);
    const isFollowing = req.user.following && req.user.following.includes(targetUser.id);
    const followActionText = isFollowing ? 'Unfollow' : 'Follow';
    const followActionColor = isFollowing ? '#f44336' : '#3cb371';
    
    let userPostsHtml = '<h3>Recent Posts</h3>';
    if (posts.length > 0) {
        posts.forEach(post => {
            const linkedContent = linkifyContent(post.content);
            const postImageHtml = post.imageUrl ? `<img src="${post.imageUrl}" class="post-image" alt="Post Image">` : '';

            userPostsHtml += `
                <div class="post">
                    ${postImageHtml}
                    <p class="post-text">${linkedContent}</p>
                    <div class="post-actions" style="margin-left: 0;">
                        <small>Posted on ${post.date}</small>
                    </div>
                </div>
            `;
        });
    } else {
        userPostsHtml += '<p>This user has not posted yet.</p>';
    }

    const mainColContent = `
        <div class="main-col" style="float: none; width: 100%; padding: 0;">
            <div class="box">
                <img src="${targetUser.pfpUrl}" class="pfp" style="margin-right: 10px;">
                <h2 style="margin-left: 55px; margin-top: 5px; border-bottom: none;">${targetUser.username}</h2>
                <div style="clear: both;"></div>

                <p style="font-size: 14px; margin-top: 10px;">
                    <strong>Bio:</strong> ${targetUser.bio}<br>
                    <strong>Joined:</strong> ${targetUser.joinDate}<br>
                    <strong>Followers:</strong> ${(targetUser.followers || []).length}<br>
                    <strong>Following:</strong> ${(targetUser.following || []).length}
                </p>
                
                <form action="/follow" method="POST" style="margin-top: 10px;">
                    <input type="hidden" name="targetUserId" value="${targetUser.id}">
                    <input type="hidden" name="action" value="${isFollowing ? 'unfollow' : 'follow'}">
                    <input type="submit" value="${followActionText}" style="background-color: ${followActionColor};">
                </form>
            </div>
            
            <div class="box">
                ${userPostsHtml}
            </div>
        </div>
    `;

    // UPDATED: Nav Content called without trending
    const finalContent = `
        ${navContent('')}
        <div class="main-col">
            ${mainColContent}
        </div>
        <div class="side-col">
            <div class="box">
                <p>Viewing ${targetUser.username}'s profile.</p>
                <p><a href="/">Back to Home Feed</a></p>
            </div>
        </div>
    `;

    res.send(createHtml(targetUser.username, finalContent, error, req.user));
});


// NEW ROUTE: POST /follow - Handle follow/unfollow action
app.post('/follow', requireLogin, async (req, res) => {
    const { targetUserId, action } = req.body;
    const currentUserId = req.user.id;

    if (currentUserId === targetUserId) {
        return res.redirect(`/?error=${encodeURIComponent('Cannot follow/unfollow yourself.')}`);
    }

    const targetUser = await getUserById(targetUserId);

    if (!targetUser) {
        return res.redirect(`/?error=${encodeURIComponent('Target user not found.')}`);
    }

    let currentUser = await db.get(`users.${currentUserId}`);
    let targetUserDb = targetUser;
    
    // Ensure arrays exist
    currentUser.following = currentUser.following || [];
    targetUserDb.followers = targetUserDb.followers || [];

    let message = '';
    
    if (action === 'follow') {
        if (!currentUser.following.includes(targetUserId)) {
            currentUser.following.push(targetUserId);
            targetUserDb.followers.push(currentUserId);
            message = `Successfully followed ${targetUser.username}.`;
        } else {
            message = `Already following ${targetUser.username}.`;
        }
    } else if (action === 'unfollow') {
        const followingIndex = currentUser.following.indexOf(targetUserId);
        if (followingIndex > -1) {
            currentUser.following.splice(followingIndex, 1);
        }

        const followerIndex = targetUserDb.followers.indexOf(currentUserId);
        if (followerIndex > -1) {
            targetUserDb.followers.splice(followerIndex, 1);
        }
        message = `Successfully unfollowed ${targetUser.username}.`;
    } else {
        return res.redirect(`/?error=${encodeURIComponent('Invalid follow action.')}`);
    }

    // Update both users in the database
    await db.set(`users.${currentUserId}`, currentUser);
    await db.set(`users.${targetUserId}`, targetUserDb);

    // Redirect back to the user's profile page
    res.redirect(`/user/${targetUser.username}?error=${encodeURIComponent(message)}`);
});


// NEW ROUTE: GET /followers - View following/followers lists
app.get('/followers', requireLogin, async (req, res) => {
    const error = req.query.error || '';
    const user = req.user;
    const allUsers = await db.get('users');
    
    // Helper function to build list HTML
    const buildListHtml = (userIds, title) => {
        if (!userIds || userIds.length === 0) {
            return `<div class="box"><h2>${title}</h2><p>None yet.</p></div>`;
        }

        let html = `<div class="box"><h2>${title}</h2>`;
        userIds.forEach(id => {
            const followedUser = allUsers[id];
            if (followedUser) {
                html += `
                    <div style="padding: 5px 0; border-bottom: 1px dotted #eee;">
                        <img src="${followedUser.pfpUrl}" class="pfp" style="width: 30px; height: 30px;">
                        <a href="/user/${followedUser.username}" class="post-user" style="margin-left: 5px; line-height: 30px; font-size: 14px;">${followedUser.username}</a>
                        <div style="clear: both;"></div>
                    </div>
                `;
            }
        });
        html += '</div>';
        return html;
    };

    const followingList = buildListHtml(user.following, `Following (${(user.following || []).length})`);
    const followersList = buildListHtml(user.followers, `Followers (${(user.followers || []).length})`);

    const mainColContent = `
        <div class="main-col" style="float: none; width: 100%; padding: 0;">
            ${followingList}
            ${followersList}
        </div>
    `;

    // UPDATED: Nav Content called without trending
    const finalContent = `
        ${navContent('')} 
        <div class="main-col">
            ${mainColContent}
        </div>
        <div class="side-col">
            <div class="box">
                <p>Use the links to the left to navigate.</p>
                <p><a href="/profile">Back to Profile</a></p>
            </div>
        </div>
    `;

    res.send(createHtml('Followers', finalContent, error, req.user));
});

// NEW ROUTE: GET /search - Search for posts by hashtag or username
app.get('/search', requireLogin, async (req, res) => {
    const query = req.query.q ? req.query.q.trim() : '';
    const error = req.query.error || '';
    
    let resultsHtml = '';
    let postsRaw = await db.get('posts');
    const allPosts = Array.isArray(postsRaw) ? postsRaw : Object.values(postsRaw || {});
    const searchResults = [];

    if (query) {
        let isHashtag = query.startsWith('#');
        let searchTerm = isHashtag ? query.substring(1).toLowerCase() : query.toLowerCase();

        // Filter posts
        const filteredPosts = allPosts.filter(post => {
            if (isHashtag) {
                // Search by hashtag
                return post.hashtags && post.hashtags.includes(searchTerm);
            } else {
                // Search by content or username (simple substring match)
                return post.content.toLowerCase().includes(searchTerm) || 
                       post.username.toLowerCase().includes(searchTerm);
            }
        }).sort((a, b) => b.timestamp - a.timestamp); // Sort newest first

        if (filteredPosts.length > 0) {
            resultsHtml += `<h2>Results for "${query}" (${filteredPosts.length} Posts)</h2>`;
            filteredPosts.forEach(post => {
                const linkedContent = linkifyContent(post.content);
                const postImageHtml = post.imageUrl ? `<img src="${post.imageUrl}" class="post-image" alt="Post Image">` : '';
                
                const userLink = post.userId === req.user.id 
                    ? '/profile' 
                    : `/user/${post.username}`;


                resultsHtml += `
                    <div class="post">
                        <img src="${post.pfpUrl}" class="pfp">
                        <div class="post-header">
                            <a href="${userLink}" class="post-user">${post.username}</a> <small>(${post.date})</small>
                        </div>
                        <div style="clear: both;"></div>

                        ${postImageHtml}
                        <p class="post-text">${linkedContent}</p>
                    </div>
                `;
            });
        } else {
            resultsHtml = `<h2>Results for "${query}"</h2><p>No posts found matching your query.</p>`;
        }
    } else {
        resultsHtml = '<h2>Search Tips</h2><p>Enter a keyword to search by post content or username, or start your query with **#** to search for a specific hashtag (e.g., `#retrogaming`).</p>';
    }

    const mainColContent = `
        <div class="main-col">
            <div class="box">
                <h2>Search x-erpt</h2>
                <form action="/search" method="GET">
                    <input type="text" name="q" value="${query}" placeholder="Search username, keyword, or #hashtag" required>
                    <input type="submit" value="Search">
                </form>
            </div>
            
            <div class="box">
                ${resultsHtml}
            </div>
        </div>
    `;

    // UPDATED: Nav Content called without trending
    const finalContent = `
        ${navContent('')}
        ${mainColContent}
        <div class="side-col">
            <div class="box">
                <p>Search is a powerful tool to find old content!</p>
            </div>
        </div>
    `;

    res.send(createHtml('Search', finalContent, error, req.user));
});


// POST /like - Handle liking/unliking a post (No change needed)
app.post('/like', requireLogin, async (req, res) => {
    const { postId } = req.body;
    const currentUserId = req.user.id;
    let redirectUrl = req.header('Referer') || '/';

    if (!postId) {
        return res.redirect(`${redirectUrl}?error=${encodeURIComponent('Missing post ID.')}`);
    }

    const postsRaw = await db.get('posts');
    const allPosts = Array.isArray(postsRaw) ? postsRaw : Object.values(postsRaw || {});
    const postIndex = allPosts.findIndex(p => p.id === postId);

    if (postIndex === -1) {
        return res.redirect(`${redirectUrl}?error=${encodeURIComponent('Post not found.')}`);
    }

    let post = allPosts[postIndex];
    
    // Ensure like fields exist
    post.likedBy = post.likedBy || [];
    post.likes = post.likes || 0;

    const likedIndex = post.likedBy.indexOf(currentUserId);
    let message = '';

    if (likedIndex > -1) {
        // Unlike
        post.likedBy.splice(likedIndex, 1);
        post.likes -= 1;
        message = 'Post unliked.';
    } else {
        // Like
        post.likedBy.push(currentUserId);
        post.likes += 1;
        message = 'Post liked!';
    }

    // Update the post in the array and save back to DB
    allPosts[postIndex] = post;
    await db.set('posts', allPosts);
    
    res.redirect(`${redirectUrl}?error=${encodeURIComponent(message)}`);
});

// POST /share - Generate share link and redirect to feed (No change needed)
app.post('/share', requireLogin, async (req, res) => {
    const { postId } = req.body;
    
    if (!postId) {
        return res.redirect(`/?error=${encodeURIComponent('Missing post ID for sharing.')}`);
    }
    
    const post = await getPostById(postId);
    
    if (!post) {
        return res.redirect(`/?error=${encodeURIComponent('Post not found for sharing.')}`);
    }
    
    // Redirects to home, which will then display the share link box for that post ID
    res.redirect(`/?sharePostId=${postId}`);
});

// GET /post/:postId - View a single post (for public sharing) (No change needed)
app.get('/post/:postId', async (req, res) => {
    const postId = req.params.postId;
    const post = await getPostById(postId);

    if (!post) {
        return res.status(404).send(createHtml('Post Not Found', '<div class="main-col"><div class="box"><h2>Error 404</h2><p>The post you are looking for does not exist or has been deleted.</p></div></div>'));
    }

    const linkedContent = linkifyContent(post.content);
    const postImageHtml = post.imageUrl ? `<img src="${post.imageUrl}" class="post-image" alt="Post Image" style="margin-left: 0; max-width: 100%;">` : '';

    const postHtml = `
        <div class="box">
            <img src="${post.pfpUrl}" class="pfp" style="float: left;">
            <div class="post-header" style="margin-left: 5px;">
                <p style="margin: 0;"><strong class="post-user">${post.username}</strong></p>
                <small style="color: #666;">Posted on ${post.date}</small>
            </div>
            <div style="clear: both;"></div>

            ${postImageHtml}
            <p class="post-text" style="margin-left: 0;">${linkedContent}</p>

            <div class="post-actions" style="margin-left: 0; padding-top: 10px; border-top: 1px solid #eee;">
                <strong>Likes:</strong> ${post.likes || 0}
            </div>
        </div>
        <p style="text-align: center;"><a href="/login">Login</a> to reply, like, or follow!</p>
    `;
    
    const bodyContent = `<div class="main-col" style="float: none; width: 60%; margin: 20px auto; padding: 0;"><h2>Post from ${post.username}</h2>${postHtml}</div>`;

    res.send(createHtml(`Post by ${post.username}`, bodyContent));
});


// --- Direct Messages (DM) Routes (Same as previous version) ---

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
                    <p><strong>From: <a href="/user/${senderUsername}" class="post-user">${senderUsername}</a></strong> 
                    <small>(${latestMsg.date})</small></p>
                    <p class="post-text" style="margin-left: 0;">${latestMsg.content.substring(0, 50)}...</p>
                    <p><a href="/compose?recipient=${senderUsername}">Reply</a> 
                    | <a href="/inbox/view/${senderId}">View Thread (Not Implemented)</a></p>
                </div>
            `;
        }
    }

    const mainColContent = `<div class="main-col"><div class="box">${inboxHtml}</div></div>`;

    // UPDATED: Nav Content called without trending
    const finalContent = `
        ${navContent('')}
        ${mainColContent}
        <div class="side-col"><div class="box"><p><a href="/compose">Compose New Message</a></p></div></div>
    `;
    res.send(createHtml('Inbox', finalContent, req.query.error, req.user));
});

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

    // UPDATED: Nav Content called without trending
    const finalContent = `
        ${navContent('')}
        ${mainColContent}
        <div class="side-col"><div class="box"><p><a href="/inbox">Back to Inbox</a></p></div></div>
    `;

    res.send(createHtml('Compose DM', finalContent, error, req.user));
});

app.post('/compose', requireLogin, async (req, res) => {
    const { recipient, content } = req.body;

    if (!recipient || !content) {
        return res.redirect(`/compose?error=${encodeURIComponent('Recipient and content are required.')}`);
    }

    const recipientUser = await getUserByUsername(recipient);

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


// GET / - Home/Feed Page 
app.get('/', requireLogin, async (req, res) => {
    const error = req.query.error || '';
    const sharePostId = req.query.sharePostId; 
    
    // FETCH TRENDING TOPICS (only for home page)
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
    `;

    // UPDATED: Nav Content called WITH trending data
    const navHtml = navContent(trendingHtml);


    const postForm = `
        <div class="box">
            <p style="font-weight: bold; margin-top: 0;">What are you doing?</p>
            
            <form action="/post" method="POST" enctype="multipart/form-data">
                <textarea name="content" rows="4" placeholder="Share something (max ${postCharCount} chars)..." required style="width: 100%; border: 1px solid #ccc;"></textarea>
                
                <p style="margin-bottom: 5px; margin-top: 5px;">Attach Image (Optional, max 5MB):</p>
                <input type="file" name="postImage" accept="image/jpeg,image/png,image/gif" style="width: 100%; padding: 0; margin-bottom: 5px; border: none;">

                <div style="margin-top: 10px; padding-top: 5px; border-top: 1px solid #eee;">
                    <input type="submit" value="Update" style="float: right;">
                    <div style="clear: both;"></div>
                </div>
            </form>
        </div>
    `;

    let feedContent = '<h2>Your Feed</h2>';
    
    const postsRaw = await db.get('posts');
    const posts = Array.from(Array.isArray(postsRaw) ? postsRaw : Object.values(postsRaw || {}))
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, 50); 

    if (posts.length > 0) {
        posts.forEach(post => {
            const likeCount = post.likes || 0;
            const hasLiked = post.likedBy && post.likedBy.includes(req.user.id);
            const likeAction = hasLiked ? 'Unlike' : 'Like';

            const postPfpUrl = post.pfpUrl || 'https://i.imgur.com/example_default_pfp.png';
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
            
            // NEW: Create link to user profile
            const userLink = post.userId === req.user.id 
                ? '/profile' 
                : `/user/${post.username}`;


            feedContent += `
                <div class="post">
                    <img src="${postPfpUrl}" class="pfp">
                    <div class="post-header">
                        <a href="${userLink}" class="post-user">${post.username}</a> <small>(${post.date})</small>
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

// Fallback to redirect non-logged-in users
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