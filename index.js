// --- Configuration Loading (Must be first) ---
// Loads configuration variables from the .env file (requires 'dotenv' package)
require('dotenv').config();

// --- Dependencies and Setup ---

// Required for Express server
const express = require('express');
const app = express();
// Use PORT from .env, fallback to 3000
const port = process.env.PORT || 3000; 

// Required for secure password hashing (MANDATORY for security)
const bcrypt = require('bcrypt');
const saltRounds = 10;

// Required for session management (crucial for stateful apps and IE5 compatibility)
const session = require('express-session');

// Quick.DB (SQLite backend) for simple, file-based persistence
const qdb = require('quick.db');
// Use DB_FILEPATH from .env, fallback if needed
const db = new qdb.QuickDB({ filePath: process.env.DB_FILEPATH || './social_network_db.sqlite' });

const domain = process.env.DOMAIN || "localhost"

// --- Initialization Block to Ensure Schema ---
// This routine ensures that 'users' is an object and 'posts' is an array,
// preventing the "not an array" error when using db.push().
async function initializeDatabase() {
    // 1. Ensure 'users' is an Object (or Map). 
    const users = await db.get('users');
    if (typeof users !== 'object' || Array.isArray(users) || users === null) {
        console.log('[DB INIT] Fixing "users" structure to be an object ({}).');
        await db.set('users', {});
    }
    
    // 2. Ensure 'posts' is an Array (Critical for db.push).
    const posts = await db.get('posts');
    if (!Array.isArray(posts)) {
        console.log('[DB INIT] Fixing "posts" structure to be an array ([]).');
        await db.set('posts', []);
    }
}

// --- Configuration and Middleware ---

// Use URL-encoded body parser to handle standard form submissions
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Set up sessions for state management
app.use(session({
    // Use SESSION_SECRET from .env, fallback if needed
    secret: process.env.SESSION_SECRET || 'default-secret-for-social-network', 
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // 1 day cookie life
        httpOnly: true, // Prevent client-side script access
        secure: false, // Must be false for local HTTP development
    }
}));

// Middleware to check if a user is logged in
function requireLogin(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        // Redirect to login page
        res.redirect('/login');
    }
}

// Middleware to load user data into request object
async function loadUser(req, res, next) {
    if (req.session.userId) {
        // Fetch user data from DB using the session ID
        req.user = await db.get(`users.${req.session.userId}`);
    }
    next();
}

app.use(loadUser);

// --- IE5 Compatible HTML/CSS Utilities ---

// Basic, IE5-compatible CSS for layout and style
const IE5_STYLES = `
    body { 
        font-family: Arial, sans-serif; 
        background-color: #f7f7f7; 
        margin: 0; 
        padding: 0;
    }
    .header {
        background-color: #dbe9f6; 
        padding: 20px 0; 
        margin-bottom: 20px; 
        text-align: center;
        border-bottom: 1px solid #cceeff;
    }
    .header h1 { 
        color: #0077cc; 
        margin: 0; 
        font-size: 24px;
    }
    .header p { 
        color: #666; 
        font-size: 14px; 
        margin-top: 5px;
    }
    .container {
        width: 800px; /* Fixed width is highly reliable for IE5 layout */
        margin: 0 auto; 
        padding: 10px;
        overflow: hidden; /* Contains floats */
    }
    .main-col {
        float: left; 
        width: 65%; 
        padding-right: 20px;
        min-height: 400px;
    }
    .side-col {
        float: right; 
        width: 30%; 
        min-height: 400px;
    }
    .box {
        background-color: #ffffff; 
        border: 1px solid #ccc; 
        padding: 15px; 
        margin-bottom: 20px;
    }
    h2 {
        font-size: 18px; 
        color: #333; 
        border-bottom: 1px solid #eee; 
        padding-bottom: 5px;
        margin-top: 0;
    }
    .post {
        border-bottom: 1px solid #eee; 
        padding: 10px 0;
    }
    .post:last-child {
        border-bottom: none;
    }
    .post-user { 
        font-weight: bold; 
        color: #0077cc; 
    }
    .post-text { 
        margin-top: 5px; 
        font-size: 14px; 
        white-space: pre-wrap;
    }
    input[type="text"], input[type="password"], textarea {
        width: 95%; 
        padding: 5px; 
        margin-bottom: 10px; 
        border: 1px solid #ccc;
    }
    input[type="submit"] {
        background-color: #0077cc; 
        color: white; 
        border: none; 
        padding: 8px 15px; 
        cursor: pointer; 
        font-size: 14px;
    }
    input[type="submit"]:hover {
        background-color: #005fa3;
    }
    .error {
        color: red; 
        font-weight: bold;
    }
    .post-actions {
        display: inline;
        font-size: 12px;
        color: #666;
    }
    .like-button {
        color: #0077cc;
        cursor: pointer;
        background: none;
        border: none;
        padding: 0;
        text-decoration: underline;
        font-size: 12px;
    }
    .like-button:hover {
        color: #005fa3;
    }
`;

// Generic HTML structure generator
function createHtml(title, bodyContent, error = '') {
    return `
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <title>${title}</title>
    <style type="text/css">
        ${IE5_STYLES}
    </style>
</head>
<body>
    <div class="header">
        <h1>X-erpt</h1>
        <p>Connecting you with friends.</p>
    </div>
    <div class="container">
        ${error ? `<div class="box" style="background-color: #ffebeb; border-color: #ffcccc;"><p class="error">${decodeURIComponent(error)}</p></div>` : ''}
        ${bodyContent}
    </div>
    <div style="clear: both;"></div>
</body>
</html>
    `;
}

// --- Authentication Logic ---

async function hashPassword(password) {
    return await bcrypt.hash(password, saltRounds);
}

async function checkPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

// --- Routes: Authentication ---

// GET /register
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
                    <input type="submit" value="Register">
                </form>
                <p>Already have an account? <a href="/login">Login here</a>.</p>
            </div>
        </div>
    `;
    res.send(createHtml('Register - X-erpt', content, req.query.error));
});

// POST /register
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
            bio: 'A new user on X-erpt!',
            joinDate: new Date().toLocaleDateString('en-US')
        };

        await db.set(`users.${userId}`, newUser);

        req.session.userId = userId;
        res.redirect('/');

    } catch (e) {
        console.error('Registration error:', e);
        res.redirect('/register?error=An%20internal%20error%20occurred.');
    }
});

// GET /login
app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    const content = `
        <div class="main-col" style="float: none; width: 100%; padding-right: 0;">
            <div class="box" style="width: 50%; margin: 40px auto; min-height: 0;">
                <h2>Login</h2>
                <form action="/login" method="POST">
                    <p>Username:</p>
                    <input type="text" name="username" required>
                    <p>Password:</p>
                    <input type="password" name="password" required>
                    <input type="submit" value="Login">
                </form>
                <p>Don't have an account? <a href="/register">Register here</a>.</p>
            </div>
        </div>
    `;
    res.send(createHtml('Login - X-erpt', content, req.query.error));
});

// POST /login
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

// GET /logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
        }
        res.redirect('/login');
    });
});


// --- Routes: Functionality ---

// POST /post - Submit a new post
app.post('/post', requireLogin, async (req, res) => {
    const { content } = req.body;

    if (!content || content.trim() === '') {
        return res.redirect('/?error=Post%20content%20cannot%20be%20empty.');
    }

    const newPost = {
        id: Date.now().toString(),
        userId: req.user.id,
        username: req.user.username,
        content: content.substring(0, 280), // Simple character limit
        timestamp: Date.now(),
        date: new Date().toLocaleString('en-US'),
        likes: 0, // Initialize likes count
        likedBy: [], // Initialize list of users who liked it
    };

    await db.push('posts', newPost);

    res.redirect('/');
});


// POST /like - Toggle Like/Unlike on a Post
app.post('/like', requireLogin, async (req, res) => {
    const { postId } = req.body;
    const userId = req.user.id;

    const postsRaw = await db.get('posts');
    const posts = Array.isArray(postsRaw) ? postsRaw : Object.values(postsRaw || {});
    
    const postIndex = posts.findIndex(p => p.id === postId);

    if (postIndex !== -1) {
        const post = posts[postIndex];
        if (!Array.isArray(post.likedBy)) post.likedBy = [];

        const likedIndex = post.likedBy.indexOf(userId);

        if (likedIndex === -1) {
            post.likes = (post.likes || 0) + 1;
            post.likedBy.push(userId);
        } else {
            post.likes = (post.likes || 1) - 1; 
            post.likedBy.splice(likedIndex, 1);
        }
        
        if (post.likes < 0) post.likes = 0; 
        posts[postIndex] = post;

        await db.set('posts', posts); 
    }

    // Redirect back to the page the user came from (or default to home)
    res.redirect(req.headers.referer || '/');
});

/**
 * NEW: POST /share now triggers a redirect to the home page, passing the post ID
 * so the share link can be rendered below the post.
 */
app.post('/share', requireLogin, (req, res) => {
    const { postId } = req.body;
    
    // Redirect to home page with the postId set as a query parameter
    res.redirect(`/?sharePostId=${postId}`);
});

// POST /profile - Update user profile (bio/password)
app.post('/profile', requireLogin, async (req, res) => {
    const { bio, newPassword } = req.body;
    let error = '';

    const currentData = await db.get(`users.${req.user.id}`);
    let updateData = { ...currentData }; 

    // 1. Update Bio
    if (bio !== undefined) {
        updateData.bio = bio.substring(0, 150);
    }
    
    // 2. Update Password (if provided and valid)
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
    
    res.redirect(`/?error=${encodeURIComponent(error || 'Profile%20Updated!')}`);
});


// GET /search - Handle user and post searching
app.get('/search', requireLogin, async (req, res) => {
    const query = req.query.q || '';
    const error = req.query.error || '';

    let resultsHtml = '';
    const lowerQuery = query.toLowerCase();

    if (query.trim() === '') {
        resultsHtml += '<p>Please enter a search query above.</p>';
    } else {

        // 1. Search Users
        const users = await db.get('users');
        const userResults = Object.values(users).filter(u => 
            u.username.toLowerCase().includes(lowerQuery) || 
            u.bio.toLowerCase().includes(lowerQuery)
        );

        resultsHtml += '<h3>Users:</h3>';
        if (userResults.length > 0) {
            userResults.forEach(user => {
                resultsHtml += `<div class="post">
                    <p><span class="post-user">${user.username}</span> <small>(Joined: ${user.joinDate})</small></p>
                    <p class="post-text">Bio: ${user.bio}</p>
                </div>`;
            });
        } else {
            resultsHtml += '<p>No users found matching query.</p>';
        }

        // 2. Search Posts
        const postsRaw = await db.get('posts');
        const posts = Array.isArray(postsRaw) ? postsRaw : Object.values(postsRaw || {});

        const postResults = Array.from(posts).filter(p => 
            p.content.toLowerCase().includes(lowerQuery) || 
            p.username.toLowerCase().includes(lowerQuery)
        )
        .sort((a, b) => b.timestamp - a.timestamp); // Sort by newest first

        resultsHtml += '<h3>Posts:</h3>';
        if (postResults.length > 0) {
            postResults.forEach(post => {
                const likeCount = post.likes || 0;
                const hasLiked = post.likedBy && post.likedBy.includes(req.user.id);
                const likeAction = hasLiked ? 'Unlike' : 'Like';

                resultsHtml += `<div class="post">
                    <p><span class="post-user">${post.username}</span> <small>(${post.date})</small></p>
                    <p class="post-text">${post.content}</p>
                    
                    <div class="post-actions">
                        <!-- Like/Unlike Button -->
                        <form action="/like" method="POST" style="display: inline; margin-right: 10px;">
                            <input type="hidden" name="postId" value="${post.id}">
                            <input type="submit" class="like-button" value="${likeAction} (${likeCount})">
                        </form>

                        <!-- Share Button -->
                        <form action="/share" method="POST" style="display: inline;">
                            <input type="hidden" name="postId" value="${post.id}">
                            <input type="submit" class="like-button" value="Share">
                        </form>
                    </div>

                </div>`;
            });
        } else {
            resultsHtml += '<p>No posts found matching query.</p>';
        }
    }

    // Build the search page content
    const content = `
        <div class="main-col">
            <div class="box">
                <h2>Search Users / Posts</h2>
                <form action="/search" method="GET">
                    <input type="text" name="q" placeholder="Type username or post..." value="${query}">
                    <input type="submit" value="Search">
                </form>
            </div>
            <div class="box">
                ${resultsHtml}
            </div>
        </div>
        <div class="side-col">
            <div class="box">
                <p>You are logged in as: <span class="post-user">${req.user.username}</span></p>
                <p><a href="/">Back to Home Feed</a></p>
                <p><a href="/logout">Logout</a></p>
            </div>
        </div>
        <div style="clear: both;"></div>
    `;

    res.send(createHtml('Search - X-erpt', content, error));
});


/**
 * NEW: GET /post/:id route for individual post viewing (used by the share link)
 */
app.get('/post/:id', async (req, res) => {
    const postId = req.params.id;

    const postsRaw = await db.get('posts');
    const posts = Array.isArray(postsRaw) ? postsRaw : Object.values(postsRaw || {});
    
    const post = posts.find(p => p.id === postId);

    if (post) {
        const content = `
            <div class="main-col" style="float: none; width: 100%; padding-right: 0;">
                <div class="box" style="width: 70%; margin: 20px auto; min-height: 0;">
                    <h2>Post Detail View</h2>
                    <div class="post" style="border-bottom: none;">
                        <p><span class="post-user">${post.username}</span> <small>(${post.date})</small></p>
                        <p class="post-text" style="font-size: 16px; border: 1px solid #eee; padding: 10px;">${post.content}</p>
                        <p><small>Likes: ${post.likes || 0}</small></p>
                    </div>
                    <p><a href="/">Go back to the feed</a></p>
                </div>
            </div>
        `;
        res.send(createHtml(`Post #${postId} - X-erpt`, content));
    } else {
        const content = `<div class="box"><h2>404 Error</h2><p>Post not found.</p><p><a href="/">Go back to the feed</a></p></div>`;
        res.send(createHtml('Not Found', content));
    }
});


// GET / - Home/Feed Page (Main View)
app.get('/', requireLogin, async (req, res) => {
    const error = req.query.error || '';
    // NEW: Get the ID of the post to show the share URL for
    const sharePostId = req.query.sharePostId; 

    // --- Side Column Content (Profile and Search) ---
    const sideColContent = `
        <!-- Your Profile Box -->
        <div class="box">
            <h2>Your Profile</h2>
            <form action="/profile" method="POST">
                <p style="font-size: 16px;"><span class="post-user">${req.user.username}</span></p>
                
                <p>Bio:</p>
                <!-- Bio input -->
                <textarea name="bio" rows="4">${req.user.bio || ''}</textarea>
                
                <p>New Password:</p>
                <input type="password" name="newPassword" placeholder="Leave blank to keep current">
                
                <input type="submit" value="Update Profile">
            </form>
        </div>

        <!-- Search Users / Posts Box -->
        <div class="box">
            <h2>Search Users / Posts</h2>
            <form action="/search" method="GET">
                <input type="text" name="q" placeholder="Type username or post..." required>
                <input type="submit" value="Search">
            </form>
        </div>
    `;


    // --- Main Column Content (Posting and Feed) ---
    
    // 1. Post Update Form (Posting functionality)
    const postForm = `
        <div class="box">
            <h2>What's happening with your friends?</h2>
            <div style="background-color: #f0f8ff; border: 1px solid #cceeff; padding: 10px; margin-bottom: 10px;">
                <p style="font-weight: bold; margin-top: 0;">"What are you up to?"</p>
                <p style="font-size: 12px; margin-bottom: 0;">Friends share quick updates and stay connected.</p>
            </div>
            
            <h2>Post an update</h2>
            <form action="/post" method="POST">
                <p>Share something (max 280 chars):</p>
                <textarea name="content" rows="4" placeholder="Share something..." required></textarea>
                <input type="submit" value="Post">
            </form>
        </div>
    `;

    // 2. Recent Updates Feed (Post viewing functionality)
    let feedContent = '<h2>Recent Updates</h2>';
    
    const postsRaw = await db.get('posts');
    const posts = Array.isArray(postsRaw) ? postsRaw : Object.values(postsRaw || {});


    // Sort posts to show newest first.
    const recentPosts = Array.from(posts)
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, 50); 

    if (recentPosts.length > 0) {
        recentPosts.forEach(post => {
            const likeCount = post.likes || 0;
            const hasLiked = post.likedBy && post.likedBy.includes(req.user.id);
            const likeAction = hasLiked ? 'Unlike' : 'Like';

            // Logic to display the share URL box if the ID matches the query param
            let shareUrlBox = '';
            if (sharePostId && post.id === sharePostId) {
                const fullShareUrl = `http://${domain}/post/${post.id}`; // Generate the shareable URL
                shareUrlBox = `
                    <div style="margin-top: 10px; padding: 8px; border: 1px dashed #0077cc; background-color: #e6f7ff;">
                        <p style="margin: 0; font-size: 12px; color: #333; font-weight: bold;">
                            Share link: <a href="${fullShareUrl}" target="_blank" style="color: #0077cc; text-decoration: underline;">${fullShareUrl}</a>
                        </p>
                        <!-- Close Button: Simple link redirecting to /, clearing the sharePostId parameter -->
                        <p style="margin: 5px 0 0 0;"><a href="/" style="font-size: 10px; color: #666; font-weight: bold;">[ CLOSE ]</a></p>
                    </div>
                `;
            }

            feedContent += `
                <div class="post">
                    <p><span class="post-user">${post.username}</span> <small>(${post.date})</small></p>
                    <p class="post-text">${post.content}</p>
                    
                    <div class="post-actions">
                        <!-- Like/Unlike Button (Form submission for IE5 compatibility) -->
                        <form action="/like" method="POST" style="display: inline; margin-right: 10px;">
                            <input type="hidden" name="postId" value="${post.id}">
                            <input type="submit" class="like-button" value="${likeAction} (${likeCount})">
                        </form>

                        <!-- Share Button (Form submission for IE5 compatibility) -->
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
        <div class="main-col">
            ${mainColContent}
        </div>
        <div class="side-col">
            ${sideColContent}
        </div>
    `;

    res.send(createHtml('Home - X-erpt', finalContent, error));
});


// Redirect the root path to the login page if not authenticated
app.get('/', (req, res) => {
    if (req.session.userId) {
        // User is logged in, continue to the home route
        res.redirect('/');
    } else {
        // User is not logged in, redirect to the login route
        res.redirect('/login');
    }
});

// --- Server Start ---

// Ensure the database initialization completes before starting the Express server.
initializeDatabase().then(() => {
    app.listen(port, () => {
        console.log(`[SERVER] X-erpt social network running at http://localhost:${port}`);
        console.log(`[CONFIG] Session Secret: ${process.env.SESSION_SECRET ? 'Loaded from .env' : 'Using default'}`);
        console.log('[INFO] Designed for IE5+ compatibility using simple HTML/CSS and server-side rendering.');
    });
}).catch(e => {
    console.error('FATAL: Database initialization failed.', e);
});
