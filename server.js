require('dotenv').config();

function validateEnvironment() {
    const required = [
        'STRIPE_SECRET_KEY',
        'STRIPE_WEBHOOK_SECRET',
        'EMAIL_USER',
        'EMAIL_PASS'
    ];
    
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
        console.error('❌ Missing environment variables:', missing);
        console.error('💡 Make sure these are set in Railway or your .env file');
        process.exit(1);
    } else {
        console.log('✅ All required environment variables are set');
        console.log('🔐 Using Stripe key:', process.env.STRIPE_SECRET_KEY.substring(0, 12) + '...');
        console.log('🪝 Webhook secret configured:', !!process.env.STRIPE_WEBHOOK_SECRET);
    }
}

// Call this at the very top of your file, right after require statements:
validateEnvironment();

// server.js
const express = require('express');
const mysql = require('mysql2');
const path = require('path');
const session = require('express-session');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

app.set('trust proxy', true);

// Connect to Database
const dbConfig = {
    host: process.env.MYSQLHOST || 'localhost',
    user: process.env.MYSQLUSER || 'root',
    password: process.env.MYSQLPASSWORD || 'ninTENdo12',
    database: process.env.MYSQLDATABASE || 'japanese_learning',
    port: process.env.MYSQLPORT || 3306,
    charset: 'utf8mb4'
};

let db;

function createConnection() {
    db = mysql.createConnection(dbConfig);
    
    db.connect((err) => {
        if (err) {
            console.error('Database connection failed:', err);
            console.log('Retrying connection in 5 seconds...');
            setTimeout(createConnection, 5000);
            return;
        }
        console.log('✅ Connected to MySQL database');

        ensureTablesExist();
    });

    db.on('error', (err) => {
        console.error('Database error:', err);
        if (err.code === 'PROTOCOL_CONNECTION_LOST' || 
            err.code === 'ECONNRESET' || 
            err.code === 'ETIMEDOUT') {
            console.log('🔄 Connection lost, reconnecting...');
            createConnection();
        } else {
            throw err;
        }
    });
}

createConnection();

function ensureTablesExist() {
    const tables = [
        `CREATE TABLE IF NOT EXISTS payments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            payment_intent_id VARCHAR(255) UNIQUE,
            email VARCHAR(255),
            amount DECIMAL(10,2),
            status VARCHAR(50),
            stripe_session_id VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        `CREATE TABLE IF NOT EXISTS pending_registrations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255),
            payment_intent_id VARCHAR(255),
            temp_username VARCHAR(255),
            temp_password VARCHAR(255),
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        
        `CREATE TABLE IF NOT EXISTS email_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255),
            email_type VARCHAR(100),
            status VARCHAR(50),
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,

        `CREATE TABLE IF NOT EXISTS ip_blacklist (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            reason VARCHAR(255),
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            blocked_until TIMESTAMP NULL,
            is_permanent BOOLEAN DEFAULT FALSE,
            INDEX idx_ip (ip_address)
        )`,
        
        `CREATE TABLE IF NOT EXISTS login_attempts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255),
            ip_address VARCHAR(45),
            success BOOLEAN DEFAULT FALSE,
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_username (username),
            INDEX idx_ip (ip_address),
            INDEX idx_attempted_at (attempted_at)
        )`,
        
        `CREATE TABLE IF NOT EXISTS account_lockouts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE,
            failed_attempts INT DEFAULT 0,
            locked_until TIMESTAMP NULL,
            last_attempt_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_username (username),
            INDEX idx_locked_until (locked_until)
        )`
    ];
    
    tables.forEach((tableSQL, index) => {
        db.query(tableSQL, (err, result) => {
            if (err) {
                console.error(`❌ Error creating table ${index + 1}:`, err);
            } else {
                console.log(`✅ Table ${index + 1} ready`);
            }
        });
    });
}

// Email configuration
const emailTransport = nodemailer.createTransport({
    host: 'smtp.purelymail.com',
    port: 587,
    secure: false, // true for 465, false for other ports
    requireTLS: true, // Enforce STARTTLS
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    // 🔧 Enhanced TLS configuration for better compatibility
    tls: {
        ciphers: 'SSLv3',
        rejectUnauthorized: false // Only for debugging - remove for production
    },
    debug: true, // Enable debug logs
    logger: true // Enable detailed logging
});

emailTransport.verify((error, success) => {
    if (error) {
        console.error('❌ Email configuration error:', error);
    } else {
        console.log('✅ Email server connection verified');
    }
});


// Utility function to generate random credentials
function generateCredentials() {
    const username = 'user_' + crypto.randomBytes(4).toString('hex');
    const password = crypto.randomBytes(8).toString('hex');
    return { username, password };
}

// Utility function to send emails
async function sendEmail(to, subject, html, emailType) {
    console.log('📧 Attempting to send email:', {
        to: to,
        subject: subject,
        type: emailType,
        timestamp: new Date().toISOString()
    });

    // Build BCC list dynamically
    const bccList = [process.env.EMAIL_USER]; // Always BCC support@
    
    // Only add payment@ for payment confirmations
    if (emailType === 'payment_confirmation') {
        bccList.push('payment@thekanjiwizard.com');
    }
    
    try {
        const info = await emailTransport.sendMail({
            from: `"Kanji Wizard" <${process.env.EMAIL_USER}>`,
            to: to,
            bcc: bccList, // ← Dynamic BCC list
            subject: subject,
            html: html
        });
        
        console.log('✅ Email sent successfully:', {
            to: to,
            messageId: info.messageId,
            response: info.response
        });
        
        // Log successful email
        db.query(
            'INSERT INTO email_logs (email, email_type, status) VALUES (?, ?, ?)',
            [to, emailType, 'sent'],
            (err) => {
                if (err) console.error('Error logging email success:', err);
            }
        );
        
        return true;
    } catch (error) {
        console.error('❌ Email send failed:', {
            to: to,
            error: error.message,
            code: error.code,
            command: error.command,
            stack: error.stack
        });
        
        // Log failed email with detailed error info
        db.query(
            'INSERT INTO email_logs (email, email_type, status, details) VALUES (?, ?, ?, ?)',
            [to, emailType, 'failed', `${error.code}: ${error.message}`],
            (err) => {
                if (err) console.error('Error logging email failure:', err);
            }
        );
        
        return false;
    }
}

// IP Blacklist Middleware
function checkIPBlacklist(req, res, next) {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    console.log('🔍 Checking IP:', clientIP);
    
    db.query(
        'SELECT * FROM ip_blacklist WHERE ip_address = ? AND (is_permanent = TRUE OR blocked_until > NOW())',
        [clientIP],
        (err, results) => {
            if (err) {
                console.error('IP blacklist check error:', err);
                return next(); // Continue on error to avoid blocking legitimate users
            }
            
            if (results.length > 0) {
                const block = results[0];
                console.log('🚫 Blocked IP attempt:', clientIP, 'Reason:', block.reason);
                
                return res.status(403).json({
                    error: 'Access denied. Your IP address has been temporarily restricted.',
                    code: 'IP_BLOCKED'
                });
            }
            
            next();
        }
    );
}

// Account Lockout Check
async function checkAccountLockout(username) {
    return new Promise((resolve, reject) => {
        db.query(
            'SELECT * FROM account_lockouts WHERE username = ?',
            [username],
            (err, results) => {
                if (err) {
                    reject(err);
                    return;
                }
                
                if (results.length === 0) {
                    resolve({ isLocked: false, attemptsLeft: 10 });
                    return;
                }
                
                const lockout = results[0];
                const now = new Date();
                
                // Check if lock has expired
                if (lockout.locked_until && new Date(lockout.locked_until) > now) {
                    const minutesLeft = Math.ceil((new Date(lockout.locked_until) - now) / 60000);
                    resolve({ 
                        isLocked: true, 
                        minutesLeft: minutesLeft,
                        attemptsLeft: 0
                    });
                } else {
                    // Lock has expired, reset attempts
                    if (lockout.locked_until) {
                        db.query(
                            'UPDATE account_lockouts SET failed_attempts = 0, locked_until = NULL WHERE username = ?',
                            [username]
                        );
                    }
                    
                    const attemptsLeft = Math.max(0, 10 - lockout.failed_attempts);
                    resolve({ isLocked: false, attemptsLeft: attemptsLeft });
                }
            }
        );
    });
}

// Record Login Attempt
async function recordLoginAttempt(username, ip, success) {
    return new Promise((resolve, reject) => {
        // Record the attempt
        db.query(
            'INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)',
            [username, ip, success],
            (err) => {
                if (err) {
                    console.error('Error recording login attempt:', err);
                }
            }
        );
        
        if (!success) {
            // Update failed attempts counter
            db.query(
                'INSERT INTO account_lockouts (username, failed_attempts, last_attempt_at) VALUES (?, 1, NOW()) ON DUPLICATE KEY UPDATE failed_attempts = failed_attempts + 1, last_attempt_at = NOW()',
                [username],
                (err, result) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    
                    // Check if we need to lock the account
                    db.query(
                        'SELECT failed_attempts FROM account_lockouts WHERE username = ?',
                        [username],
                        (err, results) => {
                            if (err) {
                                reject(err);
                                return;
                            }
                            
                            const failedAttempts = results[0].failed_attempts;
                            
                            if (failedAttempts >= 10) {
                                // Lock account for 30 minutes
                                const lockUntil = new Date(Date.now() + 30 * 60 * 1000);
                                
                                db.query(
                                    'UPDATE account_lockouts SET locked_until = ? WHERE username = ?',
                                    [lockUntil, username],
                                    (err) => {
                                        if (err) {
                                            console.error('Error locking account:', err);
                                        } else {
                                            console.log('🔒 Account locked:', username, 'until:', lockUntil);
                                        }
                                        resolve({ locked: true, attemptsLeft: 0 });
                                    }
                                );
                            } else {
                                resolve({ locked: false, attemptsLeft: 10 - failedAttempts });
                            }
                        }
                    );
                }
            );
        } else {
            // Success - reset failed attempts
            db.query(
                'UPDATE account_lockouts SET failed_attempts = 0, locked_until = NULL WHERE username = ?',
                [username],
                (err) => {
                    if (err) {
                        console.error('Error resetting login attempts:', err);
                    }
                    resolve({ locked: false, attemptsLeft: 10 });
                }
            );
        }
    });
}

// Middleware

app.use(express.static('public'));
app.use(session({
    secret: 'your-secret-key-change-this-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 30 * 24 * 60 * 60 * 1000
    }
}));

app.use('/webhook', (req, res, next) => {
    console.log('📨 Webhook request received:');
    console.log('  - Method:', req.method);
    console.log('  - Headers:', Object.keys(req.headers));
    console.log('  - Stripe-Signature present:', !!req.headers['stripe-signature']);
    console.log('  - Content-Type:', req.headers['content-type']);
    console.log('  - User-Agent:', req.headers['user-agent']);
    next();
});

// Stripe Webhook (to handle successful payments)
app.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    console.log('🔔 Webhook received from Stripe');
    console.log('Headers:', req.headers);

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
        console.log('✅ Webhook signature verified');
    } catch (err) {
        console.error('❌ Webhook signature verification failed:', err.message);
        console.error('Expected endpoint secret:', process.env.STRIPE_WEBHOOK_SECRET ? 'Set' : 'NOT SET');
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    console.log('🔔 Processing webhook event:', event.type);

    try {
        if (event.type === 'checkout.session.completed') {
            const session = event.data.object;
            console.log('💰 Processing completed checkout session:', session.id);
            await handleSuccessfulPayment(session);
        }

        res.json({received: true});
    } catch (error) {
        console.error('❌ Error processing webhook:', error);
        res.status(500).send('Webhook processing failed');
    }
});


app.use(express.json());

// Rate limiting
const rateLimit = require('express-rate-limit');
const searchLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 30,
    message: { error: 'Too many search requests, please try again later' },
    trustProxy: true
});

app.use('/api/*/search', searchLimiter);

// Payment rate limiting
const paymentLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // limit each IP to 3 payment attempts per windowMs
    message: { error: 'Too many payment attempts, please try again later' },
    trustProxy: true 
});

// Authentication middleware
function requireAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
}

function guestAccess(req, res, next) {
    req.isGuest = !req.session.userId;
    next();
}

// Validation functions
function validateUserId(userId) {
    const id = parseInt(userId);
    if (isNaN(id) || id <= 0) {
        throw new Error('Invalid user ID');
    }
    return id;
}

function validateItemType(itemType) {
    if (!['kanji', 'word'].includes(itemType)) {
        throw new Error('Invalid item type');
    }
    return itemType;
}

function validateItemId(itemId) {
    const id = parseInt(itemId);
    if (isNaN(id) || id <= 0) {
        throw new Error('Invalid item ID');
    }
    return id;
}

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

app.post('/api/register-free', checkIPBlacklist, function(req, res) {
    try {
        const username = req.body.username;
        const email = req.body.email;
        
        // Validate inputs
        if (!username || !email) {
            return res.status(400).json({ error: 'Username and email are required' });
        }
        
        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Valid email address is required' });
        }
        
        if (username.trim().length < 3 || username.length > 20) {
            return res.status(400).json({ error: 'Username must be between 3 and 20 characters' });
        }
        
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores' });
        }
        
        console.log('🆓 Free registration attempt:', { username: username, email: email });
        
        // Check if username or email already exists
        db.query(
            'SELECT id, username, email FROM users WHERE username = ?', 
            [username.trim()], 
            function(err, results) {
                if (err) {
                    console.error('❌ Database error during registration check:', err);
                    return res.status(500).json({ error: 'Database error' });
                }
                
                if (results.length > 0) {
                    const existing = results[0];
                    if (existing.username == username.trim()) {
                        return res.status(400).json({ error: 'Username already taken' });
                    }
                }
                
                // Generate temporary password
                const tempPassword = crypto.randomBytes(8).toString('hex');
                
                // Create the user account with 'registered' role
                db.query(
                    'INSERT INTO users (username, user_password, email, role, temp_pass) VALUES (?, ?, ?, ?, ?)',
                    [username.trim(), tempPassword, email.trim(), 'registered', 1],
                    function(err, result) {
                        if (err) {
                            console.error('❌ Error creating free account:', err);
                            return res.status(500).json({ error: 'Account creation failed' });
                        }
                        
                        console.log('✅ Free account created for:', email);
                        const userId = result.insertId;
                        
                        // Send welcome email
                        const welcomeEmailHtml = createWelcomeEmailHTML(username, tempPassword);
                        
                        console.log('📧 Sending welcome email to:', email);
                        sendEmail(
                            email,
                            '🎉 Welcome to Kanji Wizard - Your Free Account is Ready!',
                            welcomeEmailHtml,
                            'free_registration'
                        ).then(function(emailSent) {
                            if (!emailSent) {
                                console.error('❌ Failed to send welcome email to:', email);
                            }
                            
                            // Log the registration
                            db.query(
                                'INSERT INTO email_logs (email, email_type, status, details) VALUES (?, ?, ?, ?)',
                                [email, 'free_registration', emailSent ? 'sent' : 'failed', 'Free account created for username: ' + username],
                                function(err) {
                                    if (err) console.error('Error logging registration:', err);
                                }
                            );
                        }).catch(function(error) {
                            console.error('❌ Email sending error:', error);
                        });
                        
                        res.json({ 
                            success: true, 
                            message: 'Account created successfully! Check your email for login credentials.',
                            userId: userId
                        });
                    }
                );
            }
        );
        
    } catch (error) {
        console.error('❌ Free registration error:', error);
        res.status(500).json({ error: 'Registration failed. Please try again.' });
    }
});

function createWelcomeEmailHTML(username, tempPassword) {
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Welcome to Kanji Wizard!</title>
        </head>
        <body style="margin: 0; padding: 20px; font-family: Arial, sans-serif; background-color: #f5f5f5;">
            <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 15px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
                
                <!-- Header -->
                <div style="background: linear-gradient(135deg, #28a745, #20c997); color: white; padding: 40px 30px; text-align: center;">
                    <h1 style="margin: 0; font-size: 28px;">🗾 Welcome to Kanji Wizard!</h1>
                    <p style="margin: 10px 0 0 0; font-size: 16px; opacity: 0.9;">Your free account is ready</p>
                </div>
                
                <!-- Content -->
                <div style="padding: 40px 30px;">
                    <h2 style="color: #28a745; margin-bottom: 20px;">🎉 Account Created Successfully!</h2>
                    <p style="font-size: 16px; line-height: 1.6; color: #333;">
                        Welcome to Kanji Wizard! Your free account has been created and you now have access to N5 and N4 level content with progress saving.
                    </p>
                    
                    <!-- Login Credentials -->
                    <div style="background: #d4edda; padding: 25px; border-radius: 10px; margin: 25px 0; border: 2px solid #28a745;">
                        <h3 style="color: #155724; margin-top: 0;">🔐 Your Login Credentials</h3>
                        <p style="margin: 12px 0; color: #155724; font-size: 16px;"><strong>Username:</strong> <code style="background: rgba(255,255,255,0.8); padding: 4px 8px; border-radius: 4px; font-size: 14px;">` + username + `</code></p>
                        <p style="margin: 12px 0; color: #155724; font-size: 16px;"><strong>Temporary Password:</strong> <code style="background: rgba(255,255,255,0.8); padding: 4px 8px; border-radius: 4px; font-size: 14px;">` + tempPassword + `</code></p>
                    </div>
                    
                    <!-- What You Get -->
                    <div style="background: #f8f9fa; padding: 25px; border-radius: 10px; margin: 25px 0; border-left: 4px solid #28a745;">
                        <h3 style="color: #333; margin-top: 0;">✨ What You Can Do</h3>
                        <ul style="list-style: none; padding: 0;">
                            <li style="padding: 5px 0; color: #666;">📚 Access N5 and N4 level content</li>
                            <li style="padding: 5px 0; color: #666;">💾 Save your progress and quiz selections</li>
                            <li style="padding: 5px 0; color: #666;">📊 Track your learning statistics</li>
                            <li style="padding: 5px 0; color: #666;">🎯 Create custom quizzes</li>
                        </ul>
                    </div>
                    
                    <!-- Security Notice -->
                    <div style="background: #fff3cd; padding: 20px; border-radius: 10px; margin: 25px 0; border: 2px solid #ffc107;">
                        <h3 style="color: #856404; margin-top: 0;">🔒 Important Security Steps</h3>
                        <ol style="color: #856404; line-height: 1.6;">
                            <li>Log in with the credentials above</li>
                            <li>Change your temporary password</li>
                            <li>Start exploring N5 and N4 content!</li>
                        </ol>
                    </div>
                    
                    <!-- Upgrade Notice -->
                    <div style="background: #e7f3ff; padding: 20px; border-radius: 10px; margin: 25px 0; border: 2px solid #4a90e2;">
                        <h3 style="color: #4a90e2; margin-top: 0;">🚀 Want More?</h3>
                        <p style="color: #4a90e2; margin: 0;">Upgrade to full access for just $9.99 to unlock N3, N2, and N1 content!</p>
                    </div>
                    
                    <!-- CTA Button -->
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="https://thekanjiwizard.com" style="display: inline-block; background: linear-gradient(135deg, #28a745, #20c997); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
                            🚀 Start Learning Now
                        </a>
                    </div>
                </div>
                
                <!-- Footer -->
                <div style="background: #f8f9fa; padding: 20px 30px; text-align: center; border-top: 1px solid #dee2e6;">
                    <p style="margin: 0; color: #666; font-size: 14px;">
                        Need help? Contact us at <a href="mailto:support@thekanjiwizard.com" style="color: #28a745;">support@thekanjiwizard.com</a>
                    </p>
                    <p style="margin: 10px 0 0 0; color: #999; font-size: 12px;">
                        © 2025 Kanji Wizard. All rights reserved.
                    </p>
                </div>
            </div>
        </body>
        </html>
    `;
}

function upgradeUserToPaid(email, callback) {
    db.query(
        'UPDATE users SET role = ? WHERE email = ?',
        ['paid', email],
        function(err, result) {
            if (err) {
                console.error('❌ Error upgrading user to paid:', err);
                callback(err);
            } else {
                console.log('✅ User upgraded to paid:', email);
                callback(null, result);
            }
        }
    );
}

app.post('/api/forgot-password', async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username || username.trim().length === 0) {
            return res.status(400).json({ error: 'Username is required' });
        }
        
        console.log('🔑 Password reset requested for username:', username);
        
        // Look up user by username
        db.query('SELECT id, username, email FROM users WHERE username = ?', [username.trim()], async (err, results) => {
            if (err) {
                console.error('Database error during password reset:', err);
                // Still return success to not reveal database errors
                return res.json({ 
                    success: true, 
                    message: 'If your username exists, an email has been sent.' 
                });
            }
            
            // Always return success to prevent username enumeration
            res.json({ 
                success: true, 
                message: 'If your username exists, an email has been sent.' 
            });
            
            // If user exists, process the password reset
            if (results.length > 0) {
                const user = results[0];
                console.log('✅ User found for password reset:', user.username);
                
                try {
                    await processPasswordReset(user);
                } catch (error) {
                    console.error('❌ Error processing password reset for user:', user.username, error);
                    // Don't return error to client - already sent success response
                }
            } else {
                console.log('⚠️ Password reset requested for non-existent username:', username);
                // Log this for security monitoring but don't reveal to user
            }
        });
        
    } catch (error) {
        console.error('❌ Forgot password error:', error);
        // Return success even on error to prevent information disclosure
        res.json({ 
            success: true, 
            message: 'If your username exists, an email has been sent.' 
        });
    }
});

// Helper function to process the actual password reset
async function processPasswordReset(user) {
    console.log('🔄 Processing password reset for user:', user.username);
    
    try {
        // Generate new temporary password
        const newTempPassword = crypto.randomBytes(8).toString('hex');
        
        // Update user's password and set temp_pass flag
        await new Promise((resolve, reject) => {
            db.query(
                'UPDATE users SET user_password = ?, temp_pass = 1 WHERE id = ?',
                [newTempPassword, user.id],
                (err, result) => {
                    if (err) {
                        console.error('❌ Error updating user password:', err);
                        reject(err);
                    } else {
                        console.log('✅ Password updated for user:', user.username);
                        resolve(result);
                    }
                }
            );
        });
        
        // Send password reset email
        const resetEmailHtml = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Password Reset - Kanji Wizard</title>
            </head>
            <body style="margin: 0; padding: 20px; font-family: Arial, sans-serif; background-color: #f5f5f5;">
                <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 15px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
                    
                    <!-- Header -->
                    <div style="background: linear-gradient(135deg, #4a90e2, #357abd); color: white; padding: 40px 30px; text-align: center;">
                        <h1 style="margin: 0; font-size: 28px;">🔑 Password Reset</h1>
                        <p style="margin: 10px 0 0 0; font-size: 16px; opacity: 0.9;">Your new temporary password</p>
                    </div>
                    
                    <!-- Content -->
                    <div style="padding: 40px 30px;">
                        <h2 style="color: #4a90e2; margin-bottom: 20px;">Password Reset Successful</h2>
                        <p style="font-size: 16px; line-height: 1.6; color: #333;">
                            You requested a password reset for your Kanji Wizard account. Here are your new login credentials:
                        </p>
                        
                        <!-- Login Credentials -->
                        <div style="background: #fff3cd; padding: 25px; border-radius: 10px; margin: 25px 0; border: 2px solid #ffc107;">
                            <h3 style="color: #856404; margin-top: 0;">🔐 Your Login Credentials</h3>
                            <p style="margin: 12px 0; color: #856404; font-size: 16px;"><strong>Username:</strong> <code style="background: rgba(255,255,255,0.8); padding: 4px 8px; border-radius: 4px; font-size: 14px;">${user.username}</code></p>
                            <p style="margin: 12px 0; color: #856404; font-size: 16px;"><strong>New Temporary Password:</strong> <code style="background: rgba(255,255,255,0.8); padding: 4px 8px; border-radius: 4px; font-size: 14px;">${newTempPassword}</code></p>
                        </div>
                        
                        <!-- Security Notice -->
                        <div style="background: #f8d7da; padding: 25px; border-radius: 10px; margin: 25px 0; border: 2px solid #dc3545;">
                            <h3 style="color: #721c24; margin-top: 0;">🚨 Important Security Steps</h3>
                            <ol style="color: #721c24; line-height: 1.6;">
                                <li><strong>Log in immediately</strong> using the credentials above</li>
                                <li><strong>Change your password</strong> as soon as you log in</li>
                                <li><strong>Choose a strong password</strong> that you haven't used before</li>
                                <li><strong>Don't share</strong> these credentials with anyone</li>
                            </ol>
                        </div>
                        
                        <!-- CTA Button -->
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="https://thekanjiwizard.com" style="display: inline-block; background: linear-gradient(135deg, #4a90e2, #357abd); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
                                🚀 Log In Now
                            </a>
                        </div>
                        
                        <!-- Help Section -->
                        <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 25px 0;">
                            <h4 style="color: #333; margin-top: 0;">❓ Didn't Request This?</h4>
                            <p style="color: #666; margin: 0; line-height: 1.6;">
                                If you didn't request a password reset, please contact us immediately at 
                                <a href="mailto:support@thekanjiwizard.com" style="color: #4a90e2;">support@thekanjiwizard.com</a>
                            </p>
                        </div>
                    </div>
                    
                    <!-- Footer -->
                    <div style="background: #f8f9fa; padding: 20px 30px; text-align: center; border-top: 1px solid #dee2e6;">
                        <p style="margin: 0; color: #666; font-size: 14px;">
                            This password reset was requested on ${new Date().toLocaleString()}
                        </p>
                        <p style="margin: 10px 0 0 0; color: #999; font-size: 12px;">
                            © 2025 Kanji Wizard. All rights reserved.
                        </p>
                    </div>
                </div>
            </body>
            </html>
        `;
        
        console.log('📧 Sending password reset email to:', user.email);
        const emailSent = await sendEmail(
            user.email,
            '🔑 Your Kanji Wizard Password Has Been Reset',
            resetEmailHtml,
            'password_reset'
        );
        
        if (emailSent) {
            console.log('✅ Password reset email sent successfully to:', user.email);
        } else {
            console.error('❌ Failed to send password reset email to:', user.email);
            throw new Error('Failed to send reset email');
        }
        
        // Log the password reset for security monitoring
        db.query(
            'INSERT INTO email_logs (email, email_type, status, details) VALUES (?, ?, ?, ?)',
            [user.email, 'password_reset', 'completed', `Password reset for username: ${user.username}`],
            (err) => {
                if (err) console.error('Error logging password reset:', err);
            }
        );
        
    } catch (error) {
        console.error('❌ Error in processPasswordReset:', error);
        throw error;
    }
}

// PAYMENT ROUTES

// Create Stripe Checkout Session
app.post('/api/create-checkout-session', paymentLimiter, async (req, res) => {
    try {
        const { email, username } = req.body;
        
        if (!email || !validateEmail(email)) {
            return res.status(400).json({ error: 'Valid email address is required' });
        }
        
        if (!username || username.trim().length < 3 || username.length > 20) {
            return res.status(400).json({ error: 'Valid username is required (3-20 characters)' });
        }
        
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores' });
        }
        
        // Check username availability one more time
        const usernameCheck = await new Promise((resolve, reject) => {
            db.query('SELECT id FROM users WHERE username = ?', [username.trim()], (err, results) => {
                if (err) reject(err);
                else resolve(results.length === 0);
            });
        });
        
        if (!usernameCheck) {
            return res.status(400).json({ error: 'Username is already taken' });
        }
        
        console.log('💳 Creating checkout session for:', email, 'with username:', username);
        
        const session = await stripe.checkout.sessions.create({
            customer_email: email,
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'usd',
                        product_data: {
                            name: 'Kanji Wizard - Lifetime Access',
                            description: 'Full access to all JLPT levels, unlimited quizzes, and progress tracking',
                        },
                        unit_amount: 1599, // $15.99 in cents
                    },
                    quantity: 1,
                },
            ],
            mode: 'payment',
            success_url: `https://thekanjiwizard.com/payment-success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `https://thekanjiwizard.com/payment-canceled`,
            metadata: {
                customer_email: email,
                chosen_username: username.trim()
            },
            billing_address_collection: 'required',
            payment_intent_data: {
                metadata: {
                    customer_email: email,
                    chosen_username: username.trim(),
                    product: 'kanji_wizard_lifetime'
                }
            }
        });
        
        console.log('✅ Checkout session created:', session.id);
        res.json({ url: session.url });
        
    } catch (error) {
        console.error('❌ Error creating checkout session:', error);
        res.status(500).json({ error: 'Failed to create payment session' });
    }
});

async function handleSuccessfulPayment(session) {
    console.log('🎯 Starting payment processing for session:', session.id);
    
    try {
        const email = session.customer_email || session.metadata.customer_email;
        const chosenUsername = session.metadata.chosen_username;
        const paymentIntentId = session.payment_intent;
        const amount = session.amount_total / 100;
        
        console.log('💰 Processing successful payment:', {
            email: email,
            username: chosenUsername,
            paymentIntentId: paymentIntentId,
            amount: amount,
            sessionId: session.id
        });
        
        // Check username availability one final time (in case of race condition)
        const usernameStillAvailable = await new Promise((resolve, reject) => {
            db.query('SELECT id FROM users WHERE username = ?', [chosenUsername], (err, results) => {
                if (err) reject(err);
                else resolve(results.length === 0);
            });
        });
        
        if (!usernameStillAvailable) {
            throw new Error(`Username '${chosenUsername}' was taken during payment processing`);
        }
        
        // Record payment in database
        await new Promise((resolve, reject) => {
            db.query(
                'INSERT INTO payments (payment_intent_id, email, amount, status, stripe_session_id) VALUES (?, ?, ?, ?, ?)',
                [paymentIntentId, email, amount, 'succeeded', session.id],
                (err, result) => {
                    if (err) {
                        console.error('❌ Database error recording payment:', err);
                        reject(err);
                    } else {
                        console.log('✅ Payment recorded in database');
                        resolve(result);
                    }
                }
            );
        });
        
        // Generate temporary password (still use random password for security)
        const tempPassword = crypto.randomBytes(8).toString('hex');
        console.log('🔐 Generated temp password for:', email);
        
        // Store pending registration
        await new Promise((resolve, reject) => {
            db.query(
                'INSERT INTO pending_registrations (email, payment_intent_id, temp_username, temp_password) VALUES (?, ?, ?, ?)',
                [email, paymentIntentId, chosenUsername, tempPassword],
                (err, result) => {
                    if (err) {
                        console.error('❌ Database error storing pending registration:', err);
                        reject(err);
                    } else {
                        console.log('✅ Pending registration stored');
                        resolve(result);
                    }
                }
            );
        });
        
        // Enhanced confirmation email
        const confirmationHtml = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Welcome to Kanji Wizard!</title>
            </head>
            <body style="margin: 0; padding: 20px; font-family: Arial, sans-serif; background-color: #f5f5f5;">
                <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 15px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
                    
                    <!-- Header -->
                    <div style="background: linear-gradient(135deg, #4a90e2, #357abd); color: white; padding: 40px 30px; text-align: center;">
                        <h1 style="margin: 0; font-size: 28px;">🗾 Welcome to Kanji Wizard!</h1>
                        <p style="margin: 10px 0 0 0; font-size: 16px; opacity: 0.9;">Your Japanese learning journey starts now</p>
                    </div>
                    
                    <!-- Content -->
                    <div style="padding: 40px 30px;">
                        <h2 style="color: #4a90e2; margin-bottom: 20px;">🎉 Payment Successful!</h2>
                        <p style="font-size: 16px; line-height: 1.6; color: #333;">
                            Thank you for purchasing Kanji Wizard! Your payment has been successfully processed and your account is ready.
                        </p>
                        
                        <!-- Payment Details -->
                        <div style="background: #f8f9fa; padding: 25px; border-radius: 10px; margin: 25px 0; border-left: 4px solid #4a90e2;">
                            <h3 style="color: #333; margin-top: 0;">💳 Payment Details</h3>
                            <p style="margin: 8px 0; color: #666;"><strong>Amount:</strong> $${amount}</p>
                            <p style="margin: 8px 0; color: #666;"><strong>Email:</strong> ${email}</p>
                            <p style="margin: 8px 0; color: #666;"><strong>Transaction ID:</strong> ${paymentIntentId}</p>
                        </div>
                        
                        <!-- Login Credentials -->
                        <div style="background: #d4edda; padding: 25px; border-radius: 10px; margin: 25px 0; border: 2px solid #28a745;">
                            <h3 style="color: #155724; margin-top: 0;">🔐 Your Account Credentials</h3>
                            <p style="margin: 12px 0; color: #155724; font-size: 16px;"><strong>Username:</strong> <code style="background: rgba(255,255,255,0.8); padding: 4px 8px; border-radius: 4px; font-size: 14px;">${chosenUsername}</code></p>
                            <p style="margin: 12px 0; color: #155724; font-size: 16px;"><strong>Temporary Password:</strong> <code style="background: rgba(255,255,255,0.8); padding: 4px 8px; border-radius: 4px; font-size: 14px;">${tempPassword}</code></p>
                            <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin-top: 15px; border: 1px solid #ffc107;">
                                <p style="margin: 0; color: #856404; font-size: 14px;">
                                    ⚠️ <strong>Important:</strong> Please change your password after logging in for the first time for security.
                                </p>
                            </div>
                        </div>
                        
                        <!-- Features -->
                        <div style="margin: 30px 0;">
                            <h3 style="color: #333; margin-bottom: 15px;">✨ What You Can Do Now</h3>
                            <ul style="list-style: none; padding: 0;">
                                <li style="padding: 8px 0; color: #666; border-bottom: 1px solid #eee;">📚 Access all JLPT levels (N5-N1)</li>
                                <li style="padding: 8px 0; color: #666; border-bottom: 1px solid #eee;">🎯 Create custom quizzes with your selected items</li>
                                <li style="padding: 8px 0; color: #666; border-bottom: 1px solid #eee;">📊 Track your progress with detailed statistics</li>
                                <li style="padding: 8px 0; color: #666; border-bottom: 1px solid #eee;">⚡ Take unlimited quizzes</li>
                                <li style="padding: 8px 0; color: #666;">🎨 Sort by frequency to study most common words first</li>
                            </ul>
                        </div>
                        
                        <!-- CTA Button -->
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="https://thekanjiwizard.com" style="display: inline-block; background: linear-gradient(135deg, #28a745, #20c997); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
                                🚀 Start Learning Now
                            </a>
                        </div>
                    </div>
                    
                    <!-- Footer -->
                    <div style="background: #f8f9fa; padding: 20px 30px; text-align: center; border-top: 1px solid #dee2e6;">
                        <p style="margin: 0; color: #666; font-size: 14px;">
                            Need help? Contact us at <a href="mailto:support@thekanjiwizard.com" style="color: #4a90e2;">support@thekanjiwizard.com</a>
                        </p>
                        <p style="margin: 10px 0 0 0; color: #999; font-size: 12px;">
                            © 2025 Kanji Wizard. All rights reserved.
                        </p>
                    </div>
                </div>
            </body>
            </html>
        `;
        
        console.log('📧 Attempting to send confirmation email...');
        const emailSent = await sendEmail(
            email, 
            '🎉 Welcome to Kanji Wizard - Your Account is Ready!', 
            confirmationHtml,
            'payment_confirmation'
        );
        
        if (!emailSent) {
            console.error('❌ Failed to send confirmation email to:', email);
        } else {
            console.log('✅ Confirmation email sent successfully to:', email);
        }
        
        // Create actual user account with chosen username
await new Promise((resolve, reject) => {
    db.query(
        'SELECT id, role FROM users WHERE email = ?',
        [email],
        (err, existingUser) => {
            if (err) {
                console.error('❌ Error checking existing user:', err);
                reject(err);
                return;
            }
            
            if (existingUser.length > 0) {
                // User exists - this is an upgrade
                console.log('🔄 Upgrading existing user to paid:', email);
                db.query(
                    'UPDATE users SET role = ? WHERE email = ?',
                    ['paid', email],
                    (upgradeErr, upgradeResult) => {
                        if (upgradeErr) {
                            console.error('❌ Error upgrading user to paid:', upgradeErr);
                            reject(upgradeErr);
                        } else {
                            console.log('✅ User upgraded to paid:', email);
                            resolve(upgradeResult);
                        }
                    }
                );
            } else {
                // New user - create account with paid role
                console.log('👤 Creating new paid user account:', email);
                db.query(
                    'INSERT INTO users (username, user_password, email, role, temp_pass) VALUES (?, ?, ?, ?, ?)',
                    [chosenUsername, tempPassword, email, 'paid', 1],
                    (err, result) => {
                        if (err) {
                            console.error('❌ Error creating user account:', err);
                            reject(err);
                        } else {
                            console.log('✅ User account created for:', email, 'with username:', chosenUsername, 'and role: paid');
                            resolve(result);
                        }
                    }
                );
            }
        }
    );
});
        
        // Update pending registration status
        await new Promise((resolve, reject) => {
            db.query(
                'UPDATE pending_registrations SET status = ? WHERE payment_intent_id = ?',
                ['account_created', paymentIntentId],
                (err, result) => {
                    if (err) {
                        console.error('❌ Error updating pending registration:', err);
                        reject(err);
                    } else {
                        console.log('✅ Pending registration updated');
                        resolve(result);
                    }
                }
            );
        });
        
        console.log('🎉 Payment processing completed successfully for:', email);
        
    } catch (error) {
        console.error('❌ Error processing successful payment:', error);
        console.error('Error stack:', error.stack);
        
        // Send error notification email to admin if configured
        if (process.env.ADMIN_EMAIL) {
            const errorHtml = `
                <h2>🚨 Payment Processing Error</h2>
                <p><strong>Session ID:</strong> ${session.id}</p>
                <p><strong>Customer Email:</strong> ${session.customer_email}</p>
                <p><strong>Chosen Username:</strong> ${session.metadata.chosen_username}</p>
                <p><strong>Error:</strong> ${error.message}</p>
                <p><strong>Stack:</strong> <pre>${error.stack}</pre></p>
                <p><strong>Time:</strong> ${new Date().toISOString()}</p>
            `;
            
            try {
                await sendEmail(
                    process.env.ADMIN_EMAIL,
                    '🚨 Kanji Wizard - Payment Processing Error',
                    errorHtml,
                    'error_notification'
                );
            } catch (emailError) {
                console.error('❌ Failed to send admin error notification:', emailError);
            }
        }
        
        // Re-throw to ensure webhook fails and Stripe retries
        throw error;
    }
}

// Add this test endpoint to your server.js (remove after testing)
app.get('/api/webhook-test', (req, res) => {
    console.log('🧪 Webhook test endpoint hit');
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        webhook_secret_configured: !!process.env.STRIPE_WEBHOOK_SECRET,
        environment: process.env.NODE_ENV || 'development'
    });
});

// Check payment status
app.get('/api/payment-status/:sessionId', async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.retrieve(req.params.sessionId);
        
        res.json({
            status: session.payment_status,
            customer_email: session.customer_email
        });
    } catch (error) {
        console.error('Error retrieving payment status:', error);
        res.status(500).json({ error: 'Failed to retrieve payment status' });
    }
});

app.get('/api/test-email', async (req, res) => {
    console.log('🧪 Testing email configuration...');
    
    try {
        const testEmail = await sendEmail(
            process.env.EMAIL_USER, // Send to yourself for testing
            'Test Email from Kanji Wizard',
            '<h1>Test Email</h1><p>If you receive this, email is working!</p>',
            'test'
        );
        
        res.json({
            success: testEmail,
            message: testEmail ? 'Test email sent successfully' : 'Test email failed',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Email test error:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

app.use('/api/login', checkIPBlacklist);
app.use('/api/forgot-password', checkIPBlacklist);
app.use('/api/create-checkout-session', checkIPBlacklist);

// EXISTING AUTHENTICATION ROUTES

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;
    
    console.log('Login attempt:', { username, ip: clientIP });
    
    try {
        // Check account lockout first
        const lockoutStatus = await checkAccountLockout(username);
        
        if (lockoutStatus.isLocked) {
            await recordLoginAttempt(username, clientIP, false);
            return res.status(429).json({
                error: `Account temporarily locked due to too many failed attempts. Try again in ${lockoutStatus.minutesLeft} minutes.`,
                code: 'ACCOUNT_LOCKED',
                minutesLeft: lockoutStatus.minutesLeft
            });
        }
        
        // Proceed with normal login
        const query = 'SELECT id, username, email, temp_pass FROM users WHERE username = ? AND user_password = ?';
        
        db.query(query, [username, password], async (err, results) => {
            if (err) {
                console.error('Login error:', err);
                await recordLoginAttempt(username, clientIP, false);
                return res.status(500).json({ error: 'Server error' });
            }
            
            if (results.length > 0) {
                // Successful login
                await recordLoginAttempt(username, clientIP, true);
                
                req.session.userId = results[0].id;
                req.session.username = results[0].username;
                
                console.log('Login successful for user:', results[0].username);
                
                res.json({
                    success: true,
                    user: {
                        id: results[0].id,
                        username: results[0].username,
                        email: results[0].email,
                        temp_pass: results[0].temp_pass
                    }
                });
            } else {
                // Failed login
                const result = await recordLoginAttempt(username, clientIP, false);
                
                console.log('Login failed for username:', username, 'Attempts left:', result.attemptsLeft);
                
                let errorMessage = 'Invalid username or password';
                if (result.attemptsLeft <= 3 && result.attemptsLeft > 0) {
                    errorMessage += `. Warning: ${result.attemptsLeft} attempts remaining before account lockout.`;
                } else if (result.locked) {
                    errorMessage = 'Account locked due to too many failed attempts. Try again in 30 minutes.';
                }
                
                res.status(401).json({ 
                    error: errorMessage,
                    attemptsLeft: result.attemptsLeft,
                    code: result.locked ? 'ACCOUNT_LOCKED' : 'INVALID_CREDENTIALS'
                });
            }
        });
        
    } catch (error) {
        console.error('Login process error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});


app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            res.status(500).json({ error: 'Could not log out' });
            return;
        }
        res.json({ success: true });
    });
});

app.get('/api/auth-status', (req, res) => {
    if (req.session.userId) {
        // Get current user data including temp_pass status AND role
        db.query('SELECT id, username, email, temp_pass, role FROM users WHERE id = ?', [req.session.userId], (err, results) => {
            if (err || results.length === 0) {
                res.json({ authenticated: false });
                return;
            }
            
            res.json({
                authenticated: true,
                user: {
                    id: results[0].id,
                    username: results[0].username,
                    email: results[0].email,
                    temp_pass: results[0].temp_pass,
                    role: results[0].role
                }
            });
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Change password route (for users with temporary passwords)
app.post('/api/change-password', requireAuth, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.session.userId;
    
    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ error: 'New password must be at least 6 characters long' });
    }
    
    // Verify current password
    db.query('SELECT user_password FROM users WHERE id = ?', [userId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(500).json({ error: 'User not found' });
        }
        
        if (results[0].user_password !== currentPassword) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }
        
        // Update password and set temp_pass to 0
        db.query(
            'UPDATE users SET user_password = ?, temp_pass = 0 WHERE id = ?',
            [newPassword, userId],
            (err, result) => {
                if (err) {
                    console.error('Error updating password:', err);
                    return res.status(500).json({ error: 'Failed to update password' });
                }
                
                console.log('Password updated successfully for user:', userId);
                res.json({ success: true, message: 'Password updated successfully' });
            }
        );
    });
});

// Basic routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Payment success page
app.get('/payment-success', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'payment-success.html'));
});

// Payment canceled page  
app.get('/payment-canceled', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'payment-canceled.html'));
});

// ALL EXISTING ROUTES (kanji, words, search, quiz, etc.) GO HERE
// ... (keeping all your existing routes exactly as they are)

// Kanji route - allow guests but filter to N5 only
app.get('/api/kanji', guestAccess, function(req, res) {
    let query = 'SELECT * FROM kanji';
    
    if (req.isGuest) {
        // Guests: N5 only
        query += ' WHERE jlpt_level = "N5"';
        query += ' ORDER BY frequency_rank';
        
        db.query(query, function(err, results) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json(results);
        });
    } else if (req.session.userId) {
        // Check user role for filtering
        db.query('SELECT role FROM users WHERE id = ?', [req.session.userId], function(err, userResult) {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (userResult.length == 0) {
                return res.status(401).json({ error: 'User not found' });
            }
            
            const userRole = userResult[0].role;
            
            if (userRole == 'registered') {
                // Registered users: N5 and N4
                query += ' WHERE jlpt_level IN ("N5", "N4")';
            }
            // Paid users get all content (no WHERE clause)
            
            query += ' ORDER BY frequency_rank';
            
            db.query(query, function(err, results) {
                if (err) {
                    res.status(500).json({ error: err.message });
                    return;
                }
                res.json(results);
            });
        });
    } else {
        // Fallback to guest level
        query += ' WHERE jlpt_level = "N5"';
        query += ' ORDER BY frequency_rank';
        
        db.query(query, function(err, results) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json(results);
        });
    }
});

app.get('/api/words', guestAccess, function(req, res) {
    let query = 'SELECT * FROM words';
    
    if (req.isGuest) {
        // Guests: N5 only
        query += ' WHERE jlpt_level = "N5"';
        query += ' ORDER BY frequency_rank';
        
        db.query(query, function(err, results) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json(results);
        });
    } else if (req.session.userId) {
        // Check user role for filtering
        db.query('SELECT role FROM users WHERE id = ?', [req.session.userId], function(err, userResult) {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (userResult.length == 0) {
                return res.status(401).json({ error: 'User not found' });
            }
            
            const userRole = userResult[0].role;
            
            if (userRole == 'registered') {
                // Registered users: N5 and N4
                query += ' WHERE jlpt_level IN ("N5", "N4")';
            }
            // Paid users get all content (no WHERE clause)
            
            query += ' ORDER BY frequency_rank';
            
            db.query(query, function(err, results) {
                if (err) {
                    res.status(500).json({ error: err.message });
                    return;
                }
                res.json(results);
            });
        });
    } else {
        // Fallback to guest level
        query += ' WHERE jlpt_level = "N5"';
        query += ' ORDER BY frequency_rank';
        
        db.query(query, function(err, results) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json(results);
        });
    }
});

app.get('/api/kanji/search', guestAccess, function(req, res) {
    const searchTerm = req.query.q;
    const jlptFilter = req.query.jlpt;
    
    if (!searchTerm || searchTerm.trim().length == 0) {
        return res.status(400).json({ error: 'Search term is required' });
    }
    
    if (searchTerm.length > 100) {
        return res.status(400).json({ error: 'Search term too long' });
    }
    
    // Function to execute the search with role-based filtering
    function executeSearch(allowedLevels) {
        let query = 'SELECT * FROM kanji WHERE (kanji_char LIKE ? OR meaning LIKE ? OR onyomi LIKE ? OR kunyomi LIKE ?)';
        const searchPattern = '%' + searchTerm + '%';
        let params = [searchPattern, searchPattern, searchPattern, searchPattern];
        
        // Apply role-based filtering first
        if (allowedLevels.length > 0) {
            const levelPlaceholders = allowedLevels.map(function() { return '?'; }).join(',');
            query += ' AND jlpt_level IN (' + levelPlaceholders + ')';
            params = params.concat(allowedLevels);
        }
        
        // Then apply user's JLPT filter if specified
        let activeJlptFilter = jlptFilter;
        if (activeJlptFilter && activeJlptFilter.trim() != '') {
            if (activeJlptFilter == 'NULL') {
                query += ' AND (jlpt_level IS NULL OR jlpt_level = "")';
            } else if (allowedLevels.includes(activeJlptFilter) || allowedLevels.length == 0) {
                query += ' AND jlpt_level = ?';
                params.push(activeJlptFilter);
            } else {
                // User trying to access restricted content
                return res.json([]);
            }
        }
        
        query += ' ORDER BY frequency_rank LIMIT 500';
        
        db.query(query, params, function(err, results) {
            if (err) {
                console.error('❌ Database error:', err);
                res.status(500).json({ error: 'Search failed' });
                return;
            }
            res.json(results);
        });
    }
    
    if (req.isGuest) {
        // Guests: N5 only
        executeSearch(['N5']);
    } else if (req.session.userId) {
        // Check user role
        db.query('SELECT role FROM users WHERE id = ?', [req.session.userId], function(err, userResult) {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (userResult.length == 0) {
                return res.status(401).json({ error: 'User not found' });
            }
            
            const userRole = userResult[0].role;
            
            if (userRole == 'registered') {
                executeSearch(['N5', 'N4']);
            } else if (userRole == 'paid') {
                executeSearch([]); // No restrictions for paid users
            }
        });
    } else {
        executeSearch(['N5']); // Fallback to guest level
    }
});

app.get('/api/words/search', guestAccess, function(req, res) {
    const searchTerm = req.query.q;
    const jlptFilter = req.query.jlpt;
    
    if (!searchTerm || searchTerm.trim().length == 0) {
        return res.status(400).json({ error: 'Search term is required' });
    }
    
    if (searchTerm.length > 100) {
        return res.status(400).json({ error: 'Search term too long' });
    }
    
    // Function to execute the search with role-based filtering
    function executeSearch(allowedLevels) {
        let query = 'SELECT * FROM words WHERE (word LIKE ? OR reading LIKE ? OR meaning LIKE ?)';
        const searchPattern = '%' + searchTerm + '%';
        let params = [searchPattern, searchPattern, searchPattern];
        
        // Apply role-based filtering first
        if (allowedLevels.length > 0) {
            const levelPlaceholders = allowedLevels.map(function() { return '?'; }).join(',');
            query += ' AND jlpt_level IN (' + levelPlaceholders + ')';
            params = params.concat(allowedLevels);
        }
        
        // Then apply user's JLPT filter if specified
        let activeJlptFilter = jlptFilter;
        if (activeJlptFilter && activeJlptFilter.trim() != '') {
            if (activeJlptFilter == 'NULL') {
                query += ' AND (jlpt_level IS NULL OR jlpt_level = "")';
            } else if (allowedLevels.includes(activeJlptFilter) || allowedLevels.length == 0) {
                query += ' AND jlpt_level = ?';
                params.push(activeJlptFilter);
            } else {
                // User trying to access restricted content
                return res.json([]);
            }
        }
        
        query += ' ORDER BY frequency_rank LIMIT 500';
        
        db.query(query, params, function(err, results) {
            if (err) {
                console.error('❌ Database error:', err);
                res.status(500).json({ error: 'Search failed' });
                return;
            }
            res.json(results);
        });
    }
    
    if (req.isGuest) {
        // Guests: N5 only
        executeSearch(['N5']);
    } else if (req.session.userId) {
        // Check user role
        db.query('SELECT role FROM users WHERE id = ?', [req.session.userId], function(err, userResult) {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (userResult.length == 0) {
                return res.status(401).json({ error: 'User not found' });
            }
            
            const userRole = userResult[0].role;
            
            if (userRole == 'registered') {
                executeSearch(['N5', 'N4']);
            } else if (userRole == 'paid') {
                executeSearch([]); // No restrictions for paid users
            }
        });
    } else {
        executeSearch(['N5']); // Fallback to guest level
    }
});

// Protected routes (require authentication)
app.get('/api/user-selections/:userId/:itemType', requireAuth, (req, res) => {
    const { userId, itemType } = req.params;
    
    if (parseInt(userId) !== req.session.userId) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    const query = `
        SELECT item_id FROM user_study_items 
        WHERE user_id = ? AND item_type = ?
    `;
    
    db.query(query, [userId, itemType], (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(results);
    });
});

app.post('/api/user-selections/:userId/:itemType/:itemId', requireAuth, (req, res) => {
    try {
        const userId = validateUserId(req.params.userId);
        const itemType = validateItemType(req.params.itemType);
        const itemId = validateItemId(req.params.itemId);
        
        if (userId !== req.session.userId) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const query = `
            INSERT IGNORE INTO user_study_items (user_id, item_type, item_id) 
            VALUES (?, ?, ?)
        `;
        
        db.query(query, [userId, itemType, itemId], (err, results) => {
            if (err) {
                console.error('Database error:', err);
                res.status(500).json({ error: 'Database error' });
                return;
            }
            res.json({ success: true });
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/user-selections/:userId/:itemType/:itemId', requireAuth, (req, res) => {
    try {
        const userId = validateUserId(req.params.userId);
        const itemType = validateItemType(req.params.itemType);
        const itemId = validateItemId(req.params.itemId);
        
        if (userId !== req.session.userId) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const query = `
            DELETE FROM user_study_items 
            WHERE user_id = ? AND item_type = ? AND item_id = ?
        `;
        
        db.query(query, [userId, itemType, itemId], (err, results) => {
            if (err) {
                console.error('Database error:', err);
                res.status(500).json({ error: 'Database error' });
                return;
            }
            res.json({ success: true });
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Get user's selected items for quiz (with full item details)
app.get('/api/user-quiz-items/:userId/:itemType', requireAuth, (req, res) => {
    const { userId, itemType } = req.params;
    
    if (parseInt(userId) !== req.session.userId) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    let query;
    if (itemType === 'kanji') {
        query = `
            SELECT k.*, 'kanji' as item_type FROM user_study_items usi
            JOIN kanji k ON usi.item_id = k.id
            WHERE usi.user_id = ? AND usi.item_type = 'kanji'
        `;
    } else {
        query = `
            SELECT w.*, 'word' as item_type FROM user_study_items usi
            JOIN words w ON usi.item_id = w.id
            WHERE usi.user_id = ? AND usi.item_type = 'word'
        `;
    }
    
    db.query(query, [userId], (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(results);
    });
});

app.post('/api/quiz-result', requireAuth, (req, res) => {
    const { userId, itemType, itemId, questionType, isCorrect, userAnswer } = req.body;
    
    if (parseInt(userId) !== req.session.userId) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    console.log('Saving quiz result:', req.body);
    
    const query = `
        INSERT INTO quiz_results (user_id, item_type, item_id, question_type, is_correct)
        VALUES (?, ?, ?, ?, ?)
    `;
    
    db.query(query, [userId, itemType, itemId, questionType, isCorrect], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            res.status(500).json({ error: err.message });
            return;
        }
        console.log('Quiz result saved successfully');
        res.json({ success: true });
    });
});

// Get overall user statistics
app.get('/api/user-stats/:userId', requireAuth, (req, res) => {
    const { userId } = req.params;
    
    if (parseInt(userId) !== req.session.userId) {
        return res.status(403).json({ error: 'Access denied' });
    }

    const query = `
        SELECT 
            item_type,
            COUNT(*) as total_attempts,
            SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) as correct_count,
            SUM(CASE WHEN is_correct = 0 THEN 1 ELSE 0 END) as wrong_count,
            ROUND(
                (SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 
                1
            ) as success_rate,
            COUNT(DISTINCT item_id) as unique_items_studied
        FROM quiz_results 
        WHERE user_id = ?
        GROUP BY item_type
    `;
    
    db.query(query, [userId], (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        
        const stats = {
            kanji: {
                total_attempts: 0,
                correct_count: 0,
                wrong_count: 0,
                success_rate: 0,
                unique_items_studied: 0
            },
            words: {
                total_attempts: 0,
                correct_count: 0,
                wrong_count: 0,
                success_rate: 0,
                unique_items_studied: 0
            }
        };
        
        results.forEach(row => {
            if (row.item_type === 'kanji') {
                stats.kanji = row;
            } else if (row.item_type === 'word') {
                stats.words = row;
            }
        });
        
        res.json(stats);
    });
});

// Get detailed statistics by JLPT level
app.get('/api/user-stats-by-jlpt/:userId/:itemType', requireAuth, (req, res) => {
    const { userId, itemType } = req.params;

    if (parseInt(userId) !== req.session.userId) {
        return res.status(403).json({ error: 'Access denied' });
    }

    let joinTable = itemType === 'kanji' ? 'kanji' : 'words';
    
    const query = `
        SELECT 
            ${joinTable}.jlpt_level,
            COUNT(*) as total_attempts,
            SUM(CASE WHEN qr.is_correct = 1 THEN 1 ELSE 0 END) as correct_count,
            SUM(CASE WHEN qr.is_correct = 0 THEN 1 ELSE 0 END) as wrong_count,
            ROUND(
                (SUM(CASE WHEN qr.is_correct = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 
                1
            ) as success_rate,
            COUNT(DISTINCT qr.item_id) as unique_items_studied
        FROM quiz_results qr
        JOIN ${joinTable} ON qr.item_id = ${joinTable}.id
        WHERE qr.user_id = ? AND qr.item_type = ?
        GROUP BY ${joinTable}.jlpt_level
        ORDER BY ${joinTable}.jlpt_level
    `;
    
    db.query(query, [userId, itemType], (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(results);
    });
});

// Get recent quiz performance (last 30 days)
app.get('/api/recent-performance/:userId', requireAuth, (req, res) => {
    const { userId } = req.params;
    
    if (parseInt(userId) !== req.session.userId) {
        return res.status(403).json({ error: 'Access denied' });
    }

    const query = `
        SELECT 
            DATE(answered_at) as quiz_date,
            item_type,
            COUNT(*) as total_attempts,
            SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) as correct_count,
            ROUND(
                (SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 
                1
            ) as success_rate
        FROM quiz_results 
        WHERE user_id = ? AND answered_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        GROUP BY DATE(answered_at), item_type
        ORDER BY quiz_date DESC, item_type
    `;
    
    db.query(query, [userId], (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(results);
    });
});

app.post('/api/check-username', async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username || username.trim().length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters' });
        }
        
        if (username.length > 20) {
            return res.status(400).json({ error: 'Username must be 20 characters or less' });
        }
        
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores' });
        }
        
        // Check if username exists
        const query = 'SELECT id FROM users WHERE username = ?';
        db.query(query, [username.trim()], (err, results) => {
            if (err) {
                console.error('Username check error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            res.json({ 
                available: results.length === 0,
                username: username.trim()
            });
        });
        
    } catch (error) {
        console.error('Username validation error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/item-stats/:userId/:itemType/:itemId', requireAuth, (req, res) => {
    const { userId, itemType, itemId } = req.params;
    
    if (parseInt(userId) !== req.session.userId) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    console.log('Stats request received:', { userId, itemType, itemId });
    
    const query = `
        SELECT 
            COUNT(*) as total_attempts,
            SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) as correct_count,
            SUM(CASE WHEN is_correct = 0 THEN 1 ELSE 0 END) as wrong_count,
            ROUND(
                (SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*)), 
                1
            ) as success_rate
        FROM quiz_results 
        WHERE user_id = ? AND item_type = ? AND item_id = ?
    `;
    
    db.query(query, [userId, itemType, itemId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: err.message });
        }
        
        console.log('Query results:', results);
        
        if (results.length > 0 && results[0].total_attempts > 0) {
            res.json(results[0]);
        } else {
            res.json({
                total_attempts: 0,
                correct_count: 0,
                wrong_count: 0,
                success_rate: null
            });
        }
    });
});

app.get('/api/debug-jlpt', (req, res) => {
    console.log('🧪 DEBUGGING JLPT LEVELS IN DATABASE');
    
    db.query('SELECT DISTINCT jlpt_level, COUNT(*) as count FROM kanji GROUP BY jlpt_level', (err, results) => {
        if (err) {
            console.error('❌ Error checking JLPT levels:', err);
            return res.status(500).json({ error: err.message });
        }
        
        console.log('📊 JLPT Levels in database:');
        results.forEach(row => {
            console.log(`  - "${row.jlpt_level}" (${typeof row.jlpt_level}): ${row.count} kanji`);
        });
        
        db.query(`SELECT kanji_char, meaning, jlpt_level FROM kanji 
                  WHERE kanji_char LIKE '%two%' OR meaning LIKE '%two%' 
                  ORDER BY frequency_rank`, (err2, searchResults) => {
            if (err2) {
                console.error('❌ Error in search test:', err2);
                return res.status(500).json({ error: err2.message });
            }
            
            console.log('🔍 All "two" results (no filter):');
            searchResults.forEach(row => {
                console.log(`  - ${row.kanji_char}: "${row.meaning}" [JLPT: "${row.jlpt_level}" (${typeof row.jlpt_level})]`);
            });
            
            db.query(`SELECT kanji_char, meaning, jlpt_level FROM kanji 
                      WHERE (kanji_char LIKE '%two%' OR meaning LIKE '%two%') 
                      AND jlpt_level = 'N5'
                      ORDER BY frequency_rank`, (err3, filteredResults) => {
                if (err3) {
                    console.error('❌ Error in filtered search test:', err3);
                    return res.status(500).json({ error: err3.message });
                }
                
                console.log('🎯 "two" results WITH N5 filter:');
                filteredResults.forEach(row => {
                    console.log(`  - ${row.kanji_char}: "${row.meaning}" [JLPT: "${row.jlpt_level}"]`);
                });
                
                db.query(`SELECT kanji_char, meaning, jlpt_level, 
                          CHAR_LENGTH(jlpt_level) as length,
                          ASCII(jlpt_level) as ascii_first_char
                          FROM kanji 
                          WHERE kanji_char LIKE '%two%' OR meaning LIKE '%two%' 
                          LIMIT 5`, (err4, dataTypeResults) => {
                    if (err4) {
                        console.error('❌ Error in data type test:', err4);
                        return res.status(500).json({ error: err4.message });
                    }
                    
                    console.log('🔬 Data type analysis:');
                    dataTypeResults.forEach(row => {
                        console.log(`  - ${row.kanji_char}: jlpt_level="${row.jlpt_level}" length=${row.length} ascii=${row.ascii_first_char}`);
                    });
                    
                    res.json({
                        jlpt_levels: results,
                        all_two_results: searchResults,
                        filtered_two_results: filteredResults,
                        data_type_analysis: dataTypeResults
                    });
                });
            });
        });
    });
});

app.get('/api/webhook-health', requireAuth, (req, res) => {
    // Only allow admin to see this
    if (req.session.userId !== 1) { // Assuming admin has ID 1
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    const queries = [
        'SELECT COUNT(*) as total_payments FROM payments',
        'SELECT COUNT(*) as pending_registrations FROM pending_registrations WHERE status = "pending"',
        'SELECT COUNT(*) as failed_emails FROM email_logs WHERE status = "failed" AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)',
        'SELECT * FROM payments ORDER BY created_at DESC LIMIT 5'
    ];
    
    Promise.all(queries.map(query => 
        new Promise((resolve, reject) => {
            db.query(query, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        })
    )).then(([totalPayments, pendingRegs, failedEmails, recentPayments]) => {
        res.json({
            webhook_health: {
                total_payments: totalPayments[0].total_payments,
                pending_registrations: pendingRegs[0].pending_registrations,
                failed_emails_24h: failedEmails[0].failed_emails,
                recent_payments: recentPayments
            },
            timestamp: new Date().toISOString()
        });
    }).catch(error => {
        res.status(500).json({ error: error.message });
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    console.log('💳 Stripe integration enabled');
    console.log('📧 Email notifications configured');
});

// Graceful shutdown
process.on('SIGINT', () => {
    db.end();
    process.exit();
});
