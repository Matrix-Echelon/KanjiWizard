// server.js
const express = require('express');
const mysql = require('mysql2');
const path = require('path');
const session = require('express-session');

const app = express();
const port = process.env.PORT || 3000;

//Connect to Database
const dbConfig = {
    host: process.env.MYSQLHOST || 'localhost',
    user: process.env.MYSQLUSER || 'root',
    password: process.env.MYSQLPASSWORD || 'ninTENdo12',
    database: process.env.MYSQLDATABASE || 'japanese_learning',
    port: process.env.MYSQLPORT || 3306,
    // Only valid single connection options:
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
    });

    // Handle connection errors and reconnect
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

// Initialize connection
createConnection();

// Middleware
app.use(express.json());
app.use(express.static('public')); // Serve static files from 'public' directory
app.use(session({
    secret: 'your-secret-key-change-this-in-production', // Change this to a random string
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true if using HTTPS
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days for "remember me"
    }
}));

// Authentication middleware
function requireAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
}

// Guest access middleware (only N5 content)
function guestAccess(req, res, next) {
    req.isGuest = !req.session.userId;
    next();
}

// Authentication routes
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    console.log('Login attempt:', { username });
    
    const query = 'SELECT id, username FROM users WHERE username = ? AND user_password = ?';
    
    db.query(query, [username, password], (err, results) => {
        if (err) {
            console.error('Login error:', err);
            res.status(500).json({ error: 'Server error' });
            return;
        }
        
        if (results.length > 0) {
            // Login successful
            req.session.userId = results[0].id;
            req.session.username = results[0].username;
            
            console.log('Login successful for user:', results[0].username);
            
            res.json({
                success: true,
                user: {
                    id: results[0].id,
                    username: results[0].username
                }
            });
        } else {
            // Login failed
            console.log('Login failed for username:', username);
            res.status(401).json({ error: 'Invalid username or password' });
        }
    });
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
        res.json({
            authenticated: true,
            user: {
                id: req.session.userId,
                username: req.session.username
            }
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Basic routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Kanji route - allow guests but filter to N5 only
app.get('/api/kanji', guestAccess, (req, res) => {
    let query = 'SELECT * FROM kanji';
    
    // If guest, only show N5 kanji
    if (req.isGuest) {
        query += ' WHERE jlpt_level = "N5"';
    }
    
    query += ' ORDER BY frequency_rank';
    
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(results);
    });
});

// Words route - allow guests but filter to N5 only
app.get('/api/words', guestAccess, (req, res) => {
    let query = 'SELECT * FROM words';
    
    // If guest, only show N5 words
    if (req.isGuest) {
        query += ' WHERE jlpt_level = "N5"';
    }
    
    query += ' ORDER BY frequency_rank';
    
    db.query(query, (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(results);
    });
});

// Search kanji
app.get('/api/kanji/search', guestAccess, (req, res) => {
    const searchTerm = req.query.q;
    const jlptFilter = req.query.jlpt;
    
    console.log('🔍 KANJI SEARCH DEBUG:');
    console.log('  - Search Term:', searchTerm);
    console.log('  - JLPT Filter:', jlptFilter);
    console.log('  - Is Guest:', req.isGuest);
    
    // Input validation
    if (!searchTerm || searchTerm.trim().length === 0) {
        return res.status(400).json({ error: 'Search term is required' });
    }
    
    if (searchTerm.length > 100) {
        return res.status(400).json({ error: 'Search term too long' });
    }
    
    // COMPLETELY REWRITTEN: Build query step by step
    let query = `SELECT * FROM kanji WHERE (kanji_char LIKE ? OR meaning LIKE ? OR onyomi LIKE ? OR kunyomi LIKE ?)`;
    const searchPattern = `%${searchTerm}%`;
    let params = [searchPattern, searchPattern, searchPattern, searchPattern];
    
    // Determine what JLPT filter to apply
    let activeJlptFilter = jlptFilter;
    
    // For guests, force N5 only
    if (req.isGuest) {
        console.log('  - Guest detected: forcing N5 filter');
        activeJlptFilter = 'N5';
        
        // If guest tried to search non-N5, return empty
        if (jlptFilter && jlptFilter !== 'N5') {
            console.log('  - Guest tried non-N5, returning empty');
            return res.json([]);
        }
    }
    
    // Add JLPT filter if we have one
    if (activeJlptFilter && activeJlptFilter.trim() !== '') {
        console.log('  - Adding JLPT filter:', activeJlptFilter);
        
        if (activeJlptFilter === 'NULL') {
            query += ` AND (jlpt_level IS NULL OR jlpt_level = '')`;
        } else {
            query += ` AND jlpt_level = ?`;
            params.push(activeJlptFilter);
        }
    }
    
    query += ` ORDER BY frequency_rank LIMIT 500`;
    
    console.log('  - Final Query:', query);
    console.log('  - Final Params:', params);
    console.log('  - Params count:', params.length);
    
    // Execute the query
    db.query(query, params, (err, results) => {
        if (err) {
            console.error('❌ Database error:', err);
            res.status(500).json({ error: 'Search failed' });
            return;
        }
        
        console.log(`✅ Query executed successfully`);
        console.log(`  - Returned ${results.length} results`);
        
        // Debug: Show JLPT distribution
        if (results.length > 0) {
            const jlptCounts = {};
            results.forEach(item => {
                const level = item.jlpt_level || 'NULL';
                jlptCounts[level] = (jlptCounts[level] || 0) + 1;
            });
            console.log('  - JLPT distribution:', jlptCounts);
            
            // Show first few results for verification
            console.log('  - First 3 results:');
            results.slice(0, 3).forEach(item => {
                console.log(`    * ${item.kanji_char}: "${item.meaning}" [${item.jlpt_level}]`);
            });
        }
        
        res.json(results);
    });
});


// Search words  
app.get('/api/words/search', guestAccess, (req, res) => {
    const searchTerm = req.query.q;
    const jlptFilter = req.query.jlpt;
    
    console.log('🔍 WORDS SEARCH DEBUG:');
    console.log('  - Search Term:', searchTerm);
    console.log('  - JLPT Filter:', jlptFilter);
    console.log('  - Is Guest:', req.isGuest);
    
    // Input validation
    if (!searchTerm || searchTerm.trim().length === 0) {
        return res.status(400).json({ error: 'Search term is required' });
    }
    
    if (searchTerm.length > 100) {
        return res.status(400).json({ error: 'Search term too long' });
    }
    
    // COMPLETELY REWRITTEN: Build query step by step
    let query = `SELECT * FROM words WHERE (word LIKE ? OR reading LIKE ? OR meaning LIKE ?)`;
    const searchPattern = `%${searchTerm}%`;
    let params = [searchPattern, searchPattern, searchPattern];
    
    // Determine what JLPT filter to apply
    let activeJlptFilter = jlptFilter;
    
    // For guests, force N5 only
    if (req.isGuest) {
        console.log('  - Guest detected: forcing N5 filter');
        activeJlptFilter = 'N5';
        
        // If guest tried to search non-N5, return empty
        if (jlptFilter && jlptFilter !== 'N5') {
            console.log('  - Guest tried non-N5, returning empty');
            return res.json([]);
        }
    }
    
    // Add JLPT filter if we have one
    if (activeJlptFilter && activeJlptFilter.trim() !== '') {
        console.log('  - Adding JLPT filter:', activeJlptFilter);
        
        if (activeJlptFilter === 'NULL') {
            query += ` AND (jlpt_level IS NULL OR jlpt_level = '')`;
        } else {
            query += ` AND jlpt_level = ?`;
            params.push(activeJlptFilter);
        }
    }
    
    query += ` ORDER BY frequency_rank LIMIT 500`;
    
    console.log('  - Final Query:', query);
    console.log('  - Final Params:', params);
    console.log('  - Params count:', params.length);
    
    // Execute the query
    db.query(query, params, (err, results) => {
        if (err) {
            console.error('❌ Database error:', err);
            res.status(500).json({ error: 'Search failed' });
            return;
        }
        
        console.log(`✅ Query executed successfully`);
        console.log(`  - Returned ${results.length} results`);
        
        // Debug: Show JLPT distribution
        if (results.length > 0) {
            const jlptCounts = {};
            results.forEach(item => {
                const level = item.jlpt_level || 'NULL';
                jlptCounts[level] = (jlptCounts[level] || 0) + 1;
            });
            console.log('  - JLPT distribution:', jlptCounts);
        }
        
        res.json(results);
    });
});

app.use(express.json({ limit: '10mb' })); // Limit request size

// Add rate limiting (optional but recommended)
const rateLimit = require('express-rate-limit');

const searchLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 30, // Limit each IP to 30 search requests per minute
    message: { error: 'Too many search requests, please try again later' }
});

app.use('/api/*/search', searchLimiter);

// ✅ GENERAL SECURITY: Validate all user inputs
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

// Protected routes (require authentication)
app.get('/api/user-selections/:userId/:itemType', requireAuth, (req, res) => {
    // Existing code - only accessible to logged-in users
    const { userId, itemType } = req.params;
    
    // Verify user can only access their own data
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

// All quiz-related routes require authentication
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
    
    // Existing code...
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
    
    // Existing code...
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
        
        // Format the results
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

// Add this debug code after your other routes
console.log('=== REGISTERING STATS ENDPOINT ===');

app.get('/api/item-stats/:userId/:itemType/:itemId', requireAuth, (req, res) => {
    const { userId, itemType, itemId } = req.params;
    
    if (parseInt(userId) !== req.session.userId) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    // Existing code...
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
    
    // Test 1: Check what JLPT levels exist in database
    db.query('SELECT DISTINCT jlpt_level, COUNT(*) as count FROM kanji GROUP BY jlpt_level', (err, results) => {
        if (err) {
            console.error('❌ Error checking JLPT levels:', err);
            return res.status(500).json({ error: err.message });
        }
        
        console.log('📊 JLPT Levels in database:');
        results.forEach(row => {
            console.log(`  - "${row.jlpt_level}" (${typeof row.jlpt_level}): ${row.count} kanji`);
        });
        
        // Test 2: Search for "two" without any JLPT filter
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
            
            // Test 3: Search for "two" WITH N5 filter
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
                
                // Test 4: Check for data type issues
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
                    
                    // Return all debug info
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

console.log('=== STATS ENDPOINT REGISTERED ===');

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});


// Graceful shutdown
process.on('SIGINT', () => {
    db.end();
    process.exit();
});