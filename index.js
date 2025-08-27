// lets-pay/server/index.js - COMPLETE FIXED VERSION
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const dbAdapter = require('./database/adapter');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const midtransClient = require('midtrans-client');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT;

const JWT_SECRET = process.env.JWT_SECRET || 'verysecretkeythatshouldbeprotected';

// Enhanced Midtrans configuration
const snap = new midtransClient.Snap({
    isProduction: process.env.MIDTRANS_IS_PRODUCTION === 'true' || false,
    serverKey: process.env.MIDTRANS_SERVER_KEY,
    clientKey: process.env.MIDTRANS_CLIENT_KEY 
});

// =====================================================
// HELPER FUNCTIONS - BOOLEAN SAFE & TABLE LOOKUP FIXED
// =====================================================
// Helper function to safely check availability - handles both boolean and integer values
const isMenuAvailable = (is_available) => {
    // Handle all possible true values
    return is_available === 1 || is_available === true || is_available === '1' || is_available === 'true';
};

// Helper function to safely convert availability to integer for database
const normalizeAvailability = (is_available) => {
    return isMenuAvailable(is_available) ? 1 : 0;
};



// CRITICAL FIX: Safe table lookup function
const safeTableLookup = async (tableNumber) => {
    console.log('🔍 Safe table lookup for:', tableNumber, typeof tableNumber);
    
    const tableStr = String(tableNumber);
    console.log('🔍 Using table string:', tableStr);
    
    try {
        // Handle Take Away special case first
        if (tableStr === 'Take Away' || tableStr.toLowerCase() === 'take away') {
            console.log('🚚 Processing Take Away order');
            const [takeAwayTable] = await dbAdapter.execute(
                'SELECT id_table FROM tables WHERE table_number = ? LIMIT 1', 
                ['Take Away']
            );
            
            if (takeAwayTable.length > 0) {
                return parseInt(takeAwayTable[0].id_table);
            } else {
                console.log('🔧 Creating Take Away table');
                const [createResult] = await dbAdapter.execute(
                    'INSERT INTO tables (table_number, capacity, status) VALUES (?, ?, ?)',
                    ['Take Away', null, 'available']
                );
                return parseInt(createResult.insertId);
            }
        }
        
        // Regular table lookup with STRING comparison
        console.log('🔍 Looking for regular table:', tableStr);
        const [result] = await dbAdapter.execute(
            'SELECT id_table FROM tables WHERE table_number = ?',
            [tableStr]  // Always use string
        );
        
        console.log('🔍 Table lookup result:', result);
        
        if (result.length > 0) {
            const foundTableId = parseInt(result[0].id_table);
            console.log('✅ Found existing table with ID:', foundTableId);
            return foundTableId;
        }
        
        // If table not found and it's a valid number, create it
        if (!isNaN(tableStr) && tableStr.trim() !== '') {
            console.log('📝 Table not found, creating new table:', tableStr);
            const [createResult] = await dbAdapter.execute(
                'INSERT INTO tables (table_number, capacity, status) VALUES (?, ?, ?)',
                [tableStr, 4, 'available']  // Default capacity 4
            );
            const newTableId = parseInt(createResult.insertId);
            console.log('✅ Created new table with ID:', newTableId);
            return newTableId;
        }
        
        console.log('❌ Table not found and cannot create:', tableStr);
        return null;
        
    } catch (error) {
        console.error('❌ Safe table lookup error:', error);
        console.error('Query attempted with parameter:', tableStr, typeof tableStr);
        throw error;
    }
};

// =====================================================
// PAYMENT UTILITIES CLASS
// =====================================================
class PaymentUtils {
    static verifyMidtransSignature(notification, serverKey) {
        const orderId = notification.order_id;
        const statusCode = notification.status_code;
        const grossAmount = notification.gross_amount;
        const signatureKey = notification.signature_key;

        const hash = crypto
            .createHash('sha512')
            .update(orderId + statusCode + grossAmount + serverKey)
            .digest('hex');

        return hash === signatureKey;
    }

    static mapMidtransStatusToPaymentStatus(transactionStatus, fraudStatus = null) {
        switch (transactionStatus) {
            case 'capture':
                if (fraudStatus === 'challenge') {
                    return 'Pending';
                } else if (fraudStatus === 'accept') {
                    return 'Sudah Bayar';
                }
                return 'Sudah Bayar';
            
            case 'settlement':
                return 'Sudah Bayar';
            
            case 'pending':
                return 'Pending';
            
            case 'cancel':
            case 'deny':
            case 'expire':
                return 'Dibatalkan';
            
            case 'failure':
                return 'Gagal';
                
            default:
                return 'Belum Bayar';
        }
    }

    static async logWebhookEvent(dbAdapter, webhookData) {
        const insertQuery = `
            INSERT INTO payment_webhooks 
            (order_id, midtrans_order_id, transaction_status, payment_status, webhook_data, received_at, processed)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
        `;

        const paymentStatus = this.mapMidtransStatusToPaymentStatus(
            webhookData.transaction_status, 
            webhookData.fraud_status
        );

        try {
            const [result] = await dbAdapter.execute(insertQuery, [
                webhookData.order_id,
                webhookData.order_id,
                webhookData.transaction_status,
                paymentStatus,
                JSON.stringify(webhookData),
                0  // Use 0 instead of false
            ]);
            console.log(`Webhook event logged with ID: ${result.insertId || result.webhook_id}`);
            return result.insertId || result.webhook_id;
        } catch (error) {
            console.error('Error logging webhook event:', error);
            throw error;
        }
    }

    static async updateOrderPaymentStatus(dbAdapter, orderId, paymentStatus, transactionStatus, transactionId = null) {
        const updateQuery = `
            UPDATE orders 
            SET payment_status = ?, 
                midtrans_transaction_status = ?,
                midtrans_transaction_id = COALESCE(?, midtrans_transaction_id),
                updated_at = CURRENT_TIMESTAMP
            WHERE midtrans_order_id = ?
        `;

        try {
            const [result] = await dbAdapter.execute(updateQuery, [paymentStatus, transactionStatus, transactionId, orderId]);
            console.log(`Payment status updated for order ${orderId}: ${paymentStatus} (${result.affectedRows} rows affected)`);
            return result.affectedRows;
        } catch (error) {
            console.error('Error updating payment status:', error);
            throw error;
        }
    }
}

// =====================================================
// DATABASE CONNECTION - FIXED
// =====================================================
async function connectToDatabase() {
    try {
        await dbAdapter.connect();
        console.log('✅ Database connected successfully!');
        
        // Auto-create tables if needed
        await dbAdapter.createTablesIfNotExists();
        
    } catch (err) {
        console.error('❌ Database connection failed:', err.message);
        console.error('💡 Check your .env file and database credentials');
        process.exit(1);
    }
}

connectToDatabase();

// =====================================================
// MIDDLEWARE - ENHANCED CORS
// =====================================================
// --- CORS (UNIFIED, SAFE UNTUK CREDENTIALS) ---
const ALLOWED_ORIGINS = new Set([
  'https://let-s-pay-jm5o.vercel.app',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:8080',
]);

// izinkan juga preview domain vercel FE: https://let-s-pay-jm5o-xxx.vercel.app
const isAllowedOrigin = (origin) => {
  if (!origin) return true; // curl/mobile/server-to-server (tanpa Origin)
  if (ALLOWED_ORIGINS.has(origin)) return true;
  return /^https:\/\/let-s-pay-jm5o-[\w-]+\.vercel\.app$/.test(origin);
};

const corsOptions = {
  origin(origin, callback) {
    if (isAllowedOrigin(origin)) return callback(null, true);
    console.log('CORS blocked origin:', origin);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true, // butuh echo ACAO per-origin (tidak boleh '*')
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'Cache-Control',
    'Pragma',
  ],
  optionsSuccessStatus: 204,
};

app.use((req, res, next) => {
  // bantu cache vary Origin biar CDN/proxy tidak reuse salah
  res.setHeader('Vary', 'Origin');
  next();
});

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath);
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname)}`);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Hanya file gambar (jpeg, jpg, png, gif) yang diizinkan!'));
    }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        console.log('❌ No token provided');
        return res.sendStatus(401);
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log('❌ Token verification failed:', err.message);
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

// =====================================================
// HEALTH CHECK - ALWAYS FIRST
// =====================================================
app.get('/api/health', (req, res) => {
    console.log('🏥 Health check requested');
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        database: dbAdapter ? 'Connected' : 'Disconnected',
        port: PORT,
        midtrans: {
            server_key_configured: !!process.env.MIDTRANS_SERVER_KEY,
            client_key_configured: !!process.env.MIDTRANS_CLIENT_KEY,
            is_production: process.env.MIDTRANS_IS_PRODUCTION === 'true'
        }
    });
});

// =====================================================
// DEBUG ENDPOINTS
// =====================================================
app.get('/api/debug/test-simple', async (req, res) => {
    console.log('🧪 Simple test endpoint hit');
    res.json({
        success: true,
        message: 'Debug endpoint is working!',
        timestamp: new Date().toISOString(),
        server_status: 'OK'
    });
});

app.get('/api/debug/schema', async (req, res) => {
    console.log('🔍 DEBUGGING SCHEMA ENDPOINT HIT!');
    
    try {
        // Simple test first
        console.log('Testing database connection...');
        
        // Check if we can query tables at all
        const [simpleTest] = await dbAdapter.execute('SELECT 1 as test');
        console.log('✅ Basic DB connection works:', simpleTest);
        
        // Try to get tables info - handle both MySQL and PostgreSQL
        let tablesSchema = [];
        let tablesData = [];
        
        try {
            // Try PostgreSQL style first
            const [pgSchema] = await dbAdapter.execute(`
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns 
                WHERE table_name = 'tables'
                ORDER BY ordinal_position
            `);
            tablesSchema = pgSchema;
            console.log('✅ PostgreSQL schema query worked');
        } catch (pgError) {
            console.log('PostgreSQL schema failed, trying MySQL style...');
            try {
                // Try MySQL style
                const [mysqlSchema] = await dbAdapter.execute('DESCRIBE tables');
                tablesSchema = mysqlSchema;
                console.log('✅ MySQL schema query worked');
            } catch (mysqlError) {
                console.log('❌ Both schema queries failed:', mysqlError.message);
                tablesSchema = [{ error: 'Could not get schema', pg_error: pgError.message, mysql_error: mysqlError.message }];
            }
        }
        
        // Get actual table data
        try {
            const [data] = await dbAdapter.execute('SELECT * FROM tables LIMIT 5');
            tablesData = data;
            console.log('✅ Tables data retrieved:', data);
        } catch (dataError) {
            console.log('❌ Could not get table data:', dataError.message);
            tablesData = [{ error: 'Could not get table data', message: dataError.message }];
        }
        
        // Test different query types for table lookup
        const testResults = {};
        
        // Test with integer 1
        try {
            const [intResult] = await dbAdapter.execute('SELECT * FROM tables WHERE table_number = ?', [1]);
            testResults.integer_lookup = { success: true, result: intResult, count: intResult.length };
        } catch (intError) {
            testResults.integer_lookup = { success: false, error: intError.message };
        }
        
        // Test with string '1'
        try {
            const [strResult] = await dbAdapter.execute('SELECT * FROM tables WHERE table_number = ?', ['1']);
            testResults.string_lookup = { success: true, result: strResult, count: strResult.length };
        } catch (strError) {
            testResults.string_lookup = { success: false, error: strError.message };
        }
        
        console.log('🧪 Test results:', testResults);
        
        res.json({
            success: true,
            message: 'Debug schema endpoint working!',
            database_connection: 'OK',
            tables_schema: tablesSchema,
            tables_data: tablesData,
            lookup_tests: testResults,
            server_time: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('❌ Debug schema error:', error);
        res.status(500).json({ 
            success: false,
            error: error.message,
            stack: error.stack,
            message: 'Debug endpoint failed'
        });
    }
});

app.post('/api/debug/order', async (req, res) => {
    console.log('🧪 DEBUG ORDER ENDPOINT HIT');
    console.log('Request body received:', JSON.stringify(req.body, null, 2));
    
    const { tableNumber, items } = req.body;
    
    try {
        // Test safe table lookup
        console.log('🧪 Testing safeTableLookup function...');
        const tableId = await safeTableLookup(tableNumber);
        console.log('🧪 safeTableLookup result:', tableId);
        
        // Test menu items lookup
        console.log('🧪 Testing menu items...');
        const menuResults = [];
        
        if (items && items.length > 0) {
            for (let i = 0; i < items.length; i++) {
                const item = items[i];
                console.log(`Testing menu item ${i + 1}:`, item);
                
                try {
                    const [menuResult] = await dbAdapter.execute(
                        'SELECT id_menu, name, price, is_available FROM menu_items WHERE id_menu = ?',
                        [item.id_menu]
                    );
                    console.log(`Menu result ${i + 1}:`, menuResult);
                    menuResults.push(menuResult[0] || null);
                } catch (menuError) {
                    console.log(`Menu lookup error ${i + 1}:`, menuError.message);
                    menuResults.push({ error: menuError.message });
                }
            }
        }
        
        res.json({
            success: true,
            message: 'Debug order test completed',
            results: {
                table_lookup: tableId,
                menu_results: menuResults,
                tableNumber_received: tableNumber,
                tableNumber_type: typeof tableNumber
            }
        });
        
    } catch (error) {
        console.error('Debug order test error:', error);
        res.status(500).json({
            error: error.message,
            stack: error.stack
        });
    }
});

// =====================================================
// AUTH ENDPOINTS - FIXED LOGIN
// =====================================================
app.post('/api/register', async (req, res) => {
    const { username, password, role, name } = req.body;
    if (!username || !password || !role || !name) {
        return res.status(400).json({ message: 'Semua field (username, password, role, name) harus diisi.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await dbAdapter.execute(
            'INSERT INTO users (username, password_hash, role, name) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, role, name]
        );
        res.status(201).json({ message: 'User berhasil didaftarkan!', userId: result.insertId });
    } catch (err) {
        console.error('Error registering user:', err);
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Username sudah digunakan.' });
        }
        res.status(500).json({ message: 'Gagal mendaftarkan user.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    console.log('🔐 LOGIN ATTEMPT:');
    console.log('Username:', username);
    
    if (!username || !password) {
        console.log('❌ Missing username or password');
        return res.status(400).json({ 
            message: 'Username dan password harus diisi.',
            error: 'MISSING_CREDENTIALS'
        });
    }
    
    try {
      console.log('🔍 Looking up user in database...');
const [userRows] = await dbAdapter.execute(
    'SELECT id, username, password_hash, role, name FROM users WHERE username = ?',
    [username]
);
const user = userRows[0];
    
        console.log('User found:', user ? 'YES' : 'NO');
        
        if (!user) {
            console.log('❌ User not found in database');
            return res.status(400).json({ 
                message: 'Username atau password salah.',
                error: 'INVALID_CREDENTIALS'
            });
        }
        
        console.log('🔐 Comparing password...');
        const isMatch = await bcrypt.compare(password, user.password_hash);
        console.log('Password match:', isMatch ? 'YES' : 'NO');
        
        if (!isMatch) {
            console.log('❌ Password mismatch');
            return res.status(400).json({ 
                message: 'Username atau password salah.',
                error: 'INVALID_CREDENTIALS'
            });
        }
        
        console.log('🎫 Creating JWT token...');
        const payload = {
            id: user.id,
            username: user.username,
            role: user.role,
            name: user.name
        };
        
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '24h' });
        console.log('✅ JWT token created successfully');
        
        const responseData = {
            message: 'Login berhasil!',
            token: token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                name: user.name
            }
        };
        
        console.log('✅ LOGIN SUCCESS - Sending response');
        res.status(200).json(responseData);
        
    } catch (err) {
        console.error('❌ LOGIN ERROR:', err);
        res.status(500).json({ 
            message: 'Terjadi kesalahan saat login.',
            error: 'SERVER_ERROR'
        });
    }
});

    app.post('/api/logout', authenticateToken, async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        // TODO: Add token to blacklist if needed
        // await addToBlacklist(token);
        
        console.log('🚪 User logged out successfully');
        res.json({ 
            success: true,
            message: 'Logout berhasil' 
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ 
            success: false,
            message: 'Error during logout' 
        });
    }
});

// =====================================================
// MENU ENDPOINTS - ENHANCED & BOOLEAN-SAFE
// =====================================================
app.get('/api/menu', async (req, res) => {
    try {
        const [rows] = await dbAdapter.execute('SELECT id_menu, name, description, price, category, image_url, is_available FROM menu_items ORDER BY category, name');
        console.log(`✅ Menu items fetched: ${rows.length} items`);
        
        // Debug: Log availability values and normalize them
        const normalizedRows = rows.map((item, index) => {
            console.log(`Menu ${index + 1}: "${item.name}" - is_available: ${item.is_available} (type: ${typeof item.is_available})`);
            
            // Normalize is_available to ensure consistent frontend handling
            const normalizedItem = {
                ...item,
                is_available: isMenuAvailable(item.is_available) ? 1 : 0
            };
            
            console.log(`  -> Normalized to: ${normalizedItem.is_available}`);
            return normalizedItem;
        });
        
        res.json(normalizedRows);
    } catch (err) {
        console.error('Error fetching menu:', err);
        res.status(500).json({ message: 'Gagal mengambil data menu dari database.' });
    }
});

// FIXED: Toggle menu availability - BOOLEAN SAFE
app.patch('/api/menu/:id_menu/availability', authenticateToken, async (req, res) => {
    console.log('🔄 PATCH /api/menu/:id_menu/availability called');
    console.log('Request params:', req.params);
    console.log('Request body:', req.body);
    console.log('User role:', req.user?.role);
    
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Akses ditolak. Hanya admin yang bisa mengubah ketersediaan menu.' });
    }
    
    const { id_menu } = req.params;
    const { is_available } = req.body;
    
    // Validate id_menu
    if (!id_menu || isNaN(parseInt(id_menu))) {
        console.log('❌ Invalid menu ID:', id_menu);
        return res.status(400).json({ message: 'ID menu tidak valid.' });
    }
    
    // Validate is_available
    if (is_available === undefined || is_available === null) {
        console.log('❌ Missing is_available field');
        return res.status(400).json({ message: 'Field is_available wajib diisi.' });
    }
    
    // FIXED: Use safe availability normalization
    const availabilityValue = normalizeAvailability(is_available);
    
    console.log(`📝 Toggle request - ID: ${id_menu}, New availability: ${availabilityValue}`);
    
    try {
        // First check if menu exists
        const [checkMenu] = await dbAdapter.execute(
            'SELECT id_menu, name FROM menu_items WHERE id_menu = ?',
            [parseInt(id_menu)]
        );
        
        if (checkMenu.length === 0) {
            console.log('❌ Menu not found with ID:', id_menu);
            return res.status(404).json({ message: 'Menu tidak ditemukan.' });
        }
        
        // Update availability
        const [result] = await dbAdapter.execute(
            'UPDATE menu_items SET is_available = ? WHERE id_menu = ?',
            [availabilityValue, parseInt(id_menu)]
        );
        
        if (result.affectedRows === 0) {
            console.log('❌ No rows affected during update');
            return res.status(404).json({ message: 'Menu tidak ditemukan atau tidak ada perubahan.' });
        }
        
        // Get updated menu item info for response
        const [menuItem] = await dbAdapter.execute(
            'SELECT name, is_available FROM menu_items WHERE id_menu = ?',
            [parseInt(id_menu)]
        );
        
        const menuName = menuItem[0]?.name || 'Unknown';
        const finalAvailability = menuItem[0]?.is_available;
        const statusText = isMenuAvailable(finalAvailability) ? 'Tersedia' : 'Tidak Tersedia';
        
        console.log(`✅ Menu "${menuName}" availability updated to: ${finalAvailability} (${statusText})`);
        res.json({ 
            success: true,
            message: `Ketersediaan menu "${menuName}" berhasil diubah menjadi ${statusText}!`,
            menu_name: menuName,
            is_available: normalizeAvailability(finalAvailability),
            status_text: statusText
        });
        
    } catch (err) {
        console.error('❌ Error toggling menu availability:', err);
        res.status(500).json({ 
            message: 'Gagal mengubah ketersediaan menu di database.',
            error: err.message 
        });
    }
});

// Rest of menu endpoints with safe availability checks
app.post('/api/menu', authenticateToken, upload.single('image'), async (req, res) => {
    if (req.user.role !== 'admin') {
        if (req.file) { fs.unlinkSync(req.file.path); }
        return res.status(403).json({ message: 'Akses ditolak. Hanya admin yang bisa menambah menu.' });
    }
    
    const { name, description, price, category } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : null;
    
    if (!name || !price || !category) {
        if (req.file) { fs.unlinkSync(req.file.path); }
        return res.status(400).json({ message: 'Nama, harga, dan kategori menu harus diisi.' });
    }
    
    if (isNaN(parseFloat(price))) {
        if (req.file) { fs.unlinkSync(req.file.path); }
        return res.status(400).json({ message: 'Harga harus berupa angka yang valid.' });
    }
    
    try {
        const [result] = await dbAdapter.execute(
            'INSERT INTO menu_items (name, description, price, category, image_url, is_available) VALUES (?, ?, ?, ?, ?, ?)',
            [name, description || null, parseFloat(price), category, image_url, 1]
        );
        
        const newMenuItem = {
            id_menu: result.insertId,
            name,
            description: description || '',
            price: parseFloat(price),
            category,
            image_url: image_url || 'https://placehold.co/150x150/CCCCCC/000000?text=No+Image',
            is_available: 1
        };
        
        console.log('Menu baru berhasil ditambahkan:', newMenuItem);
        res.status(201).json({ message: 'Menu berhasil ditambahkan!', menu: newMenuItem });
        
    } catch (err) {
        console.error('Error adding menu:', err);
        if (req.file) { fs.unlinkSync(req.file.path); }
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Menu dengan nama ini sudah ada.' });
        }
        res.status(500).json({ message: 'Gagal menambahkan menu ke database.' });
    }
});

app.put('/api/menu/:id_menu', authenticateToken, upload.single('image'), async (req, res) => {
    if (req.user.role !== 'admin') {
        if (req.file) { fs.unlinkSync(req.file.path); }
        return res.status(403).json({ message: 'Akses ditolak. Hanya admin yang bisa mengupdate menu.' });
    }
    
    const { id_menu } = req.params;
    const { name, description, price, category, is_available } = req.body;
    let image_url = req.body.image_url_existing;
    
    if (req.file) {
        image_url = `/uploads/${req.file.filename}`;
    } else if (req.body.clear_image === 'true') {
        image_url = null;
    }
    
    if (!name || !price || !category || is_available === undefined) {
        if (req.file) { fs.unlinkSync(req.file.path); }
        return res.status(400).json({ message: 'Nama, harga, kategori, dan ketersediaan menu tidak boleh kosong untuk update.' });
    }
    
    if (isNaN(parseFloat(price))) {
        if (req.file) { fs.unlinkSync(req.file.path); }
        return res.status(400).json({ message: 'Harga harus berupa angka yang valid.' });
    }
    
    try {
        // Get old image for cleanup
        let oldImageUrl = null;
        const [rows] = await dbAdapter.execute('SELECT image_url FROM menu_items WHERE id_menu = ?', [id_menu]);
        if (rows[0] && rows[0].image_url && rows[0].image_url.startsWith('/uploads/')) {
            oldImageUrl = path.join(__dirname, rows[0].image_url);
        }
        
        // FIXED: Use safe availability normalization
        const normalizedAvailability = normalizeAvailability(is_available);
        
        const [result] = await dbAdapter.execute(
            'UPDATE menu_items SET name = ?, description = ?, price = ?, category = ?, image_url = ?, is_available = ? WHERE id_menu = ?',
            [name, description || null, parseFloat(price), category, image_url, normalizedAvailability, id_menu]
        );
        
        if (result.affectedRows === 0) {
            if (req.file) { fs.unlinkSync(req.file.path); }
            return res.status(404).json({ message: 'Menu tidak ditemukan.' });
        }
        
        // Clean up old image
        if (oldImageUrl && fs.existsSync(oldImageUrl) && oldImageUrl !== path.join(__dirname, image_url || '')) {
            fs.unlinkSync(oldImageUrl);
            console.log('Old image deleted:', oldImageUrl);
        }
        
        console.log(`Menu dengan ID ${id_menu} berhasil diupdate.`);
        res.json({ message: 'Menu berhasil diupdate!' });
        
    } catch (err) {
        console.error('Error updating menu:', err);
        if (req.file) { fs.unlinkSync(req.file.path); }
        res.status(500).json({ message: 'Gagal mengupdate menu di database.' });
    }
});

app.delete('/api/menu/:id_menu', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Akses ditolak. Hanya admin yang bisa menghapus menu.' });
    }
    
    const { id_menu } = req.params;
    
    try {
        // Get image for cleanup
        let imageUrlToDelete = null;
        const [rows] = await dbAdapter.execute('SELECT image_url FROM menu_items WHERE id_menu = ?', [id_menu]);
        if (rows[0] && rows[0].image_url && rows[0].image_url.startsWith('/uploads/')) {
            imageUrlToDelete = path.join(__dirname, rows[0].image_url);
        }
        
        const [result] = await dbAdapter.execute('DELETE FROM menu_items WHERE id_menu = ?', [id_menu]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Menu tidak ditemukan.' });
        }
        
        // Clean up image file
        if (imageUrlToDelete && fs.existsSync(imageUrlToDelete)) {
            fs.unlinkSync(imageUrlToDelete);
            console.log('Image file deleted:', imageUrlToDelete);
        }
        
        console.log(`Menu dengan ID ${id_menu} berhasil dihapus.`);
        res.json({ message: 'Menu berhasil dihapus!' });
        
    } catch (err) {
        console.error('Error deleting menu:', err);
        if (err.code === 'ER_ROW_IS_REFERENCED_2') {
            return res.status(409).json({ message: 'Menu ini tidak bisa dihapus karena masih terdaftar dalam pesanan.' });
        }
        res.status(500).json({ message: 'Gagal menghapus menu dari database.' });
    }
});

// =====================================================
// TABLE ENDPOINTS - FIXED
// =====================================================
app.post('/api/tables', authenticateToken, async (req, res) => {
    console.log('🪑 POST /api/tables called');
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Akses ditolak. Hanya admin yang bisa menambah meja.' });
    }
    
    const { table_number, capacity } = req.body;
    if (!table_number) {
        return res.status(400).json({ message: 'Nomor meja harus diisi.' });
    }
    
    try {
        const [result] = await dbAdapter.execute(
            'INSERT INTO tables (table_number, capacity) VALUES (?, ?)',
            [table_number, capacity || null]
        );
        
        console.log(`✅ Table added: ${table_number}`);
        res.status(201).json({ message: 'Meja berhasil ditambahkan!', tableId: result.insertId });
        
    } catch (err) {
        console.error('Error adding table:', err);
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Nomor meja sudah ada.' });
        }
        res.status(500).json({ message: 'Gagal menambahkan meja.' });
    }
});

app.get('/api/tables', authenticateToken, async (req, res) => {
    console.log('🪑 GET /api/tables called');
    if (req.user.role !== 'admin' && req.user.role !== 'cashier') {
        return res.status(403).json({ message: 'Akses ditolak. Hanya admin atau kasir yang bisa melihat meja.' });
    }
    
    try {
        const [rows] = await dbAdapter.execute('SELECT * FROM tables ORDER BY table_number ASC');
        console.log(`✅ Tables fetched: ${rows.length} tables`);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching tables:', err);
        res.status(500).json({ message: 'Gagal mengambil data meja.' });
    }
});

// =====================================================
// ORDER ENDPOINTS - COMPLETELY FIXED VERSION
// =====================================================
// ========================= REVISED ROUTES =========================

// GET /api/orders — FIX: konsisten execute + placeholder per DB
app.get('/api/orders', authenticateToken, async (req, res) => {
  console.log('📋 GET /api/orders called');

  if (req.user.role !== 'admin' && req.user.role !== 'cashier') {
    return res.status(403).json({ message: 'Akses ditolak. Hanya admin atau kasir yang bisa melihat pesanan.' });
  }

  // REVISION: deteksi jenis DB untuk placeholder
  const isPostgreSQL =
    process.env.DB_TYPE === 'postgres' || process.env.DB_TYPE === 'postgresql' ||
    (process.env.DATABASE_URL && process.env.DATABASE_URL.includes('postgres'));

  try {
    // Get all orders with table info
    const [orders] = await dbAdapter.execute(`
      SELECT 
        o.id_orders as order_id,
        o.table_id,
        t.table_number,
        o.customer_name,  
        o.total_amount,
        o.status as order_status,
        o.payment_status,
        o.payment_method,
        o.midtrans_order_id,
        o.midtrans_transaction_id,
        o.midtrans_transaction_status,
        o.order_time,
        o.updated_at
      FROM orders o
      LEFT JOIN tables t ON o.table_id = t.id_table
      ORDER BY o.order_time DESC
    `);

    // Get order items for each order (2 tahap, tapi konsisten)
    const itemSqlPG = `
      SELECT 
        oi.menu_item_id,
        mi.name as menu_name,
        oi.quantity,
        oi.price_at_order,
        oi.spiciness_level,
        oi.temperature_level
      FROM order_items oi
      JOIN menu_items mi ON oi.menu_item_id = mi.id_menu
      WHERE oi.order_id = $1
    `;
    const itemSqlMy = `
      SELECT 
        oi.menu_item_id,
        mi.name as menu_name,
        oi.quantity,
        oi.price_at_order,
        oi.spiciness_level,
        oi.temperature_level
      FROM order_items oi
      JOIN menu_items mi ON oi.menu_item_id = mi.id_menu
      WHERE oi.order_id = ?
    `;

    for (let order of orders) {
      try {
        const sql = isPostgreSQL ? itemSqlPG : itemSqlMy;
        const [rows] = await dbAdapter.execute(sql, [order.order_id]); // REVISION: hindari .pool.query
        // FE kamu sebelumnya expect string => tetap stringify
        order.items = JSON.stringify(rows ?? []);
        console.log(`Order ${order.order_id} items:`, rows);
      } catch (error) {
        console.error(`Error fetching items for order ${order.order_id}:`, error);
        order.items = JSON.stringify([]);
      }
    }

    console.log(`✅ Orders fetched: ${orders.length} orders`);
    res.json(orders);

  } catch (error) {
    console.error('❌ Error fetching orders:', error);
    res.status(500).json({ message: 'Gagal mengambil data pesanan.' });
  }
});

// POST /api/orders — (tetap) hanya perapihan kecil komentar; logic sudah OK
app.post('/api/orders', async (req, res) => {
  console.log('🎯 POST /api/orders called - FIXED VERSION (PostgreSQL Compatible)');
  console.log('Request body received:', JSON.stringify(req.body, null, 2));

  const { 
    tableNumber, 
    items, 
    customerName, 
    payment_status, 
    payment_method, 
    midtrans_order_id, 
    midtrans_transaction_id 
  } = req.body;

  if (!tableNumber || !items || !Array.isArray(items) || items.length === 0) {
    console.log('❌ Missing required fields or invalid items');
    return res.status(400).json({ message: 'Nomor meja dan item pesanan tidak boleh kosong.' });
  }

  console.log('🔍 Validating request data...');
  console.log('Table Number:', tableNumber, typeof tableNumber);
  console.log('Items count:', items.length);

  try {
    console.log('🔍 Using safeTableLookup for table:', tableNumber);
    const tableId = await safeTableLookup(tableNumber);

    if (!tableId) {
      console.log('❌ Table lookup failed for:', tableNumber);
      return res.status(404).json({ message: `Meja ${tableNumber} tidak ditemukan dan tidak dapat dibuat.` });
    }

    console.log('✅ Table ID determined safely:', tableId);

    let totalAmount = 0;
    const orderItemsForDb = [];

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      console.log(`🔍 Processing item ${i + 1}:`, item);

      if (!item || !item.id_menu) {
        console.log(`❌ Invalid item at index ${i}:`, item);
        return res.status(400).json({ message: `Item pesanan ke-${i + 1} tidak valid.` });
      }

      const menuId = parseInt(item.id_menu);
      const quantity = parseInt(item.quantity) || 0;

      if (isNaN(menuId) || quantity <= 0) {
        console.log(`❌ Invalid menu ID or quantity for item ${i}:`, { menuId, quantity });
        return res.status(400).json({ message: `Menu ID atau kuantitas tidak valid untuk item ke-${i + 1}.` });
      }

      const [menuRows] = await dbAdapter.execute(
        'SELECT id_menu, name, price, is_available FROM menu_items WHERE id_menu = ?', 
        [menuId]
      );
      const menuItem = menuRows[0];

      if (!menuItem) {
        console.log(`❌ Menu item not found:`, menuId);
        return res.status(400).json({ message: `Item menu dengan ID ${menuId} tidak ditemukan.` });
      }

      if (!isMenuAvailable(menuItem.is_available)) {
        console.log(`❌ Menu item not available:`, menuItem);
        return res.status(400).json({ message: `Item menu ${menuItem.name} tidak tersedia.` });
      }

      const itemPrice = parseFloat(menuItem.price) || 0;
      const itemTotal = itemPrice * quantity;

      if (isNaN(itemTotal) || itemTotal < 0) {
        console.log(`❌ Invalid item total:`, { itemPrice, quantity, itemTotal });
        return res.status(400).json({ message: `Harga tidak valid untuk item ${menuItem.name}.` });
      }

      totalAmount += itemTotal;

      orderItemsForDb.push({
        menu_item_id: menuId,
        quantity: quantity,
        price_at_order: itemPrice,
        spiciness_level: item.spiciness_level || null,
        temperature_level: item.temperature_level || null
      });

      console.log(`✅ Processed item: ${menuItem.name} x${quantity} @ ${itemPrice} = ${itemTotal}`);
    }

    totalAmount = Math.round(totalAmount * 100) / 100;
    if (isNaN(totalAmount) || totalAmount <= 0) {
      console.log(`❌ Invalid total amount:`, totalAmount);
      return res.status(400).json({ message: 'Total amount pesanan tidak valid.' });
    }

    console.log('💰 Total amount calculated:', totalAmount);

    const orderData = {
      table_id: parseInt(tableId),
      customer_name: customerName ? String(customerName).trim() : null,
      total_amount: parseFloat(totalAmount),
      status: String('Dalam Proses'),
      payment_status: payment_status ? String(payment_status) : String('Belum Bayar'),
      payment_method: payment_method ? String(payment_method) : String('cash'),
      midtrans_order_id: midtrans_order_id ? String(midtrans_order_id) : null,
      midtrans_transaction_id: midtrans_transaction_id ? String(midtrans_transaction_id) : null
    };

    console.log('📝 Final order data:', orderData);

    const insertParams = [
      orderData.table_id,
      orderData.customer_name,
      orderData.total_amount,
      orderData.status,
      orderData.payment_status,
      orderData.payment_method,
      orderData.midtrans_order_id,
      orderData.midtrans_transaction_id
    ];

    console.log('🔍 Insert parameters:', insertParams);

    let orderId;
    const isPostgreSQL =
      process.env.DB_TYPE === 'postgres' || process.env.DB_TYPE === 'postgresql' || 
      (process.env.DATABASE_URL && process.env.DATABASE_URL.includes('postgres'));

    if (isPostgreSQL) {
      console.log('🐘 Using PostgreSQL INSERT with RETURNING clause');
      const [orderResult] = await dbAdapter.execute(
        `INSERT INTO orders 
         (table_id, customer_name, total_amount, status, payment_status, payment_method, midtrans_order_id, midtrans_transaction_id) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
         RETURNING id_orders`,
        insertParams
      );

      console.log('🔍 PostgreSQL INSERT result:', orderResult);
      if (orderResult && orderResult.length > 0 && orderResult[0].id_orders) {
        orderId = orderResult[0].id_orders;
        console.log('✅ Order ID from PostgreSQL RETURNING:', orderId);
      } else {
        console.error('❌ PostgreSQL INSERT failed - no RETURNING result');
        throw new Error('Failed to get order ID from PostgreSQL insert result');
      }

    } else {
      console.log('🐬 Using MySQL INSERT');
      const [orderResult] = await dbAdapter.execute(
        `INSERT INTO orders 
         (table_id, customer_name, total_amount, status, payment_status, payment_method, midtrans_order_id, midtrans_transaction_id) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        insertParams
      );

      console.log('🔍 MySQL INSERT result:', orderResult);
      orderId = orderResult.insertId;
      if (!orderId) {
        console.error('❌ MySQL INSERT failed - no insertId');
        throw new Error('Failed to get order ID from MySQL insert result');
      }
      console.log('✅ Order ID from MySQL insertId:', orderId);
    }

    console.log('✅ Order created with ID:', orderId);

    // Insert order items
    for (const item of orderItemsForDb) {
      console.log('📝 Inserting order item:', item);

      const itemParams = [
        parseInt(orderId),
        parseInt(item.menu_item_id),
        parseInt(item.quantity),
        parseFloat(item.price_at_order),
        item.spiciness_level ? String(item.spiciness_level) : null,
        item.temperature_level ? String(item.temperature_level) : null
      ];

      if (isPostgreSQL) {
        await dbAdapter.execute(
          'INSERT INTO order_items (order_id, menu_item_id, quantity, price_at_order, spiciness_level, temperature_level) VALUES ($1, $2, $3, $4, $5, $6)',
          itemParams
        );
      } else {
        await dbAdapter.execute(
          'INSERT INTO order_items (order_id, menu_item_id, quantity, price_at_order, spiciness_level, temperature_level) VALUES (?, ?, ?, ?, ?, ?)',
          itemParams
        );
      }

      console.log(`✅ Order item inserted: menu_id=${item.menu_item_id}, quantity=${item.quantity}`);
    }

    console.log('🎉 Order completed successfully!');
    res.status(201).json({ 
      success: true,
      message: 'Pesanan berhasil diterima dan sedang diproses!', 
      orderId: orderId,
      totalAmount: totalAmount,
      payment_status: orderData.payment_status,
      itemCount: orderItemsForDb.length
    });

  } catch (err) {
    console.error('❌ DETAILED ORDER CREATION ERROR:');
    console.error('- Error message:', err.message);
    console.error('- Error stack:', err.stack);
    console.error('- Request body received:', req.body);

    res.status(500).json({ 
      message: 'Terjadi kesalahan saat memproses pesanan.',
      error: err.message 
    });
  }
});

// PUT /api/orders/:id/status — FIX: placeholder & hasil update
app.put('/api/orders/:id/status', authenticateToken, async (req, res) => {
  console.log('📋 PUT /api/orders/:id/status called');

  if (req.user.role !== 'admin' && req.user.role !== 'cashier') {
    return res.status(403).json({ message: 'Akses ditolak. Hanya admin atau kasir yang bisa mengupdate status pesanan.' });
  }

  const { id } = req.params;
  const { status } = req.body;
  const validStatuses = ['Dalam Proses', 'Selesai', 'Dibatalkan'];

  if (!status || !validStatuses.includes(status)) {
    return res.status(400).json({ message: 'Status tidak valid.' });
  }

  const isPostgreSQL =
    process.env.DB_TYPE === 'postgres' || process.env.DB_TYPE === 'postgresql' ||
    (process.env.DATABASE_URL && process.env.DATABASE_URL.includes('postgres'));

  try {
    const sql = isPostgreSQL
      ? 'UPDATE orders SET status = $1, updated_at = NOW() WHERE id_orders = $2'
      : 'UPDATE orders SET status = ?, updated_at = NOW() WHERE id_orders = ?';

    const [result] = await dbAdapter.execute(sql, [status, id]);

    const changed = (result?.affectedRows ?? result?.rowCount ?? 0);
    if (changed === 0) {
      return res.status(404).json({ message: 'Pesanan tidak ditemukan.' });
    }

    console.log(`Status pesanan ${id} diupdate menjadi: ${status}`);
    res.json({ message: `Status pesanan berhasil diupdate menjadi ${status}!` });

  } catch (err) {
    console.error('Error updating order status:', err);
    res.status(500).json({ message: 'Gagal mengupdate status pesanan.' });
  }
});

// PUT /api/orders/:id/payment_status — FIX: placeholder & hasil update
app.put('/api/orders/:id/payment_status', async (req, res) => {
  console.log('💰 PUT /api/orders/:id/payment_status called');

  const { id } = req.params;
  const { payment_status, payment_method } = req.body;
  const validPaymentStatuses = ['Belum Bayar', 'Sudah Bayar', 'Pending', 'Dikembalikan', 'Dibatalkan', 'Gagal'];

  if (!payment_status || !validPaymentStatuses.includes(payment_status)) {
    return res.status(400).json({ message: 'Status pembayaran tidak valid.' });
  }

  const isPostgreSQL =
    process.env.DB_TYPE === 'postgres' || process.env.DB_TYPE === 'postgresql' ||
    (process.env.DATABASE_URL && process.env.DATABASE_URL.includes('postgres'));

  try {
    const sql = isPostgreSQL
      ? 'UPDATE orders SET payment_status = $1, payment_method = $2, updated_at = NOW() WHERE id_orders = $3'
      : 'UPDATE orders SET payment_status = ?, payment_method = ?, updated_at = NOW() WHERE id_orders = ?';

    const [result] = await dbAdapter.execute(sql, [payment_status, payment_method || null, id]);

    const changed = (result?.affectedRows ?? result?.rowCount ?? 0);
    if (changed === 0) {
      return res.status(404).json({ message: 'Pesanan tidak ditemukan.' });
    }

    console.log(`💰 Status pembayaran pesanan ${id} diupdate menjadi: ${payment_status}`);
    res.json({ message: `Status pembayaran pesanan berhasil diupdate menjadi ${payment_status}!` });

  } catch (err) {
    console.error('Error updating payment status:', err);
    res.status(500).json({ message: 'Gagal mengupdate status pembayaran.' });
  }
});

// PUT /api/orders/:id — FIX: placeholder sesuai DB di DELETE/SELECT/INSERT/UPDATE
app.put('/api/orders/:id', authenticateToken, async (req, res) => {
  console.log('✏️ PUT /api/orders/:id (edit order) called');

  if (req.user.role !== 'admin' && req.user.role !== 'cashier') {
    return res.status(403).json({ message: 'Akses ditolak. Hanya admin atau kasir yang bisa mengedit pesanan.' });
  }

  const { id } = req.params;
  const { items } = req.body;

  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ message: 'Pesanan harus memiliki minimal 1 item' });
  }

  const validItems = items.filter(item => item.id_menu && item.quantity && item.quantity > 0);
  if (validItems.length === 0) {
    return res.status(400).json({ message: 'Tidak ada item valid dalam pesanan' });
  }

  const isPostgreSQL =
    process.env.DB_TYPE === 'postgres' || process.env.DB_TYPE === 'postgresql' ||
    (process.env.DATABASE_URL && process.env.DATABASE_URL.includes('postgres'));

  // SQL template per DB
  const delSql = isPostgreSQL
    ? 'DELETE FROM order_items WHERE order_id = $1'
    : 'DELETE FROM order_items WHERE order_id = ?';

  const selMenuSql = isPostgreSQL
    ? 'SELECT id_menu, name, price, is_available FROM menu_items WHERE id_menu = $1'
    : 'SELECT id_menu, name, price, is_available FROM menu_items WHERE id_menu = ?';

  const updOrderSql = isPostgreSQL
    ? 'UPDATE orders SET total_amount = $1, updated_at = NOW() WHERE id_orders = $2'
    : 'UPDATE orders SET total_amount = ?, updated_at = NOW() WHERE id_orders = ?';

  const insItemSql = isPostgreSQL
    ? 'INSERT INTO order_items (order_id, menu_item_id, quantity, price_at_order, spiciness_level, temperature_level) VALUES ($1, $2, $3, $4, $5, $6)'
    : 'INSERT INTO order_items (order_id, menu_item_id, quantity, price_at_order, spiciness_level, temperature_level) VALUES (?, ?, ?, ?, ?, ?)';

  try {
    // Delete existing order items
    await dbAdapter.execute(delSql, [id]);

    // Process new items and calculate total
    let totalAmount = 0;
    const orderItemsForDb = [];

    for (const item of items) {
      const [menuRows] = await dbAdapter.execute(selMenuSql, [item.id_menu]);
      const menuItem = menuRows[0];

      if (!menuItem || !isMenuAvailable(menuItem.is_available)) {
        return res.status(400).json({ 
          message: `Item menu dengan ID ${item.id_menu} tidak ditemukan atau tidak tersedia.` 
        });
      }

      if (item.quantity <= 0) {
        return res.status(400).json({ 
          message: `Kuantitas untuk item ${menuItem.name} harus lebih dari 0.` 
        });
      }

      totalAmount += Number(menuItem.price) * Number(item.quantity);
      orderItemsForDb.push({
        menu_item_id: menuItem.id_menu,
        quantity: item.quantity,
        price_at_order: menuItem.price,
        spiciness_level: item.spiciness_level || null,
        temperature_level: item.temperature_level || null
      });
    }

    // Update order total amount
    const [updateResult] = await dbAdapter.execute(updOrderSql, [totalAmount, id]);
    const changed = (updateResult?.affectedRows ?? updateResult?.rowCount ?? 0);
    if (changed === 0) {
      return res.status(404).json({ message: 'Pesanan tidak ditemukan.' });
    }

    // Insert new order items
    for (const item of orderItemsForDb) {
      await dbAdapter.execute(
        insItemSql,
        [id, item.menu_item_id, item.quantity, item.price_at_order, item.spiciness_level, item.temperature_level]
      );
    }

    console.log(`✅ Order ${id} updated. New total: ${totalAmount}`);
    res.json({ message: 'Pesanan berhasil diupdate!', totalAmount: totalAmount });

  } catch (err) {
    console.error('Error updating order:', err);
    res.status(500).json({ message: 'Gagal mengupdate pesanan.' });
  }
});

// ======================= END REVISED ROUTES =======================


// =====================================================
// REPORTS ENDPOINT - FIXED
// =====================================================
app.get('/api/reports/sales', authenticateToken, async (req, res) => {
    console.log('📊 GET /api/reports/sales called');
    
    if (req.user.role !== 'admin' && req.user.role !== 'cashier') {
        return res.status(403).json({ message: 'Akses ditolak. Hanya admin atau kasir yang bisa melihat laporan.' });
    }
    
    const { startDate, endDate } = req.query;
    
    if (!startDate || !endDate) {
        return res.status(400).json({ message: 'Parameter startDate dan endDate diperlukan.' });
    }
    
    try {
        const [totalSalesResult] = await dbAdapter.execute(`
            SELECT 
                COALESCE(SUM(total_amount), 0) as total_sales,
                COUNT(*) as total_orders,
                SUM(CASE WHEN status = 'Selesai' THEN 1 ELSE 0 END) as completed_orders,
                SUM(CASE WHEN status = 'Dibatalkan' THEN 1 ELSE 0 END) as cancelled_orders,
                SUM(CASE WHEN status = 'Dalam Proses' THEN 1 ELSE 0 END) as pending_orders
            FROM orders 
            WHERE DATE(order_time) BETWEEN ? AND ?
        `, [startDate, endDate]);

        const [todaySalesResult] = await dbAdapter.execute(`
            SELECT 
                COALESCE(SUM(total_amount), 0) as total_sales_today,
                COUNT(*) as total_orders_today
            FROM orders 
            WHERE DATE(order_time) = ?
        `, [startDate]);

        const [topSellingItems] = await dbAdapter.execute(`
            SELECT 
                oi.menu_item_id,
                mi.name as menu_name,
                SUM(oi.quantity) as total_quantity,
                SUM(oi.quantity * oi.price_at_order) as total_revenue,
                AVG(oi.price_at_order) as avg_price
            FROM order_items oi
            JOIN menu_items mi ON oi.menu_item_id = mi.id_menu
            JOIN orders o ON oi.order_id = o.id_orders
            WHERE DATE(o.order_time) BETWEEN ? AND ?
            GROUP BY oi.menu_item_id, mi.name
            ORDER BY total_quantity DESC
            LIMIT 10
        `, [startDate, endDate]);

        const [salesByPaymentMethod] = await dbAdapter.execute(`
            SELECT 
                COALESCE(payment_method, 'Unknown') as payment_method,
                COUNT(*) as order_count,
                SUM(total_amount) as total_amount
            FROM orders 
            WHERE DATE(order_time) BETWEEN ? AND ?
            GROUP BY payment_method
        `, [startDate, endDate]);

        const [salesByDate] = await dbAdapter.execute(`
            SELECT 
                DATE(order_time) as sale_date,
                SUM(total_amount) as daily_total,
                COUNT(*) as order_count
            FROM orders 
            WHERE DATE(order_time) BETWEEN ? AND ?
            GROUP BY DATE(order_time)
            ORDER BY sale_date DESC
        `, [startDate, endDate]);
        
        const reportData = {
            totalSales: totalSalesResult[0].total_sales || 0,
            totalOrders: totalSalesResult[0].total_orders || 0,
            completedOrders: totalSalesResult[0].completed_orders || 0,
            cancelledOrders: totalSalesResult[0].cancelled_orders || 0,
            pendingOrders: totalSalesResult[0].pending_orders || 0,
            totalSalesToday: todaySalesResult[0].total_sales_today || 0,
            totalOrdersToday: todaySalesResult[0].total_orders_today || 0,
            topSellingItems: topSellingItems,
            salesByPaymentMethod: salesByPaymentMethod,
            salesByDate: salesByDate
        };
        
        console.log('📊 Report generated successfully');
        res.json(reportData);
        
    } catch (error) {
        console.error('Error generating sales report:', error);
        res.status(500).json({ message: 'Gagal mengambil data laporan penjualan.' });
    }
});

// =====================================================
// DEBUG ENDPOINT
// =====================================================
app.get('/api/debug/menu/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const [menu] = await dbAdapter.execute('SELECT * FROM menu_items WHERE id_menu = ?', [id]);
        res.json({
            found: menu.length > 0,
            menu: menu[0] || null,
            id_received: id,
            id_type: typeof id,
            id_parsed: parseInt(id),
            is_nan: isNaN(parseInt(id)),
            is_available_safe: menu[0] ? isMenuAvailable(menu[0].is_available) : null
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =====================================================
// MIDTRANS ENDPOINTS (OPTIONAL - for advanced payment)
// =====================================================
app.post('/api/midtrans/transaction', async (req, res) => {
    try {
        const { order_id, gross_amount, item_details, custom_field1, custom_field2 } = req.body;
        
        const parameter = {
            transaction_details: {
                order_id: order_id,
                gross_amount: gross_amount
            },
            item_details: item_details,
            customer_details: {
                // Add customer details if needed
            }
        };

        const transaction = await snap.createTransaction(parameter);
        
        res.json({
            token: transaction.token,
            redirect_url: transaction.redirect_url
        });
    } catch (error) {
        console.error('Midtrans transaction error:', error);
        res.status(500).json({ 
            error: 'Failed to create transaction',
            message: error.message 
        });
    }
});

app.post('/api/midtrans/webhook/notification', async (req, res) => {
    console.log('🔔 Midtrans webhook received:', new Date().toISOString());
    
    try {
        const notification = req.body;
        console.log('📦 Webhook payload:', JSON.stringify(notification, null, 2));

        // Verifikasi signature
        const serverKey = process.env.MIDTRANS_SERVER_KEY;
        if (!PaymentUtils.verifyMidtransSignature(notification, serverKey)) {
            throw new Error('Invalid signature key');
        }

        const orderId = notification.order_id;
        const transactionStatus = notification.transaction_status;
        const fraudStatus = notification.fraud_status;

        const paymentStatus = PaymentUtils.mapMidtransStatusToPaymentStatus(
            transactionStatus, 
            fraudStatus
        );

        console.log(`💰 Payment status mapping: ${transactionStatus} → ${paymentStatus}`);

        // Log webhook event
        await PaymentUtils.logWebhookEvent(dbAdapter, notification);

        // Get current status
        const currentOrderQuery = `SELECT payment_status FROM orders WHERE midtrans_order_id = ?`;
        const [currentOrderRows] = await dbAdapter.execute(currentOrderQuery, [orderId]);
        const currentOrder = currentOrderRows[0];

        const oldStatus = currentOrder ? currentOrder.payment_status : 'Unknown';

        // Update status
        const rowsAffected = await PaymentUtils.updateOrderPaymentStatus(
            dbAdapter,
            orderId,
            paymentStatus,
            transactionStatus,
            notification.transaction_id
        );

        if (rowsAffected === 0) {
            console.warn(`⚠️ No orders found with midtrans_order_id: ${orderId}`);
        } else {
            console.log(`📝 Payment status updated: ${orderId} ${oldStatus} → ${paymentStatus}`);
        }

        res.status(200).json({ 
            status: 'success', 
            message: 'Webhook processed successfully',
            data: {
                order_id: orderId,
                old_status: oldStatus,
                new_status: paymentStatus,
                rows_affected: rowsAffected
            }
        });

    } catch (error) {
        console.error('❌ Webhook processing error:', error);
        res.status(500).json({ 
            status: 'error', 
            message: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// =====================================================
// START SERVER
// =====================================================
if (process.env.VERCEL) {
  module.exports = app;
} else {
    app.listen(PORT, () => {
        console.log('='.repeat(60));
        console.log('🚀 SERVER STARTED SUCCESSFULLY! (COMPLETELY FIXED VERSION)');
        console.log('='.repeat(60));
        console.log(`🌐 Server running at: http://localhost:${PORT}`);
        console.log(`🔑 JWT Secret configured: ${JWT_SECRET ? 'YES' : 'NO'}`);
        console.log(`💳 Midtrans Mode: ${process.env.MIDTRANS_IS_PRODUCTION === 'true' ? 'PRODUCTION' : 'SANDBOX'}`);
        console.log(`📊 Database Type: ${process.env.DB_TYPE || 'mysql'}`);
        console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
        console.log('='.repeat(60));
        console.log('📋 Available Endpoints:');
        console.log('  • POST /api/login');
        console.log('  • GET  /api/health');
        console.log('  • GET  /api/debug/test-simple');
        console.log('  • GET  /api/debug/schema'); 
        console.log('  • POST /api/debug/order');
        console.log('  • GET  /api/menu (boolean-safe)');
        console.log('  • PATCH /api/menu/:id/availability (boolean-safe)');
        console.log('  • GET  /api/orders');
        console.log('  • POST /api/orders (COMPLETELY FIXED - safe table lookup)');
        console.log('  • GET  /api/tables'); 
        console.log('  • GET  /api/reports/sales');
        console.log('  • GET  /api/debug/menu/:id (boolean-safe)');
        console.log('='.repeat(60));
        console.log('🔧 KEY FIXES APPLIED:');
        console.log('  ✅ Safe table lookup function with string handling');
        console.log('  ✅ Boolean-safe menu availability checks');
        console.log('  ✅ Type-safe order creation');
        console.log('  ✅ Enhanced error logging');
        console.log('  ✅ Debug endpoints for troubleshooting');
        console.log('='.repeat(60));
    });
}