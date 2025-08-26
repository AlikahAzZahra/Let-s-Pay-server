// server/create-user.js
require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function createUser() {
    try {
        console.log('🔧 Creating fresh admin user...');
        
        // Generate hash untuk password 'admin123'
        const password = 'admin123';
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);
        
        console.log('Password:', password);
        console.log('Generated hash:', hash);
        
        // Test hash immediately
        const isValid = await bcrypt.compare(password, hash);
        console.log('Hash test:', isValid ? '✅ Valid' : '❌ Invalid');
        
        // Delete existing admin
        await pool.query('DELETE FROM users WHERE username = $1', ['admin']);
        console.log('🗑️ Deleted existing admin user');
        
        // Insert new admin
        const result = await pool.query(
            'INSERT INTO users (username, password_hash, role, name) VALUES ($1, $2, $3, $4) RETURNING id, username, role, name',
            ['admin', hash, 'admin', 'Administrator']
        );
        
        console.log('✅ Created new user:', result.rows[0]);
        
        // Test query dari database
        const testUser = await pool.query('SELECT username, password_hash FROM users WHERE username = $1', ['admin']);
        const dbHash = testUser.rows[0].password_hash;
        
        console.log('📊 Database hash:', dbHash);
        
        // Test bcrypt compare dengan hash dari database
        const compareTest = await bcrypt.compare(password, dbHash);
        console.log('🔍 Database hash test:', compareTest ? '✅ Valid' : '❌ Invalid');
        
        await pool.end();
        console.log('✅ Done! Try login with username: admin, password: admin123');
        
    } catch (error) {
        console.error('❌ Error:', error);
        await pool.end();
        process.exit(1);
    }
}

createUser();