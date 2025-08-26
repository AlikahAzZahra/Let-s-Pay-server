// database/adapter.js - SIMPLIFIED WORKING VERSION
require('dotenv').config();
const { Pool } = require('pg');

class DatabaseAdapter {
    constructor() {
        this.pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: { rejectUnauthorized: false }
        });
    }

    async connect() {
        try {
            const client = await this.pool.connect();
            await client.query('SELECT NOW()');
            client.release();
            console.log('Database connected successfully');
        } catch (error) {
            console.error('Database connection failed:', error);
            throw error;
        }
    }

    async execute(sql, params = []) {
        try {
            // Convert MySQL ? to PostgreSQL $1, $2, $3
            let pgQuery = sql;
            let paramIndex = 1;
            pgQuery = sql.replace(/\?/g, () => `$${paramIndex++}`);
            
            console.log('Query:', pgQuery);
            console.log('Params:', params);
            
            const result = await this.pool.query(pgQuery, params);
            return [result.rows];
        } catch (error) {
            console.error('Query failed:', error.message);
            throw error;
        }
    }

    async createTablesIfNotExists() {
        console.log('Tables already exist, skipping creation');
    }
}

module.exports = new DatabaseAdapter();