const bcrypt = require('bcryptjs');

// Generate hash untuk password yang diinginkan
const password1 = 'admin123';
const password2 = 'password';

const hash1 = bcrypt.hashSync(password1, 10);
const hash2 = bcrypt.hashSync(password2, 10);

console.log('Hash untuk "admin123":', hash1);
console.log('Hash untuk "password":', hash2);

// Test hash
console.log('Test admin123:', bcrypt.compareSync('admin123', hash1));
console.log('Test password:', bcrypt.compareSync('password', hash2));