// Tạo tài khoản admin, hoặc nâng quyền một tài khoản có sẵn và đặt lại mật khẩu.
// Cách dùng (đọc backend/.env): ADMIN_USERNAME=... ADMIN_PASSWORD=... npm run create-admin
import 'dotenv/config';
import bcrypt from 'bcrypt';
import mongoose from 'mongoose';
import User from '../src/models/user.model.js';
import { USERNAME_PATTERN } from '../src/utils/sanitize.util.js';

const username = process.env.ADMIN_USERNAME?.trim().toLowerCase();
const password = process.env.ADMIN_PASSWORD;
const email = (process.env.ADMIN_EMAIL?.trim() || `${username}@admin.chatchit.local`).toLowerCase();

if (!username || !USERNAME_PATTERN.test(username)) {
    console.error('Thiếu ADMIN_USERNAME hoặc không hợp lệ (3-30 ký tự gồm chữ, số, ".", "_" hoặc "-").');
    process.exit(1);
}
if (typeof password !== 'string' || password.length < 6 || password.length > 72) {
    console.error('ADMIN_PASSWORD phải dài từ 6 đến 72 ký tự.');
    process.exit(1);
}
if (password.toLowerCase() === username) {
    console.warn('Cảnh báo: mật khẩu trùng tên đăng nhập. Ai biết tên đăng nhập cũng có thể đăng nhập với quyền admin.');
}

try {
    await mongoose.connect(process.env.MONGODB_CONNECTSTRING);
    const hashPassword = await bcrypt.hash(password, 10);
    const existing = await User.findOne({ username });

    if (existing) {
        existing.role = 'admin';
        existing.hashPassword = hashPassword;
        await existing.save();
        console.log(`Tài khoản "${username}" đã có quyền admin (mật khẩu đã được đặt lại).`);
    } else {
        await User.create({ username, hashPassword, email, displayName: 'Quản trị viên', role: 'admin' });
        console.log(`Đã tạo tài khoản admin "${username}".`);
    }
} catch (error) {
    console.error('Không thể tạo tài khoản admin:', error.message);
    process.exitCode = 1;
} finally {
    await mongoose.disconnect();
}
