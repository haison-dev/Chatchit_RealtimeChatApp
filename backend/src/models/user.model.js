import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
    },
    hashPassword: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
    },
    displayName: {
        type: String,
        required: true,
        trim: true,
    },
    avatarUrl: {
        type: String,
    },
    avatarId: {
        type: String,
    },
    bio: {
        type: String,
        maxlength: 500,
    },
    phone: {
        type: String,
        sparse: true,
    },
    // Chỉ đặt bằng scripts/createAdmin.js; không API nào cho người dùng tự đổi.
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user',
    },
}, {
    timestamps: true
});

const User = mongoose.model('User', userSchema);
export default User;