const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        require: true,
        trim: true
    },
    email: {
        type: String,
        unique: true,
        require: true
    },
    password: {
        type: String,
        require: true
    },
    score: {
        html: {
            type: Number,
        },
        CSS: {
            type: Number,
        },
        javascript: {
            type: Number,
        },
        remark: {
            type: String,
        },
    },
    blackList: [],
    isAdmin: {
        type: Boolean,
        default: false
    },
    isVerified: {
        type: Boolean,
        default: false
    }
}, {timestamps: true});

const UserModel = mongoose.model('User', userSchema);

module.exports = UserModel;
