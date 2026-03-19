const mongoose = require('mongoose');

const KeySchema = new mongoose.Schema({
    // Giá trị key (chuỗi kích hoạt)
    value: {
        type: String,
        required: true,
        unique: true,
        trim: true,
    },

    // Thông tin chủ key
    ten: {
        type: String,
        required: true,
        trim: true,
    },
    sdt: {
        type: String,
        required: true,
        trim: true,
    },

    // Số thiết bị tối đa được phép
    max_devices: {
        type: Number,
        required: true,
        default: 1,
        min: 1,
    },

    // Danh sách device ID đã đăng ký
    // Mỗi phần tử: { deviceId: String, registeredAt: Date }
    devices: [
        {
            deviceId: { type: String, required: true },
            registeredAt: { type: Date, default: Date.now },
        },
    ],

    // Trạng thái key
    active: {
        type: Boolean,
        default: true,
    },

    // Ngày tạo
    createdAt: {
        type: Date,
        default: Date.now,
    },

    // Ngày hết hạn (null = không giới hạn)
    expiresAt: {
        type: Date,
        default: null,
    },
});

// Virtual: còn slot thiết bị không
KeySchema.virtual('hasSlot').get(function () {
    return this.devices.length < this.max_devices;
});

// Virtual: đã hết hạn chưa
KeySchema.virtual('isExpired').get(function () {
    if (!this.expiresAt) return false;
    return new Date() > this.expiresAt;
});

module.exports = mongoose.model('Key', KeySchema);
