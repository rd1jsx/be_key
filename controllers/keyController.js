/**
 * keyController.js
 * Xử lý toàn bộ logic nghiệp vụ liên quan đến key và device
 */
const crypto = require('crypto');
const Key = require('../models/Key');

// ─────────────────────────────────────────────
// Helper: Tạo key random 12 ký tự (A-Z, 0-9), đảm bảo không trùng
// ─────────────────────────────────────────────
const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
function randomKeyString() {
    // Tạo chuỗi 12 ký tự từ bộ CHARS
    const bytes = crypto.randomBytes(12);
    return Array.from(bytes)
        .map(b => CHARS[b % CHARS.length])
        .join('');
}

async function generateUniqueKey() {
    let attempts = 0;
    while (attempts < 20) { // tối đa 20 lần thử
        const candidate = randomKeyString();
        const exists = await Key.findOne({ value: candidate });
        if (!exists) return candidate;
        attempts++;
    }
    throw new Error('Không thể tạo key duy nhất sau nhiều lần thử');
}

// ─────────────────────────────────────────────
// CHECK LẦN 1: Xác thực key (khi user nhập key)
// POST /api/key/verify
// Body: { keyValue: String, deviceId: String }
// Trả về: thông tin key (không đăng ký device)
// ─────────────────────────────────────────────
exports.verifyKey = async (req, res) => {
    try {
        const { keyValue, deviceId } = req.body;

        if (!keyValue || !deviceId) {
            return res.status(400).json({
                ok: false,
                code: 'MISSING_PARAMS',
                message: 'Thiếu keyValue hoặc deviceId',
            });
        }

        const key = await Key.findOne({ value: keyValue.trim() });

        if (!key) {
            return res.status(404).json({
                ok: false,
                code: 'KEY_NOT_FOUND',
                message: 'Key không tồn tại hoặc không hợp lệ',
            });
        }

        if (!key.active) {
            return res.status(403).json({
                ok: false,
                code: 'KEY_INACTIVE',
                message: 'Key đã bị vô hiệu hoá',
            });
        }

        if (key.expiresAt && new Date() > key.expiresAt) {
            return res.status(403).json({
                ok: false,
                code: 'KEY_EXPIRED',
                message: 'Key đã hết hạn',
            });
        }

        // Kiểm tra device đã đăng ký chưa (để hiện trạng thái đúng)
        const alreadyRegistered = key.devices.some(d => d.deviceId === deviceId);

        // Kiểm tra còn slot không (nếu device chưa đăng ký)
        const hasSlot = key.devices.length < key.max_devices;

        if (!alreadyRegistered && !hasSlot) {
            return res.status(403).json({
                ok: false,
                code: 'DEVICE_LIMIT_REACHED',
                message: `Key đã đạt giới hạn ${key.max_devices} thiết bị`,
                max_devices: key.max_devices,
                current_devices: key.devices.length,
            });
        }

        // Key hợp lệ → trả về thông tin cơ bản (không lộ nhạy cảm)
        return res.json({
            ok: true,
            code: 'KEY_VALID',
            message: 'Key hợp lệ',
            data: {
                ten: key.ten,
                sdt: key.sdt,
                max_devices: key.max_devices,
                current_devices: key.devices.length,
                alreadyRegistered,
                hasSlot,
                expiresAt: key.expiresAt,
            },
        });
    } catch (err) {
        console.error('[verifyKey]', err);
        return res.status(500).json({ ok: false, code: 'SERVER_ERROR', message: err.message });
    }
};

// ─────────────────────────────────────────────
// CHECK LẦN 2: Xác thực + đăng ký device (khi bấm START)
// POST /api/key/activate
// Body: { keyValue: String, deviceId: String }
// Nếu device chưa có → thêm vào mảng devices (nếu còn slot)
// Nếu device đã có → cho qua
// ─────────────────────────────────────────────
exports.activateKey = async (req, res) => {
    try {
        const { keyValue, deviceId } = req.body;

        if (!keyValue || !deviceId) {
            return res.status(400).json({
                ok: false,
                code: 'MISSING_PARAMS',
                message: 'Thiếu keyValue hoặc deviceId',
            });
        }

        const key = await Key.findOne({ value: keyValue.trim() });

        if (!key) {
            return res.status(404).json({
                ok: false,
                code: 'KEY_NOT_FOUND',
                message: 'Key không tồn tại hoặc không hợp lệ',
            });
        }

        if (!key.active) {
            return res.status(403).json({
                ok: false,
                code: 'KEY_INACTIVE',
                message: 'Key đã bị vô hiệu hoá',
            });
        }

        if (key.expiresAt && new Date() > key.expiresAt) {
            return res.status(403).json({
                ok: false,
                code: 'KEY_EXPIRED',
                message: 'Key đã hết hạn',
            });
        }

        const alreadyRegistered = key.devices.some(d => d.deviceId === deviceId);

        if (!alreadyRegistered) {
            // Kiểm tra slot
            if (key.devices.length >= key.max_devices) {
                return res.status(403).json({
                    ok: false,
                    code: 'DEVICE_LIMIT_REACHED',
                    message: `Key đã đạt giới hạn ${key.max_devices} thiết bị. Không thể đăng ký thêm.`,
                    max_devices: key.max_devices,
                    current_devices: key.devices.length,
                });
            }

            // Thêm device mới vào mảng
            key.devices.push({ deviceId, registeredAt: new Date() });
            await key.save();
            console.log(`[activate] Đã thêm device "${deviceId}" vào key "${keyValue}"`);
        } else {
            console.log(`[activate] Device "${deviceId}" đã đăng ký trước đó, cho qua`);
        }

        return res.json({
            ok: true,
            code: 'ACTIVATED',
            message: alreadyRegistered ? 'Thiết bị đã được xác thực trước đó' : 'Đăng ký thiết bị thành công',
            data: {
                ten: key.ten,
                sdt: key.sdt,
                max_devices: key.max_devices,
                current_devices: key.devices.length,
                alreadyRegistered,
                expiresAt: key.expiresAt,
            },
        });
    } catch (err) {
        console.error('[activateKey]', err);
        return res.status(500).json({ ok: false, code: 'SERVER_ERROR', message: err.message });
    }
};

// ─────────────────────────────────────────────
// ADMIN: Lấy danh sách tất cả key
// GET /admin/api/keys
// ─────────────────────────────────────────────
exports.listKeys = async (req, res) => {
    try {
        const keys = await Key.find().sort({ createdAt: -1 }).lean();
        res.json({ ok: true, data: keys });
    } catch (err) {
        res.status(500).json({ ok: false, message: err.message });
    }
};

// ─────────────────────────────────────────────
// ADMIN: Tạo key mới
// POST /admin/api/keys
// Body: { ten, sdt, max_devices, expiresAt? }
// → value auto-generate 12 ký tự random, không trùng
// ─────────────────────────────────────────────
exports.createKey = async (req, res) => {
    try {
        const { ten, sdt, max_devices, expiresAt } = req.body;

        if (!ten || !sdt || !max_devices) {
            return res.status(400).json({ ok: false, message: 'Thiếu thông tin bắt buộc (ten, sdt, max_devices)' });
        }

        // Tự động tạo key random 12 ký tự, đảm bảo không trùng
        const value = await generateUniqueKey();

        const key = await Key.create({
            value,
            ten: ten.trim(),
            sdt: sdt.trim(),
            max_devices: Number(max_devices),
            expiresAt: expiresAt ? new Date(expiresAt) : null,
        });

        res.status(201).json({ ok: true, data: key });
    } catch (err) {
        res.status(500).json({ ok: false, message: err.message });
    }
};

// ─────────────────────────────────────────────
// ADMIN: Cập nhật key
// PUT /admin/api/keys/:id
// ─────────────────────────────────────────────
exports.updateKey = async (req, res) => {
    try {
        const { ten, sdt, max_devices, active, expiresAt } = req.body;
        const update = {};
        if (ten !== undefined) update.ten = ten.trim();
        if (sdt !== undefined) update.sdt = sdt.trim();
        if (max_devices !== undefined) update.max_devices = Number(max_devices);
        if (active !== undefined) update.active = Boolean(active);
        if (expiresAt !== undefined) update.expiresAt = expiresAt ? new Date(expiresAt) : null;

        const key = await Key.findByIdAndUpdate(req.params.id, update, { new: true });
        if (!key) return res.status(404).json({ ok: false, message: 'Key không tìm thấy' });

        res.json({ ok: true, data: key });
    } catch (err) {
        res.status(500).json({ ok: false, message: err.message });
    }
};

// ─────────────────────────────────────────────
// ADMIN: Xoá key
// DELETE /admin/api/keys/:id
// ─────────────────────────────────────────────
exports.deleteKey = async (req, res) => {
    try {
        const key = await Key.findByIdAndDelete(req.params.id);
        if (!key) return res.status(404).json({ ok: false, message: 'Key không tìm thấy' });
        res.json({ ok: true, message: 'Đã xoá key' });
    } catch (err) {
        res.status(500).json({ ok: false, message: err.message });
    }
};

// ─────────────────────────────────────────────
// ADMIN: Xoá 1 device khỏi key
// DELETE /admin/api/keys/:id/devices/:deviceId
// ─────────────────────────────────────────────
exports.removeDevice = async (req, res) => {
    try {
        const key = await Key.findById(req.params.id);
        if (!key) return res.status(404).json({ ok: false, message: 'Key không tìm thấy' });

        const before = key.devices.length;
        key.devices = key.devices.filter(d => d.deviceId !== req.params.deviceId);
        await key.save();

        const removed = before - key.devices.length;
        res.json({ ok: true, message: removed > 0 ? 'Đã xoá device' : 'Không tìm thấy device', removed });
    } catch (err) {
        res.status(500).json({ ok: false, message: err.message });
    }
};

// ─────────────────────────────────────────────
// ADMIN: Reset toàn bộ devices của key
// DELETE /admin/api/keys/:id/devices
// ─────────────────────────────────────────────
exports.resetDevices = async (req, res) => {
    try {
        const key = await Key.findById(req.params.id);
        if (!key) return res.status(404).json({ ok: false, message: 'Key không tìm thấy' });

        key.devices = [];
        await key.save();
        res.json({ ok: true, message: 'Đã reset tất cả thiết bị' });
    } catch (err) {
        res.status(500).json({ ok: false, message: err.message });
    }
};
