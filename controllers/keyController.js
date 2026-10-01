/**
 * keyController.js
 * Xử lý toàn bộ logic nghiệp vụ liên quan đến key và device
 */
const crypto = require('crypto');
const mongoose = require('mongoose');
const Key = require('../models/Key');

// ─────────────────────────────────────────────
// Helper: Tạo key random 12 ký tự (A-Z, 0-9), đảm bảo không trùng
// ─────────────────────────────────────────────
const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
function randomKeyString() {
    // crypto.randomInt → phân phối đều, không bị lệch modulo
    let out = '';
    for (let i = 0; i < 12; i++) out += CHARS[crypto.randomInt(CHARS.length)];
    return out;
}

// ─────────────────────────────────────────────
// Helper: validate input
// ─────────────────────────────────────────────
const isStr = (v, max = 200) => typeof v === 'string' && v.trim().length > 0 && v.length <= max;
const isId = (v) => mongoose.isValidObjectId(v);

// "YYYY-MM-DD" → hết hạn vào cuối ngày đó theo giờ Việt Nam (23:59:59 GMT+7)
// Trả về undefined nếu sai định dạng
function parseExpiry(v) {
    if (v === null || v === '') return null;
    if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return undefined;
    const d = new Date(`${v}T23:59:59.999+07:00`);
    return isNaN(d) ? undefined : d;
}

function parseMaxDevices(v) {
    const n = Number(v);
    return Number.isInteger(n) && n >= 1 && n <= 1000 ? n : undefined;
}

const PUBLIC_FIELDS_ERR = {
    ok: false,
    code: 'MISSING_PARAMS',
    message: 'Thiếu keyValue hoặc deviceId',
};

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

        if (!isStr(keyValue, 64) || !isStr(deviceId, 256)) {
            return res.status(400).json(PUBLIC_FIELDS_ERR);
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
        return res.status(500).json({ ok: false, code: 'SERVER_ERROR', message: 'Lỗi server' });
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

        if (!isStr(keyValue, 64) || !isStr(deviceId, 256)) {
            return res.status(400).json(PUBLIC_FIELDS_ERR);
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

            // Thêm device mới — atomic, tránh 2 request đồng thời vượt giới hạn
            const updated = await Key.findOneAndUpdate(
                {
                    _id: key._id,
                    'devices.deviceId': { $ne: deviceId },
                    $expr: { $lt: [{ $size: '$devices' }, '$max_devices'] },
                },
                { $push: { devices: { deviceId, registeredAt: new Date() } } },
                { new: true }
            );
            if (!updated) {
                return res.status(409).json({
                    ok: false,
                    code: 'DEVICE_LIMIT_REACHED',
                    message: 'Không thể đăng ký thiết bị, vui lòng thử lại',
                });
            }
            key.devices = updated.devices;
            console.log(`[activate] Đã thêm device mới vào key ${key._id}`);
        } else {
            console.log(`[activate] Device đã đăng ký trước đó với key ${key._id}, cho qua`);
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
        return res.status(500).json({ ok: false, code: 'SERVER_ERROR', message: 'Lỗi server' });
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
        console.error('[admin]', err);
        res.status(500).json({ ok: false, message: 'Lỗi server' });
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
        const max = parseMaxDevices(max_devices);
        const exp = parseExpiry(expiresAt ?? null);

        if (!isStr(ten) || !isStr(sdt, 30) || max === undefined) {
            return res.status(400).json({ ok: false, message: 'Thiếu hoặc sai thông tin (họ tên, SĐT, số thiết bị 1–1000)' });
        }
        if (exp === undefined) {
            return res.status(400).json({ ok: false, message: 'Ngày hết hạn không hợp lệ' });
        }

        // Tự động tạo key random 12 ký tự, đảm bảo không trùng
        const value = await generateUniqueKey();

        const key = await Key.create({
            value,
            ten: ten.trim(),
            sdt: sdt.trim(),
            max_devices: max,
            expiresAt: exp,
        });

        res.status(201).json({ ok: true, data: key });
    } catch (err) {
        console.error('[admin]', err);
        res.status(500).json({ ok: false, message: 'Lỗi server' });
    }
};

// ─────────────────────────────────────────────
// ADMIN: Cập nhật key
// PUT /admin/api/keys/:id
// ─────────────────────────────────────────────
exports.updateKey = async (req, res) => {
    try {
        if (!isId(req.params.id)) return res.status(400).json({ ok: false, message: 'ID không hợp lệ' });

        const { ten, sdt, max_devices, active, expiresAt } = req.body;
        const update = {};
        if (ten !== undefined) {
            if (!isStr(ten)) return res.status(400).json({ ok: false, message: 'Họ tên không hợp lệ' });
            update.ten = ten.trim();
        }
        if (sdt !== undefined) {
            if (!isStr(sdt, 30)) return res.status(400).json({ ok: false, message: 'SĐT không hợp lệ' });
            update.sdt = sdt.trim();
        }
        if (max_devices !== undefined) {
            update.max_devices = parseMaxDevices(max_devices);
            if (update.max_devices === undefined) return res.status(400).json({ ok: false, message: 'Số thiết bị phải từ 1 đến 1000' });
        }
        if (active !== undefined) {
            if (typeof active !== 'boolean') return res.status(400).json({ ok: false, message: 'Trạng thái không hợp lệ' });
            update.active = active;
        }
        // Chỉ đổi ngày hết hạn khi client gửi field này (null = vĩnh viễn)
        if (expiresAt !== undefined) {
            update.expiresAt = parseExpiry(expiresAt);
            if (update.expiresAt === undefined) return res.status(400).json({ ok: false, message: 'Ngày hết hạn không hợp lệ' });
        }

        const key = await Key.findByIdAndUpdate(req.params.id, update, { new: true, runValidators: true });
        if (!key) return res.status(404).json({ ok: false, message: 'Key không tìm thấy' });

        res.json({ ok: true, data: key });
    } catch (err) {
        console.error('[admin]', err);
        res.status(500).json({ ok: false, message: 'Lỗi server' });
    }
};

// ─────────────────────────────────────────────
// ADMIN: Xoá key
// DELETE /admin/api/keys/:id
// ─────────────────────────────────────────────
exports.deleteKey = async (req, res) => {
    try {
        if (!isId(req.params.id)) return res.status(400).json({ ok: false, message: 'ID không hợp lệ' });
        const key = await Key.findByIdAndDelete(req.params.id);
        if (!key) return res.status(404).json({ ok: false, message: 'Key không tìm thấy' });
        res.json({ ok: true, message: 'Đã xoá key' });
    } catch (err) {
        console.error('[admin]', err);
        res.status(500).json({ ok: false, message: 'Lỗi server' });
    }
};

// ─────────────────────────────────────────────
// ADMIN: Xoá 1 device khỏi key
// DELETE /admin/api/keys/:id/devices/:deviceId
// ─────────────────────────────────────────────
exports.removeDevice = async (req, res) => {
    try {
        if (!isId(req.params.id)) return res.status(400).json({ ok: false, message: 'ID không hợp lệ' });
        const key = await Key.findById(req.params.id);
        if (!key) return res.status(404).json({ ok: false, message: 'Key không tìm thấy' });

        const before = key.devices.length;
        key.devices = key.devices.filter(d => d.deviceId !== req.params.deviceId);
        await key.save();

        const removed = before - key.devices.length;
        res.json({ ok: true, message: removed > 0 ? 'Đã xoá device' : 'Không tìm thấy device', removed });
    } catch (err) {
        console.error('[admin]', err);
        res.status(500).json({ ok: false, message: 'Lỗi server' });
    }
};

// ─────────────────────────────────────────────
// ADMIN: Reset toàn bộ devices của key
// DELETE /admin/api/keys/:id/devices
// ─────────────────────────────────────────────
exports.resetDevices = async (req, res) => {
    try {
        if (!isId(req.params.id)) return res.status(400).json({ ok: false, message: 'ID không hợp lệ' });
        const key = await Key.findById(req.params.id);
        if (!key) return res.status(404).json({ ok: false, message: 'Key không tìm thấy' });

        key.devices = [];
        await key.save();
        res.json({ ok: true, message: 'Đã reset tất cả thiết bị' });
    } catch (err) {
        console.error('[admin]', err);
        res.status(500).json({ ok: false, message: 'Lỗi server' });
    }
};
