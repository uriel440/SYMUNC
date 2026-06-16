require('dotenv').config();
const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'suyun_mun_2027_secret_change_this';

// ========== PostgreSQL 连接 ==========
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ========== 初始化数据库表 ==========
async function initDatabase() {
    const client = await pool.connect();
    try {
        // 用户表
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(36) PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                "isAdmin" BOOLEAN DEFAULT FALSE,
                "genevaAccess" BOOLEAN DEFAULT FALSE,
                "genevaNewsAccess" BOOLEAN DEFAULT FALSE,
                "almatyNewsAccess" BOOLEAN DEFAULT FALSE,
                "delegateId" VARCHAR(100),
                "delegateName" VARCHAR(255)
            )
        `);
        // 文件表
        await client.query(`
            CREATE TABLE IF NOT EXISTS files (
                id VARCHAR(36) PRIMARY KEY,
                "originalName" VARCHAR(255),
                "storedName" VARCHAR(255),
                committee VARCHAR(50),
                type VARCHAR(50),
                "uploadedBy" VARCHAR(36),
                "uploaderName" VARCHAR(255),
                visible BOOLEAN DEFAULT FALSE,
                "uploadTime" VARCHAR(50)
            )
        `);
        // 财务表
        await client.query(`
            CREATE TABLE IF NOT EXISTS finances (
                id VARCHAR(36) PRIMARY KEY,
                title VARCHAR(255),
                "originalName" VARCHAR(255),
                "storedName" VARCHAR(255),
                "uploadedBy" VARCHAR(36),
                "uploaderName" VARCHAR(255),
                "uploadTime" VARCHAR(50)
            )
        `);
        // 测验表
        await client.query(`
            CREATE TABLE IF NOT EXISTS quizzes (
                id VARCHAR(36) PRIMARY KEY,
                "originalName" VARCHAR(255),
                "storedName" VARCHAR(255),
                committee VARCHAR(50),
                "uploadedBy" VARCHAR(36),
                "uploaderName" VARCHAR(255),
                "uploadTime" VARCHAR(50)
            )
        `);
        // 新闻表
        await client.query(`
            CREATE TABLE IF NOT EXISTS news (
                id VARCHAR(36) PRIMARY KEY,
                title VARCHAR(255),
                "originalName" VARCHAR(255),
                "storedName" VARCHAR(255),
                committee VARCHAR(50),
                "uploadedBy" VARCHAR(36),
                "uploaderName" VARCHAR(255),
                "uploadTime" VARCHAR(50)
            )
        `);
        // 投票表
        await client.query(`
            CREATE TABLE IF NOT EXISTS votes (
                id SERIAL PRIMARY KEY,
                data JSONB DEFAULT '{}'::jsonb
            )
        `);
        // 不信任案表
        await client.query(`
            CREATE TABLE IF NOT EXISTS censures (
                id SERIAL PRIMARY KEY,
                data JSONB DEFAULT '{}'::jsonb
            )
        `);
        // 总理表
        await client.query(`
            CREATE TABLE IF NOT EXISTS prime_ministers (
                id SERIAL PRIMARY KEY,
                data JSONB DEFAULT '{}'::jsonb
            )
        `);

        // 初始化默认数据
        const pmResult = await client.query('SELECT * FROM prime_ministers');
        if (pmResult.rows.length === 0) {
            await client.query(
                'INSERT INTO prime_ministers (data) VALUES ($1)',
                [JSON.stringify({ name: "约瑟夫·拉尼埃尔", party: "全国独立人士与农民中心 (CNIP)", updatedAt: new Date().toISOString() })]
            );
        }
        const voteResult = await client.query('SELECT * FROM votes');
        if (voteResult.rows.length === 0) {
            await client.query(
                'INSERT INTO votes (data) VALUES ($1)',
                [JSON.stringify({ votes: {}, history: [], currentBill: { id: 'current', text: '授权政府接受日内瓦会议达成的停战协议及印度支那和平解决方案', active: true }, completedBills: [] })]
            );
        }
        const censureResult = await client.query('SELECT * FROM censures');
        if (censureResult.rows.length === 0) {
            await client.query(
                'INSERT INTO censures (data) VALUES ($1)',
                [JSON.stringify({ active: false, votes: { yes: [], no: [], abstain: [] }, history: [], completedCensures: [] })]
            );
        }
        console.log('✅ 数据库初始化完成');
    } catch (err) {
        console.error('数据库初始化失败:', err);
    } finally {
        client.release();
    }
}
initDatabase();

// ========== 本地存储 ==========
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
[DATA_DIR, UPLOADS_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

const COMMITTEE_PASSWORDS = { iaea: '123456', almaty: '1991' };

// ========== 邮箱配置 ==========
const EMAIL_CONFIG = {
    host: 'smtp.qq.com',
    port: 465,
    secure: true,
    auth: {
        user: '3645987036@qq.com',
        pass: 'lcnonrlngeuedbhd'
    }
};
const EMAIL_FROM = '苏韵模联组委会 <3645987036@qq.com>';
const transporter = nodemailer.createTransport(EMAIL_CONFIG);
const verificationCodes = {};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
        const uniqueName = uuidv4() + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// ========== 认证中间件 ==========
function authMiddleware(req, res, next) {
    const token = req.cookies?.token;
    if (!token) return res.status(401).json({ error: '未登录' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: '登录已过期' });
    }
}

function adminMiddleware(req, res, next) {
    if (!req.user || !req.user.isAdmin) return res.status(403).json({ error: '需要管理员权限' });
    next();
}

async function genevaAccessMiddleware(req, res, next) {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) return res.status(401).json({ error: '用户不存在' });
    const user = result.rows[0];
    if (user.isAdmin) return next();
    if (!user.genevaAccess) return res.status(403).json({ error: '您尚未获得日内瓦会场的访问权限，请联系管理员' });
    next();
}

async function newsUploadMiddleware(req, res, next) {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) return res.status(401).json({ error: '用户不存在' });
    const user = result.rows[0];
    if (user.isAdmin) return next();
    const { committee } = req.body;
    if (committee === 'geneva' && user.genevaNewsAccess) return next();
    if (committee === 'almaty' && user.almatyNewsAccess) return next();
    return res.status(403).json({ error: '您没有该委员会的新闻上传权限，请联系管理员' });
}

// ========== 委员会密码验证 ==========
app.post('/api/verify-committee-password', authMiddleware, (req, res) => {
    const { committee, password } = req.body;
    if (!committee || !['iaea', 'almaty'].includes(committee)) return res.status(400).json({ error: '无效的委员会' });
    if (req.user.isAdmin) return res.json({ verified: true, message: '管理员自动通过' });
    if (password === COMMITTEE_PASSWORDS[committee]) {
        const token = jwt.sign({ id: req.user.id, committee, verified: true }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie(`committee_${committee}`, token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
        return res.json({ verified: true, message: '验证通过' });
    }
    res.status(403).json({ verified: false, error: '密码错误' });
});

app.get('/api/check-committee-access/:committee', authMiddleware, (req, res) => {
    const { committee } = req.params;
    if (!['iaea', 'almaty'].includes(committee)) return res.status(400).json({ error: '无效的委员会' });
    if (req.user.isAdmin) return res.json({ granted: true });
    const token = req.cookies[`committee_${committee}`];
    if (!token) return res.json({ granted: false });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.id === req.user.id && decoded.committee === committee && decoded.verified) return res.json({ granted: true });
    } catch (err) {}
    res.json({ granted: false });
});

// ========== 认证路由 ==========
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        if (!username || !password || !email) return res.status(400).json({ error: '用户名、密码和邮箱不能为空' });
        if (password.length < 6) return res.status(400).json({ error: '密码至少6位' });
        const existing = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (existing.rows.length > 0) {
            const u = existing.rows[0];
            if (u.username === username) return res.status(400).json({ error: '用户名已存在' });
            if (u.email === email) return res.status(400).json({ error: '该邮箱已被绑定' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (id, username, email, password, "isAdmin", "genevaAccess", "genevaNewsAccess", "almatyNewsAccess", "delegateId", "delegateName") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)',
            [uuidv4(), username, email, hashedPassword, false, false, false, false, null, null]
        );
        res.json({ message: '注册成功' });
    } catch (err) {
        console.error('注册失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(400).json({ error: '用户名或密码错误' });
        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: '用户名或密码错误' });
        const token = jwt.sign({
            id: user.id, username: user.username, isAdmin: user.isAdmin,
            genevaAccess: user.genevaAccess || false,
            genevaNewsAccess: user.genevaNewsAccess || false,
            almatyNewsAccess: user.almatyNewsAccess || false
        }, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.json({ message: '登录成功', isAdmin: user.isAdmin, genevaAccess: user.genevaAccess });
    } catch (err) {
        console.error('登录失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.clearCookie('committee_iaea');
    res.clearCookie('committee_almaty');
    res.json({ message: '已退出' });
});

app.get('/api/me', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
        if (result.rows.length === 0) return res.status(401).json({ error: '用户不存在' });
        const user = result.rows[0];
        res.json({
            username: user.username, email: user.email,
            isAdmin: user.isAdmin, genevaAccess: user.genevaAccess || false,
            genevaNewsAccess: user.genevaNewsAccess || false,
            almatyNewsAccess: user.almatyNewsAccess || false
        });
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

// ========== 密码找回 ==========
app.post('/api/send-code', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: '请输入邮箱' });
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(400).json({ error: '该邮箱未注册' });
    const user = result.rows[0];
    const code = String(Math.floor(100000 + Math.random() * 900000));
    verificationCodes[email] = { code, userId: user.id, expires: Date.now() + 10 * 60 * 1000 };
    try {
        await transporter.sendMail({
            from: EMAIL_FROM, to: email, subject: '苏韵模拟联合国 - 密码重置验证码',
            html: `<div style="max-width:500px;..."><h2 style="color:#8B1A2B;">苏韵模拟联合国大会</h2><p>您好，<strong>${user.username}</strong>：</p><p>您正在申请重置密码，验证码如下：</p><div style="text-align:center;font-size:32px;font-weight:bold;color:#8B1A2B;padding:20px;background:#fff;border-radius:4px;margin:20px 0;letter-spacing:8px;">${code}</div><p style="color:#888;font-size:14px;">验证码10分钟内有效，请勿透露给他人。</p></div>`
        });
        res.json({ message: '验证码已发送到您的邮箱' });
    } catch (err) { res.status(500).json({ error: '邮件发送失败，请稍后再试' }); }
});

app.post('/api/reset-password', async (req, res) => {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) return res.status(400).json({ error: '信息不完整' });
    if (newPassword.length < 6) return res.status(400).json({ error: '新密码至少6位' });
    const record = verificationCodes[email];
    if (!record) return res.status(400).json({ error: '请先获取验证码' });
    if (Date.now() > record.expires) { delete verificationCodes[email]; return res.status(400).json({ error: '验证码已过期' }); }
    if (record.code !== code) return res.status(400).json({ error: '验证码错误' });
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, record.userId]);
    delete verificationCodes[email];
    res.json({ message: '密码重置成功，请登录' });
});

// ========== 简化版：文件上传/获取/下载 ==========
// 由于代码较长，此处为精简版核心功能
// 完整功能见之前的 server.js

// ========== 议员管理 API ==========
app.get('/api/admin/users-with-delegate', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, email, "isAdmin", "genevaAccess", "genevaNewsAccess", "almatyNewsAccess", "delegateId", "delegateName" FROM users');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.put('/api/admin/users/:userId/set-delegate', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { delegateId, delegateName } = req.body;
        await pool.query('UPDATE users SET "delegateId" = $1, "delegateName" = $2 WHERE id = $3', [delegateId, delegateName, req.params.userId]);
        res.json({ message: '议员已分配' });
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.get('/api/my-delegate', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT "delegateId", "delegateName", "isAdmin" FROM users WHERE id = $1', [req.user.id]);
        if (result.rows.length === 0) return res.status(401).json({ error: '用户不存在' });
        res.json({ delegateId: result.rows[0].delegateId, delegateName: result.rows[0].delegateName, isAdmin: result.rows[0].isAdmin });
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

// ========== 投票 API ==========
app.post('/api/submit-vote', authMiddleware, async (req, res) => {
    try {
        const { voteType } = req.body;
        const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
        if (userResult.rows.length === 0) return res.status(401).json({ error: '用户不存在' });
        const user = userResult.rows[0];
        if (!user.delegateId && !user.isAdmin) return res.status(403).json({ error: '您不是议员，无权投票' });
        
        const voteResult = await pool.query('SELECT * FROM votes LIMIT 1');
        let voteData = voteResult.rows.length > 0 ? voteResult.rows[0].data : { votes: {}, history: [], currentBill: { id: 'current', text: '授权政府接受日内瓦会议达成的停战协议及印度支那和平解决方案', active: true }, completedBills: [] };
        
        const delegateKey = user.delegateId || `admin_${user.id}`;
        if (voteData.votes[delegateKey] && !user.isAdmin) return res.status(403).json({ error: '您已经投过票了' });
        
        voteData.votes[delegateKey] = { delegateName: user.delegateName || user.username, vote: voteType, timestamp: new Date().toISOString(), billId: 'current' };
        voteData.history.unshift({ delegateName: user.delegateName || user.username, vote: voteType, timestamp: new Date().toISOString(), billId: 'current' });
        if (voteData.history.length > 100) voteData.history.pop();
        
        await pool.query('DELETE FROM votes');
        await pool.query('INSERT INTO votes (data) VALUES ($1)', [voteData]);
        res.json({ message: '投票已记录', votes: voteData.votes });
    } catch (err) {
        console.error('提交投票失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.get('/api/get-votes', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM votes LIMIT 1');
        if (result.rows.length === 0) return res.json({ votes: {}, history: [], currentBill: { id: 'current', text: '授权政府接受日内瓦会议达成的停战协议及印度支那和平解决方案', active: true }, completedBills: [] });
        res.json(result.rows[0].data);
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

// ========== 总理管理 API ==========
app.get('/api/get-prime-minister', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM prime_ministers LIMIT 1');
        if (result.rows.length === 0) return res.json({ name: "约瑟夫·拉尼埃尔", party: "全国独立人士与农民中心 (CNIP)" });
        res.json(result.rows[0].data);
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.post('/api/admin/set-prime-minister', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { name, party } = req.body;
        if (!name || !party) return res.status(400).json({ error: '请填写完整信息' });
        await pool.query('DELETE FROM prime_ministers');
        await pool.query('INSERT INTO prime_ministers (data) VALUES ($1)', [JSON.stringify({ name, party, updatedAt: new Date().toISOString(), updatedBy: req.user.username })]);
        res.json({ message: `总理已更换为 ${name}（${party}）` });
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

// ========== 用户管理 ==========
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, email, "isAdmin", "genevaAccess", "genevaNewsAccess", "almatyNewsAccess" FROM users');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.put('/api/admin/users/:userId/toggle-admin', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const userResult = await pool.query('SELECT "isAdmin", username FROM users WHERE id = $1', [req.params.userId]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: '用户不存在' });
        const user = userResult.rows[0];
        if (req.params.userId === req.user.id) return res.status(400).json({ error: '不能修改自己的权限' });
        await pool.query('UPDATE users SET "isAdmin" = NOT "isAdmin" WHERE id = $1', [req.params.userId]);
        const newStatus = !user.isAdmin;
        res.json({ message: `用户 ${user.username} ${newStatus ? '已设为管理员' : '已取消管理员'}` });
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.put('/api/admin/users/:userId/toggle-geneva', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const userResult = await pool.query('SELECT "genevaAccess", username FROM users WHERE id = $1', [req.params.userId]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: '用户不存在' });
        const user = userResult.rows[0];
        await pool.query('UPDATE users SET "genevaAccess" = NOT "genevaAccess" WHERE id = $1', [req.params.userId]);
        const newStatus = !user.genevaAccess;
        res.json({ message: `用户 ${user.username} ${newStatus ? '已获得日内瓦会场权限' : '已被取消日内瓦会场权限'}` });
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.put('/api/admin/users/:userId/toggle-geneva-news', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const userResult = await pool.query('SELECT "genevaNewsAccess", username FROM users WHERE id = $1', [req.params.userId]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: '用户不存在' });
        const user = userResult.rows[0];
        await pool.query('UPDATE users SET "genevaNewsAccess" = NOT "genevaNewsAccess" WHERE id = $1', [req.params.userId]);
        const newStatus = !user.genevaNewsAccess;
        res.json({ message: `用户 ${user.username} ${newStatus ? '已获得危机联动新闻权限' : '已被取消危机联动新闻权限'}` });
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.put('/api/admin/users/:userId/toggle-almaty-news', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const userResult = await pool.query('SELECT "almatyNewsAccess", username FROM users WHERE id = $1', [req.params.userId]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: '用户不存在' });
        const user = userResult.rows[0];
        await pool.query('UPDATE users SET "almatyNewsAccess" = NOT "almatyNewsAccess" WHERE id = $1', [req.params.userId]);
        const newStatus = !user.almatyNewsAccess;
        res.json({ message: `用户 ${user.username} ${newStatus ? '已获得历史委员会新闻权限' : '已被取消历史委员会新闻权限'}` });
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.delete('/api/admin/users/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const userResult = await pool.query('SELECT username FROM users WHERE id = $1', [req.params.userId]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: '用户不存在' });
        if (req.params.userId === req.user.id) return res.status(400).json({ error: '不能删除自己' });
        await pool.query('DELETE FROM users WHERE id = $1', [req.params.userId]);
        res.json({ message: `用户 ${userResult.rows[0].username} 已删除` });
    } catch (err) {
        res.status(500).json({ error: '服务器错误' });
    }
});

// ========== 文件上传（简版核心） ==========
app.post('/api/upload/position', authMiddleware, upload.single('file'), async (req, res) => {
    try {
        const { committee } = req.body;
        if (!committee || !['iaea', 'almaty', 'geneva'].includes(committee)) return res.status(400).json({ error: '无效的委员会' });
        await pool.query(
            'INSERT INTO files (id, "originalName", "storedName", committee, type, "uploadedBy", "uploaderName", visible, "uploadTime") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            [uuidv4(), req.file.originalname, req.file.filename, committee, 'position', req.user.id, req.user.username, false, new Date().toISOString()]
        );
        res.json({ message: '立场文件上传成功' });
    } catch (err) { res.status(500).json({ error: '服务器错误' }); }
});

app.post('/api/upload/admin', authMiddleware, adminMiddleware, upload.single('file'), async (req, res) => {
    try {
        const { committee } = req.body;
        if (!committee || !['iaea', 'almaty', 'geneva'].includes(committee)) return res.status(400).json({ error: '无效的委员会' });
        const visible = req.body.visible === 'true';
        await pool.query(
            'INSERT INTO files (id, "originalName", "storedName", committee, type, "uploadedBy", "uploaderName", visible, "uploadTime") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            [uuidv4(), req.file.originalname, req.file.filename, committee, 'academic', req.user.id, req.user.username, visible, new Date().toISOString()]
        );
        res.json({ message: '学术文件上传成功', visible });
    } catch (err) { res.status(500).json({ error: '服务器错误' }); }
});

app.get('/api/files/:committee', authMiddleware, async (req, res) => {
    try {
        const { committee } = req.params;
        const result = await pool.query('SELECT * FROM files WHERE committee = $1', [committee]);
        const isAdmin = req.user.isAdmin;
        const userId = req.user.id;
        const filtered = result.rows.filter(f => {
            if (isAdmin) return true;
            if (f.type === 'academic' && f.visible) return true;
            if (f.type === 'position' && f.uploadedBy === userId) return true;
            return false;
        });
        res.json(filtered.map(f => ({ id: f.id, originalName: f.originalName, type: f.type, uploaderName: f.uploaderName, uploadTime: f.uploadTime, committee: f.committee })));
    } catch (err) { res.status(500).json({ error: '服务器错误' }); }
});

app.get('/api/download/:fileId', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM files WHERE id = $1', [req.params.fileId]);
        if (result.rows.length === 0) return res.status(404).json({ error: '文件不存在' });
        const file = result.rows[0];
        const isAdmin = req.user.isAdmin;
        const userId = req.user.id;
        const allowed = isAdmin || (file.type === 'academic' && file.visible) || (file.type === 'position' && file.uploadedBy === userId);
        if (!allowed) return res.status(403).json({ error: '无权下载' });
        res.download(path.join(UPLOADS_DIR, file.storedName), file.originalName);
    } catch (err) { res.status(500).json({ error: '服务器错误' }); }
});

// ========== 页面路由 ==========
app.get('/committees/geneva.html', authMiddleware, genevaAccessMiddleware, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'committees', 'geneva.html'));
});

app.get('/committees/parliament.html', authMiddleware, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'committees', 'parliament.html'));
});

app.listen(PORT, () => {
    console.log(`✅ 服务器已启动：http://localhost:${PORT}`);
    console.log(`📋 PostgreSQL 版服务器运行中`);
});