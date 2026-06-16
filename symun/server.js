const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'suyun_mun_2027_secret_change_this';

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const FILES_FILE = path.join(DATA_DIR, 'files.json');
const FINANCE_FILE = path.join(DATA_DIR, 'finance.json');
const QUIZ_FILE = path.join(DATA_DIR, 'quiz.json');
const NEWS_FILE = path.join(DATA_DIR, 'news.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

const COMMITTEE_PASSWORDS = {
    iaea: '123456',
    almaty: '1991'
};

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

[DATA_DIR, UPLOADS_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(FILES_FILE)) fs.writeFileSync(FILES_FILE, '[]');
if (!fs.existsSync(FINANCE_FILE)) fs.writeFileSync(FINANCE_FILE, '[]');
if (!fs.existsSync(QUIZ_FILE)) fs.writeFileSync(QUIZ_FILE, '[]');
if (!fs.existsSync(NEWS_FILE)) fs.writeFileSync(NEWS_FILE, '[]');

function readJSON(file) { return JSON.parse(fs.readFileSync(file, 'utf-8')); }
function writeJSON(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

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

function genevaAccessMiddleware(req, res, next) {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(401).json({ error: '用户不存在' });
    if (user.isAdmin) return next();
    if (!user.genevaAccess) return res.status(403).json({ error: '您尚未获得日内瓦会场的访问权限，请联系管理员' });
    next();
}

function newsUploadMiddleware(req, res, next) {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(401).json({ error: '用户不存在' });
    if (user.isAdmin) return next();
    const { committee } = req.body;
    if (committee === 'geneva' && user.genevaNewsAccess) return next();
    if (committee === 'almaty' && user.almatyNewsAccess) return next();
    return res.status(403).json({ error: '您没有该委员会的新闻上传权限，请联系管理员' });
}

// ========== 委员会密码验证 ==========
app.post('/api/verify-committee-password', authMiddleware, (req, res) => {
    const { committee, password } = req.body;
    if (!committee || !['iaea', 'almaty'].includes(committee)) {
        return res.status(400).json({ error: '无效的委员会' });
    }
    if (req.user.isAdmin) {
        return res.json({ verified: true, message: '管理员自动通过' });
    }
    if (password === COMMITTEE_PASSWORDS[committee]) {
        const token = jwt.sign({
            id: req.user.id,
            committee: committee,
            verified: true
        }, JWT_SECRET, { expiresIn: '24h' });
        res.cookie(`committee_${committee}`, token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
        return res.json({ verified: true, message: '验证通过' });
    }
    res.status(403).json({ verified: false, error: '密码错误' });
});

app.get('/api/check-committee-access/:committee', authMiddleware, (req, res) => {
    const { committee } = req.params;
    if (!['iaea', 'almaty'].includes(committee)) {
        return res.status(400).json({ error: '无效的委员会' });
    }
    if (req.user.isAdmin) return res.json({ granted: true });
    const token = req.cookies[`committee_${committee}`];
    if (!token) return res.json({ granted: false });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.id === req.user.id && decoded.committee === committee && decoded.verified) {
            return res.json({ granted: true });
        }
    } catch (err) {}
    res.json({ granted: false });
});

// ========== 认证路由 ==========
app.post('/api/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password || !email) return res.status(400).json({ error: '用户名、密码和邮箱不能为空' });
    if (password.length < 6) return res.status(400).json({ error: '密码至少6位' });
    const users = readJSON(USERS_FILE);
    if (users.find(u => u.username === username)) return res.status(400).json({ error: '用户名已存在' });
    if (users.find(u => u.email === email)) return res.status(400).json({ error: '该邮箱已被绑定' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: uuidv4(), username, email, password: hashedPassword,
        isAdmin: false, genevaAccess: false, genevaNewsAccess: false, almatyNewsAccess: false,
        delegateId: null, delegateName: null
    };
    users.push(newUser);
    writeJSON(USERS_FILE, users);
    res.json({ message: '注册成功' });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).json({ error: '用户名或密码错误' });
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
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.clearCookie('committee_iaea');
    res.clearCookie('committee_almaty');
    res.json({ message: '已退出' });
});

app.get('/api/me', authMiddleware, (req, res) => {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(401).json({ error: '用户不存在' });
    res.json({
        username: user.username, email: user.email,
        isAdmin: user.isAdmin, genevaAccess: user.genevaAccess || false,
        genevaNewsAccess: user.genevaNewsAccess || false,
        almatyNewsAccess: user.almatyNewsAccess || false
    });
});

app.post('/api/send-code', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: '请输入邮箱' });
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).json({ error: '该邮箱未注册' });
    const code = String(Math.floor(100000 + Math.random() * 900000));
    verificationCodes[email] = { code, userId: user.id, expires: Date.now() + 10 * 60 * 1000 };
    try {
        await transporter.sendMail({
            from: EMAIL_FROM, to: email, subject: '苏韵模拟联合国 - 密码重置验证码',
            html: `<div style="max-width:500px;margin:auto;padding:30px;background:#faf8f5;border-radius:8px;font-family:'Microsoft YaHei',sans-serif;">
                <h2 style="color:#8B1A2B;text-align:center;">苏韵模拟联合国大会</h2>
                <p>您好，<strong>${user.username}</strong>：</p><p>您正在申请重置密码，验证码如下：</p>
                <div style="text-align:center;font-size:32px;font-weight:bold;color:#8B1A2B;padding:20px;background:#fff;border-radius:4px;margin:20px 0;letter-spacing:8px;">${code}</div>
                <p style="color:#888;font-size:14px;">验证码10分钟内有效，请勿透露给他人。</p></div>`
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
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === record.userId);
    if (!user) return res.status(400).json({ error: '用户不存在' });
    user.password = await bcrypt.hash(newPassword, 10);
    writeJSON(USERS_FILE, users);
    delete verificationCodes[email];
    res.json({ message: '密码重置成功，请登录' });
});

// ========== 委员会文件上传 ==========
app.post('/api/upload/position', authMiddleware, upload.single('file'), (req, res) => {
    const { committee } = req.body;
    if (!committee || !['iaea', 'almaty', 'geneva'].includes(committee)) return res.status(400).json({ error: '无效的委员会标识' });
    const files = readJSON(FILES_FILE);
    const newFile = { id: uuidv4(), originalName: req.file.originalname, storedName: req.file.filename, committee, type: 'position', uploadedBy: req.user.id, uploaderName: req.user.username, visible: false, uploadTime: new Date().toISOString() };
    files.push(newFile);
    writeJSON(FILES_FILE, files);
    res.json({ message: '立场文件上传成功，仅您和管理员可见' });
});

app.post('/api/upload/admin', authMiddleware, adminMiddleware, upload.single('file'), (req, res) => {
    const { committee } = req.body;
    if (!committee || !['iaea', 'almaty', 'geneva'].includes(committee)) return res.status(400).json({ error: '无效的委员会标识' });
    const visible = req.body.visible === 'true';
    const files = readJSON(FILES_FILE);
    const newFile = { id: uuidv4(), originalName: req.file.originalname, storedName: req.file.filename, committee, type: 'academic', uploadedBy: req.user.id, uploaderName: req.user.username, visible, uploadTime: new Date().toISOString() };
    files.push(newFile);
    writeJSON(FILES_FILE, files);
    res.json({ message: '学术文件上传成功', visible });
});

app.get('/api/files/:committee', authMiddleware, (req, res) => {
    const { committee } = req.params;
    if (!['iaea', 'almaty', 'geneva'].includes(committee)) return res.status(400).json({ error: '无效的委员会' });
    const files = readJSON(FILES_FILE).filter(f => f.committee === committee);
    const isAdmin = req.user.isAdmin;
    const userId = req.user.id;
    const filtered = files.filter(f => {
        if (isAdmin) return true;
        if (f.type === 'academic' && f.visible) return true;
        if (f.type === 'position' && f.uploadedBy === userId) return true;
        return false;
    });
    res.json(filtered.map(f => ({ id: f.id, originalName: f.originalName, type: f.type, uploaderName: f.uploaderName, uploadTime: f.uploadTime, committee: f.committee })));
});

app.get('/api/download/:fileId', authMiddleware, (req, res) => {
    const files = readJSON(FILES_FILE);
    const file = files.find(f => f.id === req.params.fileId);
    if (!file) return res.status(404).json({ error: '文件不存在' });
    const isAdmin = req.user.isAdmin;
    const userId = req.user.id;
    const allowed = isAdmin || (file.type === 'academic' && file.visible) || (file.type === 'position' && file.uploadedBy === userId);
    if (!allowed) return res.status(403).json({ error: '无权下载此文件' });
    res.download(path.join(UPLOADS_DIR, file.storedName), file.originalName);
});

app.put('/api/files/:fileId/visibility', authMiddleware, adminMiddleware, (req, res) => {
    const files = readJSON(FILES_FILE);
    const file = files.find(f => f.id === req.params.fileId);
    if (!file) return res.status(404).json({ error: '文件不存在' });
    file.visible = !file.visible;
    writeJSON(FILES_FILE, files);
    res.json({ message: `文件已${file.visible ? '公开' : '隐藏'}` });
});

// ========== 学术测验 ==========
app.post('/api/upload/quiz', authMiddleware, upload.single('file'), (req, res) => {
    const { committee } = req.body;
    if (!committee || !['iaea', 'almaty', 'geneva'].includes(committee)) return res.status(400).json({ error: '无效的委员会标识' });
    const quizzes = readJSON(QUIZ_FILE);
    const newQuiz = { id: uuidv4(), originalName: req.file.originalname, storedName: req.file.filename, committee, uploadedBy: req.user.id, uploaderName: req.user.username, uploadTime: new Date().toISOString() };
    quizzes.push(newQuiz);
    writeJSON(QUIZ_FILE, quizzes);
    res.json({ message: '学术测验上传成功' });
});

app.get('/api/quiz/:committee', authMiddleware, (req, res) => {
    const { committee } = req.params;
    if (!['iaea', 'almaty', 'geneva'].includes(committee)) return res.status(400).json({ error: '无效的委员会' });
    const quizzes = readJSON(QUIZ_FILE).filter(q => q.committee === committee);
    res.json(quizzes.map(q => ({ id: q.id, originalName: q.originalName, uploaderName: q.uploaderName, uploadTime: q.uploadTime })));
});

app.get('/api/download/quiz/:fileId', authMiddleware, (req, res) => {
    const quizzes = readJSON(QUIZ_FILE);
    const file = quizzes.find(q => q.id === req.params.fileId);
    if (!file) return res.status(404).json({ error: '文件不存在' });
    res.download(path.join(UPLOADS_DIR, file.storedName), file.originalName);
});

app.delete('/api/quiz/:fileId', authMiddleware, adminMiddleware, (req, res) => {
    let quizzes = readJSON(QUIZ_FILE);
    const file = quizzes.find(q => q.id === req.params.fileId);
    if (!file) return res.status(404).json({ error: '文件不存在' });
    quizzes = quizzes.filter(q => q.id !== req.params.fileId);
    writeJSON(QUIZ_FILE, quizzes);
    res.json({ message: '学术测验已删除' });
});

// ========== 新闻 ==========
app.post('/api/upload/news', authMiddleware, newsUploadMiddleware, upload.single('file'), (req, res) => {
    const { committee, title } = req.body;
    if (!committee || !['almaty', 'geneva'].includes(committee)) return res.status(400).json({ error: '无效的委员会标识' });
    const news = readJSON(NEWS_FILE);
    const newNews = { id: uuidv4(), title: title || req.file.originalname, originalName: req.file.originalname, storedName: req.file.filename, committee, uploadedBy: req.user.id, uploaderName: req.user.username, uploadTime: new Date().toISOString() };
    news.push(newNews);
    writeJSON(NEWS_FILE, news);
    res.json({ message: '新闻上传成功' });
});

app.get('/api/news/:committee', authMiddleware, (req, res) => {
    const { committee } = req.params;
    if (!['almaty', 'geneva'].includes(committee)) return res.status(400).json({ error: '无效的委员会' });
    const news = readJSON(NEWS_FILE).filter(n => n.committee === committee);
    res.json(news.map(n => ({ id: n.id, title: n.title, originalName: n.originalName, uploaderName: n.uploaderName, uploadTime: n.uploadTime })));
});

app.get('/api/download/news/:fileId', authMiddleware, (req, res) => {
    const news = readJSON(NEWS_FILE);
    const file = news.find(n => n.id === req.params.fileId);
    if (!file) return res.status(404).json({ error: '文件不存在' });
    res.download(path.join(UPLOADS_DIR, file.storedName), file.originalName);
});

app.delete('/api/news/:fileId', authMiddleware, adminMiddleware, (req, res) => {
    let news = readJSON(NEWS_FILE);
    const file = news.find(n => n.id === req.params.fileId);
    if (!file) return res.status(404).json({ error: '文件不存在' });
    news = news.filter(n => n.id !== req.params.fileId);
    writeJSON(NEWS_FILE, news);
    res.json({ message: '新闻已删除' });
});

// ========== 财务公示 ==========
app.post('/api/upload/finance', authMiddleware, adminMiddleware, upload.single('file'), (req, res) => {
    const { title } = req.body;
    const finances = readJSON(FINANCE_FILE);
    const newFinance = { id: uuidv4(), title: title || req.file.originalname, originalName: req.file.originalname, storedName: req.file.filename, uploadedBy: req.user.id, uploaderName: req.user.username, uploadTime: new Date().toISOString() };
    finances.push(newFinance);
    writeJSON(FINANCE_FILE, finances);
    res.json({ message: '财务文件上传成功' });
});

app.get('/api/finance', (req, res) => {
    const finances = readJSON(FINANCE_FILE);
    res.json(finances.map(f => ({ id: f.id, title: f.title, originalName: f.originalName, uploaderName: f.uploaderName, uploadTime: f.uploadTime })));
});

app.get('/api/download/finance/:fileId', (req, res) => {
    const finances = readJSON(FINANCE_FILE);
    const file = finances.find(f => f.id === req.params.fileId);
    if (!file) return res.status(404).json({ error: '文件不存在' });
    res.download(path.join(UPLOADS_DIR, file.storedName), file.originalName);
});

app.delete('/api/finance/:fileId', authMiddleware, adminMiddleware, (req, res) => {
    let finances = readJSON(FINANCE_FILE);
    const file = finances.find(f => f.id === req.params.fileId);
    if (!file) return res.status(404).json({ error: '文件不存在' });
    finances = finances.filter(f => f.id !== req.params.fileId);
    writeJSON(FINANCE_FILE, finances);
    res.json({ message: '财务文件已删除' });
});

// ========== 日内瓦会场 ==========
app.get('/committees/geneva.html', authMiddleware, genevaAccessMiddleware, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'committees', 'geneva.html'));
});

// ========== 法国国民议会会场 ==========
app.get('/committees/parliament.html', authMiddleware, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'committees', 'parliament.html'));
});

// ========== 总理管理 API ==========
app.get('/api/get-prime-minister', authMiddleware, (req, res) => {
    try {
        const PM_FILE = path.join(DATA_DIR, 'prime-minister.json');
        if (!fs.existsSync(PM_FILE)) {
            const defaultPm = { name: "约瑟夫·拉尼埃尔", party: "全国独立人士与农民中心 (CNIP)", updatedAt: new Date().toISOString() };
            writeJSON(PM_FILE, defaultPm);
            return res.json(defaultPm);
        }
        const pmData = JSON.parse(fs.readFileSync(PM_FILE, 'utf-8'));
        res.json(pmData);
    } catch (err) {
        console.error('获取总理信息失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.post('/api/admin/set-prime-minister', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const { name, party } = req.body;
        if (!name || !party) {
            return res.status(400).json({ error: '请填写总理姓名和党派' });
        }
        
        const PM_FILE = path.join(DATA_DIR, 'prime-minister.json');
        const newPmData = {
            name: name,
            party: party,
            updatedAt: new Date().toISOString(),
            updatedBy: req.user.username
        };
        writeJSON(PM_FILE, newPmData);
        
        const CENSURE_FILE = path.join(DATA_DIR, 'censure.json');
        if (fs.existsSync(CENSURE_FILE)) {
            let censureData = JSON.parse(fs.readFileSync(CENSURE_FILE, 'utf-8'));
            censureData.history = censureData.history || [];
            censureData.history.unshift({
                delegateName: "系统",
                vote: "政府更迭",
                timestamp: new Date().toISOString(),
                action: `总理更换为：${name}（${party}），由管理员 ${req.user.username} 执行`
            });
            writeJSON(CENSURE_FILE, censureData);
        }
        
        res.json({ message: `总理已更换为 ${name}（${party}）`, primeMinister: newPmData });
    } catch (err) {
        console.error('更换总理失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

// ========== 议员管理 API ==========
app.get('/api/admin/users-with-delegate', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const users = readJSON(USERS_FILE);
        const result = users.map(u => ({
            id: u.id,
            username: u.username,
            email: u.email,
            isAdmin: u.isAdmin || false,
            genevaAccess: u.genevaAccess || false,
            genevaNewsAccess: u.genevaNewsAccess || false,
            almatyNewsAccess: u.almatyNewsAccess || false,
            delegateId: u.delegateId || null,
            delegateName: u.delegateName || null
        }));
        res.json(result);
    } catch (err) {
        console.error('获取用户列表失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.put('/api/admin/users/:userId/set-delegate', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const { delegateId, delegateName } = req.body;
        const users = readJSON(USERS_FILE);
        const user = users.find(u => u.id === req.params.userId);
        if (!user) return res.status(404).json({ error: '用户不存在' });
        
        user.delegateId = delegateId;
        user.delegateName = delegateName;
        writeJSON(USERS_FILE, users);
        res.json({ message: `用户 ${user.username} 已设置为议员：${delegateName || '无'}` });
    } catch (err) {
        console.error('设置议员失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.get('/api/my-delegate', authMiddleware, (req, res) => {
    try {
        const users = readJSON(USERS_FILE);
        const user = users.find(u => u.id === req.user.id);
        if (!user) return res.status(401).json({ error: '用户不存在' });
        res.json({
            delegateId: user.delegateId || null,
            delegateName: user.delegateName || null,
            isAdmin: user.isAdmin || false
        });
    } catch (err) {
        console.error('获取议员信息失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

// ========== 普通议案投票 API ==========
app.post('/api/submit-vote', authMiddleware, (req, res) => {
    try {
        const { voteType, billId } = req.body;
        const users = readJSON(USERS_FILE);
        const user = users.find(u => u.id === req.user.id);
        if (!user) return res.status(401).json({ error: '用户不存在' });
        
        if (!user.delegateId && !user.isAdmin) {
            return res.status(403).json({ error: '您不是议员，无权投票' });
        }
        
        const VOTES_FILE = path.join(DATA_DIR, 'votes.json');
        if (!fs.existsSync(VOTES_FILE)) fs.writeFileSync(VOTES_FILE, JSON.stringify({ 
            votes: {}, 
            history: [],
            currentBill: { id: 'current', text: '授权政府接受日内瓦会议达成的停战协议及印度支那和平解决方案', active: true },
            completedBills: []
        }));
        let votesData = JSON.parse(fs.readFileSync(VOTES_FILE, 'utf-8'));
        
        const delegateKey = user.delegateId || `admin_${user.id}`;
        
        if (votesData.votes[delegateKey] && !user.isAdmin) {
            return res.status(403).json({ error: '您已经投过票了，不能重复投票' });
        }
        
        votesData.votes[delegateKey] = {
            delegateName: user.delegateName || user.username,
            vote: voteType,
            timestamp: new Date().toISOString(),
            billId: billId || 'current'
        };
        
        votesData.history.unshift({
            delegateName: user.delegateName || user.username,
            vote: voteType,
            timestamp: new Date().toISOString(),
            billId: billId || 'current'
        });
        if (votesData.history.length > 100) votesData.history.pop();
        
        const allDelegateIds = [
            "雅克·杜克洛", "莫里斯·托雷斯", "居伊·摩勒", "保罗·拉马迪埃",
            "乔治·比多", "罗伯特·舒曼", "皮埃尔·孟戴斯-弗朗斯", "埃德加·富尔",
            "安托万·皮奈", "约瑟夫·拉尼埃尔", "雅克·苏斯戴尔",
            "其它议员1", "其它议员2"
        ];
        
        const votedCount = Object.keys(votesData.votes).length;
        const allVoted = votedCount >= allDelegateIds.length;
        
        let result = null;
        if (allVoted) {
            let yesCount = 0, noCount = 0, abstainCount = 0;
            for (const [delegateId, voteInfo] of Object.entries(votesData.votes)) {
                if (voteInfo.vote === 'yes') yesCount++;
                else if (voteInfo.vote === 'no') noCount++;
                else if (voteInfo.vote === 'abstain') abstainCount++;
            }
            
            const passed = yesCount > noCount;
            result = {
                passed: passed,
                yesCount: yesCount,
                noCount: noCount,
                abstainCount: abstainCount,
                billText: votesData.currentBill?.text || '当前议案'
            };
            
            votesData.completedBills = votesData.completedBills || [];
            votesData.completedBills.unshift({
                id: Date.now(),
                text: votesData.currentBill?.text || '当前议案',
                result: passed ? '通过' : '不通过',
                yesCount: yesCount,
                noCount: noCount,
                abstainCount: abstainCount,
                timestamp: new Date().toISOString()
            });
            if (votesData.completedBills.length > 20) votesData.completedBills.pop();
            
            votesData.votes = {};
            votesData.currentBill = {
                id: 'current',
                text: '',
                active: false
            };
            
            writeJSON(VOTES_FILE, votesData);
        } else {
            writeJSON(VOTES_FILE, votesData);
        }
        
        res.json({ 
            message: '投票已记录', 
            votes: votesData.votes,
            allVoted: allVoted,
            result: result,
            currentBill: votesData.currentBill
        });
    } catch (err) {
        console.error('提交投票失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.get('/api/get-votes', authMiddleware, (req, res) => {
    try {
        const VOTES_FILE = path.join(DATA_DIR, 'votes.json');
        if (!fs.existsSync(VOTES_FILE)) {
            return res.json({ 
                votes: {}, 
                history: [],
                currentBill: { id: 'current', text: '授权政府接受日内瓦会议达成的停战协议及印度支那和平解决方案', active: true },
                completedBills: []
            });
        }
        const votesData = JSON.parse(fs.readFileSync(VOTES_FILE, 'utf-8'));
        res.json(votesData);
    } catch (err) {
        console.error('获取投票失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.post('/api/set-current-bill', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const { billText } = req.body;
        const VOTES_FILE = path.join(DATA_DIR, 'votes.json');
        if (!fs.existsSync(VOTES_FILE)) {
            fs.writeFileSync(VOTES_FILE, JSON.stringify({ votes: {}, history: [], currentBill: {}, completedBills: [] }));
        }
        let votesData = JSON.parse(fs.readFileSync(VOTES_FILE, 'utf-8'));
        
        votesData.currentBill = {
            id: 'current',
            text: billText,
            active: true,
            startTime: new Date().toISOString()
        };
        votesData.votes = {};
        
        writeJSON(VOTES_FILE, votesData);
        res.json({ message: '议案已更新', currentBill: votesData.currentBill });
    } catch (err) {
        console.error('设置议案失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.post('/api/admin/reset-votes', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const VOTES_FILE = path.join(DATA_DIR, 'votes.json');
        let votesData = { 
            votes: {}, 
            history: [],
            currentBill: { id: 'current', text: '新议案', active: true },
            completedBills: []
        };
        writeJSON(VOTES_FILE, votesData);
        res.json({ message: '所有投票已重置' });
    } catch (err) {
        console.error('重置投票失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.post('/api/admin/reset-single-vote', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const { delegateId } = req.body;
        if (!delegateId) return res.status(400).json({ error: '缺少议员ID' });
        
        const VOTES_FILE = path.join(DATA_DIR, 'votes.json');
        if (!fs.existsSync(VOTES_FILE)) return res.json({ message: '无投票记录' });
        
        let votesData = JSON.parse(fs.readFileSync(VOTES_FILE, 'utf-8'));
        
        if (votesData.votes[delegateId]) {
            delete votesData.votes[delegateId];
            votesData.history.unshift({
                delegateName: delegateId,
                vote: 'reset',
                timestamp: new Date().toISOString(),
                action: '管理员重置了该议员的投票',
                proxyBy: req.user.username
            });
            writeJSON(VOTES_FILE, votesData);
        }
        
        res.json({ message: `已重置 ${delegateId} 的投票` });
    } catch (err) {
        console.error('重置单个投票失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.post('/api/admin/proxy-vote', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const { delegateId, voteType, billId } = req.body;
        if (!delegateId || !voteType) return res.status(400).json({ error: '缺少必要参数' });
        
        const validDelegateIds = [
            "雅克·杜克洛", "莫里斯·托雷斯", "居伊·摩勒", "保罗·拉马迪埃",
            "乔治·比多", "罗伯特·舒曼", "皮埃尔·孟戴斯-弗朗斯", "埃德加·富尔",
            "安托万·皮奈", "约瑟夫·拉尼埃尔", "雅克·苏斯戴尔",
            "其它议员1", "其它议员2"
        ];
        
        if (!validDelegateIds.includes(delegateId)) return res.status(400).json({ error: '无效的议员ID' });
        
        const VOTES_FILE = path.join(DATA_DIR, 'votes.json');
        if (!fs.existsSync(VOTES_FILE)) fs.writeFileSync(VOTES_FILE, JSON.stringify({ votes: {}, history: [], currentBill: { text: '授权政府接受日内瓦会议达成的停战协议及印度支那和平解决方案' }, completedBills: [] }));
        let votesData = JSON.parse(fs.readFileSync(VOTES_FILE, 'utf-8'));
        
        votesData.votes[delegateId] = {
            delegateName: delegateId,
            vote: voteType,
            timestamp: new Date().toISOString(),
            billId: billId || 'current',
            proxyBy: req.user.username
        };
        
        votesData.history.unshift({
            delegateName: delegateId,
            vote: voteType,
            timestamp: new Date().toISOString(),
            billId: billId || 'current',
            proxyBy: req.user.username
        });
        if (votesData.history.length > 100) votesData.history.pop();
        
        const allDelegateIds = [
            "雅克·杜克洛", "莫里斯·托雷斯", "居伊·摩勒", "保罗·拉马迪埃",
            "乔治·比多", "罗伯特·舒曼", "皮埃尔·孟戴斯-弗朗斯", "埃德加·富尔",
            "安托万·皮奈", "约瑟夫·拉尼埃尔", "雅克·苏斯戴尔",
            "其它议员1", "其它议员2"
        ];
        
        const votedCount = Object.keys(votesData.votes).length;
        const allVoted = votedCount >= allDelegateIds.length;
        
        let result = null;
        if (allVoted) {
            let yesCount = 0, noCount = 0, abstainCount = 0;
            for (const [delegateId, voteInfo] of Object.entries(votesData.votes)) {
                if (voteInfo.vote === 'yes') yesCount++;
                else if (voteInfo.vote === 'no') noCount++;
                else if (voteInfo.vote === 'abstain') abstainCount++;
            }
            
            const passed = yesCount > noCount;
            result = {
                passed: passed,
                yesCount: yesCount,
                noCount: noCount,
                abstainCount: abstainCount,
                billText: votesData.currentBill?.text || '当前议案'
            };
            
            votesData.completedBills = votesData.completedBills || [];
            votesData.completedBills.unshift({
                id: Date.now(),
                text: votesData.currentBill?.text || '当前议案',
                result: passed ? '通过' : '不通过',
                yesCount: yesCount,
                noCount: noCount,
                abstainCount: abstainCount,
                timestamp: new Date().toISOString()
            });
            if (votesData.completedBills.length > 20) votesData.completedBills.pop();
            
            votesData.votes = {};
            votesData.currentBill = {
                id: 'current',
                text: '',
                active: false
            };
        }
        
        writeJSON(VOTES_FILE, votesData);
        res.json({ 
            message: `已为 ${delegateId} 记录${voteType === 'yes' ? '赞成' : (voteType === 'no' ? '反对' : '弃权')}投票`, 
            votes: votesData.votes,
            allVoted: allVoted,
            result: result
        });
    } catch (err) {
        console.error('管理员代投失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

// ========== 不信任案投票 API ==========
app.get('/api/get-censure', authMiddleware, (req, res) => {
    try {
        const CENSURE_FILE = path.join(DATA_DIR, 'censure.json');
        if (!fs.existsSync(CENSURE_FILE)) {
            return res.json({ 
                active: false, 
                votes: { yes: [], no: [], abstain: [] }, 
                history: [],
                completedCensures: []
            });
        }
        const censureData = JSON.parse(fs.readFileSync(CENSURE_FILE, 'utf-8'));
        res.json(censureData);
    } catch (err) {
        console.error('获取不信任案状态失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.post('/api/submit-censure-vote', authMiddleware, (req, res) => {
    try {
        const { voteType } = req.body;
        const users = readJSON(USERS_FILE);
        const user = users.find(u => u.id === req.user.id);
        if (!user) return res.status(401).json({ error: '用户不存在' });
        
        if (!user.delegateId && !user.isAdmin) return res.status(403).json({ error: '您不是议员，无权投票' });
        
        const CENSURE_FILE = path.join(DATA_DIR, 'censure.json');
        if (!fs.existsSync(CENSURE_FILE)) {
            fs.writeFileSync(CENSURE_FILE, JSON.stringify({ 
                active: true, 
                votes: { yes: [], no: [], abstain: [] }, 
                history: [],
                completedCensures: []
            }));
        }
        let censureData = JSON.parse(fs.readFileSync(CENSURE_FILE, 'utf-8'));
        
        if (!censureData.active) {
            censureData.active = true;
            censureData.votes = { yes: [], no: [], abstain: [] };
        }
        
        const delegateKey = user.delegateId || `admin_${user.id}`;
        const delegateName = user.delegateName || user.username;
        
        censureData.votes.yes = censureData.votes.yes.filter(id => id !== delegateKey);
        censureData.votes.no = censureData.votes.no.filter(id => id !== delegateKey);
        censureData.votes.abstain = censureData.votes.abstain.filter(id => id !== delegateKey);
        
        if (voteType === 'yes') censureData.votes.yes.push(delegateKey);
        else if (voteType === 'no') censureData.votes.no.push(delegateKey);
        else if (voteType === 'abstain') censureData.votes.abstain.push(delegateKey);
        
        censureData.history.unshift({
            delegateName: delegateName,
            vote: voteType,
            timestamp: new Date().toISOString()
        });
        if (censureData.history.length > 100) censureData.history.pop();
        
        const allDelegateIds = [
            "雅克·杜克洛", "莫里斯·托雷斯", "居伊·摩勒", "保罗·拉马迪埃",
            "乔治·比多", "罗伯特·舒曼", "皮埃尔·孟戴斯-弗朗斯", "埃德加·富尔",
            "安托万·皮奈", "约瑟夫·拉尼埃尔", "雅克·苏斯戴尔",
            "其它议员1", "其它议员2"
        ];
        
        const totalDelegates = allDelegateIds.length;
        const votedCount = censureData.votes.yes.length + censureData.votes.no.length + censureData.votes.abstain.length;
        const allVoted = votedCount >= totalDelegates;
        
        let result = null;
        if (allVoted) {
            const getWeight = (id) => {
                const weightMap = {
                    "雅克·杜克洛": 51, "莫里斯·托雷斯": 51,
                    "居伊·摩勒": 53, "保罗·拉马迪埃": 53,
                    "乔治·比多": 44, "罗伯特·舒曼": 44,
                    "皮埃尔·孟戴斯-弗朗斯": 50, "埃德加·富尔": 50,
                    "安托万·皮奈": 47, "约瑟夫·拉尼埃尔": 47,
                    "雅克·苏斯戴尔": 121,
                    "其它议员1": 7, "其它议员2": 7
                };
                return weightMap[id] || 0;
            };
            
            let yesWeight = 0, noWeight = 0, abstainWeight = 0;
            censureData.votes.yes.forEach(id => { yesWeight += getWeight(id); });
            censureData.votes.no.forEach(id => { noWeight += getWeight(id); });
            censureData.votes.abstain.forEach(id => { abstainWeight += getWeight(id); });
            
            const passed = yesWeight >= 313;
            result = {
                passed: passed,
                yesWeight: yesWeight,
                noWeight: noWeight,
                abstainWeight: abstainWeight
            };
            
            censureData.completedCensures = censureData.completedCensures || [];
            censureData.completedCensures.unshift({
                id: Date.now(),
                result: passed ? '通过' : '不通过',
                yesWeight: yesWeight,
                noWeight: noWeight,
                abstainWeight: abstainWeight,
                timestamp: new Date().toISOString()
            });
            if (censureData.completedCensures.length > 20) censureData.completedCensures.pop();
            
            censureData.active = false;
            censureData.votes = { yes: [], no: [], abstain: [] };
            
            writeJSON(CENSURE_FILE, censureData);
        } else {
            writeJSON(CENSURE_FILE, censureData);
        }
        
        res.json({ 
            message: '不信任案投票已记录', 
            votes: censureData.votes,
            allVoted: allVoted,
            result: result
        });
    } catch (err) {
        console.error('提交不信任案投票失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.post('/api/admin/proxy-censure-vote', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const { delegateId, voteType } = req.body;
        if (!delegateId || !voteType) return res.status(400).json({ error: '缺少必要参数' });
        
        const CENSURE_FILE = path.join(DATA_DIR, 'censure.json');
        if (!fs.existsSync(CENSURE_FILE)) {
            fs.writeFileSync(CENSURE_FILE, JSON.stringify({ active: true, votes: { yes: [], no: [], abstain: [] }, history: [], completedCensures: [] }));
        }
        let censureData = JSON.parse(fs.readFileSync(CENSURE_FILE, 'utf-8'));
        
        if (!censureData.active) {
            censureData.active = true;
            censureData.votes = { yes: [], no: [], abstain: [] };
        }
        
        censureData.votes.yes = censureData.votes.yes.filter(id => id !== delegateId);
        censureData.votes.no = censureData.votes.no.filter(id => id !== delegateId);
        censureData.votes.abstain = censureData.votes.abstain.filter(id => id !== delegateId);
        
        if (voteType === 'yes') censureData.votes.yes.push(delegateId);
        else if (voteType === 'no') censureData.votes.no.push(delegateId);
        else if (voteType === 'abstain') censureData.votes.abstain.push(delegateId);
        
        censureData.history.unshift({
            delegateName: delegateId,
            vote: voteType,
            timestamp: new Date().toISOString(),
            proxyBy: req.user.username
        });
        if (censureData.history.length > 100) censureData.history.pop();
        
        const allDelegateIds = [
            "雅克·杜克洛", "莫里斯·托雷斯", "居伊·摩勒", "保罗·拉马迪埃",
            "乔治·比多", "罗伯特·舒曼", "皮埃尔·孟戴斯-弗朗斯", "埃德加·富尔",
            "安托万·皮奈", "约瑟夫·拉尼埃尔", "雅克·苏斯戴尔",
            "其它议员1", "其它议员2"
        ];
        
        const totalDelegates = allDelegateIds.length;
        const votedCount = censureData.votes.yes.length + censureData.votes.no.length + censureData.votes.abstain.length;
        const allVoted = votedCount >= totalDelegates;
        
        let result = null;
        if (allVoted) {
            const getWeight = (id) => {
                const weightMap = {
                    "雅克·杜克洛": 51, "莫里斯·托雷斯": 51,
                    "居伊·摩勒": 53, "保罗·拉马迪埃": 53,
                    "乔治·比多": 44, "罗伯特·舒曼": 44,
                    "皮埃尔·孟戴斯-弗朗斯": 50, "埃德加·富尔": 50,
                    "安托万·皮奈": 47, "约瑟夫·拉尼埃尔": 47,
                    "雅克·苏斯戴尔": 121,
                    "其它议员1": 7, "其它议员2": 7
                };
                return weightMap[id] || 0;
            };
            
            let yesWeight = 0, noWeight = 0, abstainWeight = 0;
            censureData.votes.yes.forEach(id => { yesWeight += getWeight(id); });
            censureData.votes.no.forEach(id => { noWeight += getWeight(id); });
            censureData.votes.abstain.forEach(id => { abstainWeight += getWeight(id); });
            
            const passed = yesWeight >= 313;
            result = {
                passed: passed,
                yesWeight: yesWeight,
                noWeight: noWeight,
                abstainWeight: abstainWeight
            };
            
            censureData.completedCensures = censureData.completedCensures || [];
            censureData.completedCensures.unshift({
                id: Date.now(),
                result: passed ? '通过' : '不通过',
                yesWeight: yesWeight,
                noWeight: noWeight,
                abstainWeight: abstainWeight,
                timestamp: new Date().toISOString(),
                proxyBy: req.user.username
            });
            if (censureData.completedCensures.length > 20) censureData.completedCensures.pop();
            
            censureData.active = false;
            censureData.votes = { yes: [], no: [], abstain: [] };
            
            writeJSON(CENSURE_FILE, censureData);
        } else {
            writeJSON(CENSURE_FILE, censureData);
        }
        
        res.json({ 
            message: `已为 ${delegateId} 记录不信任案${voteType === 'yes' ? '赞成' : (voteType === 'no' ? '反对' : '弃权')}投票`,
            allVoted: allVoted,
            result: result
        });
    } catch (err) {
        console.error('管理员代投不信任案失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

app.post('/api/admin/reset-censure', authMiddleware, adminMiddleware, (req, res) => {
    try {
        const CENSURE_FILE = path.join(DATA_DIR, 'censure.json');
        const newCensureData = { 
            active: false, 
            votes: { yes: [], no: [], abstain: [] }, 
            history: [],
            completedCensures: []
        };
        writeJSON(CENSURE_FILE, newCensureData);
        res.json({ message: '不信任案已重置' });
    } catch (err) {
        console.error('重置不信任案失败:', err);
        res.status(500).json({ error: '服务器错误' });
    }
});

// ========== 用户管理 ==========
app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
    const users = readJSON(USERS_FILE).map(u => ({
        id: u.id, username: u.username, email: u.email,
        isAdmin: u.isAdmin, genevaAccess: u.genevaAccess || false,
        genevaNewsAccess: u.genevaNewsAccess || false,
        almatyNewsAccess: u.almatyNewsAccess || false
    }));
    res.json(users);
});

app.put('/api/admin/users/:userId/toggle-admin', authMiddleware, adminMiddleware, (req, res) => {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.params.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    if (user.id === req.user.id) return res.status(400).json({ error: '不能修改自己的权限' });
    user.isAdmin = !user.isAdmin;
    writeJSON(USERS_FILE, users);
    res.json({ message: `用户 ${user.username} ${user.isAdmin ? '已设为管理员' : '已取消管理员'}` });
});

app.put('/api/admin/users/:userId/toggle-geneva', authMiddleware, adminMiddleware, (req, res) => {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.params.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    user.genevaAccess = !user.genevaAccess;
    writeJSON(USERS_FILE, users);
    res.json({ message: `用户 ${user.username} ${user.genevaAccess ? '已获得日内瓦会场权限' : '已被取消日内瓦会场权限'}` });
});

app.put('/api/admin/users/:userId/toggle-geneva-news', authMiddleware, adminMiddleware, (req, res) => {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.params.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    user.genevaNewsAccess = !user.genevaNewsAccess;
    writeJSON(USERS_FILE, users);
    res.json({ message: `用户 ${user.username} ${user.genevaNewsAccess ? '已获得危机联动新闻权限' : '已被取消危机联动新闻权限'}` });
});

app.put('/api/admin/users/:userId/toggle-almaty-news', authMiddleware, adminMiddleware, (req, res) => {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.params.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    user.almatyNewsAccess = !user.almatyNewsAccess;
    writeJSON(USERS_FILE, users);
    res.json({ message: `用户 ${user.username} ${user.almatyNewsAccess ? '已获得历史委员会新闻权限' : '已被取消历史委员会新闻权限'}` });
});

app.delete('/api/admin/users/:userId', authMiddleware, adminMiddleware, (req, res) => {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.params.userId);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    if (user.id === req.user.id) return res.status(400).json({ error: '不能删除自己' });
    writeJSON(USERS_FILE, users.filter(u => u.id !== req.params.userId));
    writeJSON(FILES_FILE, readJSON(FILES_FILE).filter(f => f.uploadedBy !== req.params.userId));
    res.json({ message: `用户 ${user.username} 已删除` });
});

app.listen(PORT, () => {
    console.log(`✅ 服务器已启动：http://localhost:${PORT}`);
    console.log(`📋 议会投票系统API已就绪`);
    console.log(`   总理管理API: /api/get-prime-minister, /api/admin/set-prime-minister`);
});