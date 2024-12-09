const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// 存储在线用户
const onlineUsers = new Map();

// WebSocket 连接处理
io.on('connection', (socket) => {
    console.log('用户连接成功, socket id:', socket.id);

    // 用户登录后加入
    socket.on('user_connected', (username) => {
        console.log('用户尝试连接:', username);
        onlineUsers.set(username, socket.id);
        console.log('在线用户列表:', Array.from(onlineUsers.entries()));
        // 广播更新后的在线用户列表
        const usersList = Array.from(onlineUsers.keys());
        io.emit('users_list', usersList);
    });

    // 处理私聊消息
    socket.on('private_message', async (data) => {
        const { sender, receiver, message } = data;
        console.log('收到私聊消息:', { sender, receiver, message });
        const receiverSocketId = onlineUsers.get(receiver);
        console.log('接收者socket id:', receiverSocketId);

        try {
            // 存储消息到数据库
            const result = await pool.query(
                'INSERT INTO messages (sender_username, receiver_username, content) VALUES ($1, $2, $3) RETURNING *',
                [sender, receiver, message]
            );
            console.log('消息已存储到数据库:', result.rows[0]);

            // 如果接收者在线，发送消息
            if (receiverSocketId) {
                console.log('发送消息给接收者:', receiver);
                io.to(receiverSocketId).emit('new_message', {
                    sender,
                    message,
                    timestamp: result.rows[0].created_at
                });
            } else {
                console.log('接收者不在线:', receiver);
            }
        } catch (error) {
            console.error('发送消息错误:', error);
        }
    });

    // 用
    socket.on('disconnect', () => {
        let disconnectedUser;
        for (const [username, id] of onlineUsers.entries()) {
            if (id === socket.id) {
                disconnectedUser = username;
                break;
            }
        }
        if (disconnectedUser) {
            onlineUsers.delete(disconnectedUser);
            // 广播更新后的在线用户列表
            const usersList = Array.from(onlineUsers.keys());
            io.emit('users_list', usersList);
            console.log(`${disconnectedUser} 已断开连接`);
        }
    });
});

// 数据库连接配置
const pool = new Pool({
    user: 'xlevon',
    host: '192.168.244.130',
    database: 'postgres',
    password: 'xlevon@123',
    port: 7654,
    // 添加连接池配置
    max: 20, // 最大连接数
    idleTimeoutMillis: 30000, // 连接最大空闲时间
    connectionTimeoutMillis: 2000, // 连接超时时间
    // 添加错误处理
    on: 'error',
    onError: (err, client) => {
        console.error('数据库连接池错误:', err);
    }
});

// 添加连接测试函数
async function testDatabaseConnection() {
    try {
        const client = await pool.connect();
        console.log('数据库连接测试功');
        client.release();
        return true;
    } catch (error) {
        console.error('数据库连接测试失败:', error);
        return false;
    }
}

// 在服务器启动时测��连接
testDatabaseConnection().then(success => {
    if (!success) {
        console.error('无法连接到数据库，服务器将退出');
        process.exit(1);
    }
});

// 创建用户表
async function createUsersTable() {
    try {
        // 检查表是否存在
        const tableExists = await pool.query(`
            SELECT EXISTS (
                SELECT 1 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'users'
            );
        `);

        if (!tableExists.rows[0].exists) {
            await pool.query(`
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    phone VARCHAR(11) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    avatar_url VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            console.log('用户表创建成功');
        } else {
            console.log('用户表已存在');
        }
        return true;
    } catch (error) {
        console.error('创建用户表失败:', error);
        return false;
    }
}

// 修改用户表添加头像字段
async function alterUsersTable() {
    try {
        // 检查 avatar_url 列是否存在
        const columnExists = await pool.query(`
            SELECT EXISTS (
                SELECT 1 
                FROM information_schema.columns 
                WHERE table_name = 'users' 
                AND column_name = 'avatar_url'
            );
        `);

        if (!columnExists.rows[0].exists) {
            await pool.query(`
                ALTER TABLE users 
                ADD COLUMN avatar_url VARCHAR(255)
            `);
            console.log('用户表添加 avatar_url 字段成功');
        } else {
            console.log('avatar_url 字段已存在');
        }
        return true;
    } catch (error) {
        // 如果错误是列已存在，返回成功
        if (error.code === '42701') { // PostgreSQL 错误码：列已存在
            console.log('avatar_url 字段已存在');
            return true;
        }
        console.error('修改用户表失败:', error);
        return false;
    }
}

// 创建联系人表
async function createContactsTable() {
    try {
        // 检查表是否存在
        const tableExists = await pool.query(`
            SELECT EXISTS (
                SELECT 1 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'contacts'
            );
        `);

        if (!tableExists.rows[0].exists) {
            await pool.query(`
                CREATE TABLE contacts (
                    id SERIAL PRIMARY KEY,
                    user_id VARCHAR(50) NOT NULL,
                    contact_id VARCHAR(50) NOT NULL,
                    is_blocked BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, contact_id),
                    FOREIGN KEY (user_id) REFERENCES users(username) ON DELETE CASCADE,
                    FOREIGN KEY (contact_id) REFERENCES users(username) ON DELETE CASCADE
                )
            `);
            console.log('联系人表创建成功');
        } else {
            console.log('联系人表已存在');
            // 检查是否需要添加 is_blocked 列
            const columnExists = await pool.query(`
                SELECT EXISTS (
                    SELECT 1 
                    FROM information_schema.columns 
                    WHERE table_name = 'contacts' 
                    AND column_name = 'is_blocked'
                );
            `);

            if (!columnExists.rows[0].exists) {
                await pool.query(`
                    ALTER TABLE contacts 
                    ADD COLUMN is_blocked BOOLEAN DEFAULT FALSE
                `);
                console.log('添加 is_blocked 列成功');
            }
        }
        return true;
    } catch (error) {
        // 如果错误是表已存在，返回成功
        if (error.code === '42P07') { // PostgreSQL 错误码：表已存在
            console.log('联系人表已存在，跳过创建');
            return true;
        }
        console.error('创建或修改联系人表失败:', error);
        return false;
    }
}

// 检查并添加 is_blocked 列
async function addIsBlockedColumn() {
    try {
        // 检查 is_blocked 列是否存在
        const columnExists = await pool.query(`
            SELECT EXISTS (
                SELECT 1 
                FROM information_schema.columns 
                WHERE table_name = 'contacts' 
                AND column_name = 'is_blocked'
            );
        `);

        if (!columnExists.rows[0].exists) {
            // 添加 is_blocked 列
            await pool.query(`
                ALTER TABLE contacts 
                ADD COLUMN is_blocked BOOLEAN DEFAULT FALSE;
            `);
            console.log('成功添加 is_blocked 列');
        } else {
            console.log('is_blocked 列已存在');
        }
        return true;
    } catch (error) {
        console.error('添加 is_blocked 列失败:', error);
        return false;
    }
}

// 创消息表
async function createMessagesTable() {
    try {
        // 检查表是否存在
        const tableExists = await pool.query(`
            SELECT EXISTS (
                SELECT 1 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'messages'
            );
        `);

        if (!tableExists.rows[0].exists) {
            await pool.query(`
                CREATE TABLE messages (
                    id SERIAL PRIMARY KEY,
                    sender_username VARCHAR(50) NOT NULL,
                    receiver_username VARCHAR(50) NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender_username) REFERENCES users(username) ON DELETE CASCADE,
                    FOREIGN KEY (receiver_username) REFERENCES users(username) ON DELETE CASCADE
                )
            `);
            console.log('消息表建成功');
        } else {
            console.log('消息表已存在，跳过创建');
            return true; // 表已存在也返回成功
        }
        return true;
    } catch (error) {
        // 如果错误是表已存在也返回成功
        if (error.code === '42P07') { // PostgreSQL 错误码：表已存在
            console.log('消息表已存在，跳过创建');
            return true;
        }
        console.error('创建消息表失败:', error);
        return false;
    }
}

// 初始化数据库表
async function initTables() {
    try {
        console.log('开始初始化数据库表...');
        
        // 按顺序创建表
        const userTableCreated = await createUsersTable();
        if (!userTableCreated) {
            throw new Error('用户表创建失败');
        }

        // 修改用户表添加头像字段
        const userTableAltered = await alterUsersTable();
        if (!userTableAltered) {
            throw new Error('用户表修改失败');
        }

        const contactsTableCreated = await createContactsTable();
        if (!contactsTableCreated) {
            throw new Error('联系人表创建失败');
        }

        // 添加 is_blocked 列
        const isBlockedColumnAdded = await addIsBlockedColumn();
        if (!isBlockedColumnAdded) {
            throw new Error('添加 is_blocked 列失败');
        }

        const messagesTableCreated = await createMessagesTable();
        if (!messagesTableCreated) {
            throw new Error('消息表创建失败');
        }

        console.log('所有表初始化完成');
        return true;
    } catch (error) {
        console.error('初始化数据库表失败:', error);
        return false;
    }
}

// 在服务器启动初始化表
(async () => {
    try {
        const success = await initTables();
        if (!success) {
            console.error('数据库初始化失败');
            process.exit(1);
        }
    } catch (error) {
        console.error('服务器启动错误:', error);
        process.exit(1);
    }
})();

// 定义默认头像路径
const DEFAULT_AVATAR = '/images/23.jpg';

// 注册接口
app.post('/register', async (req, res) => {
    const { username, phone, password } = req.body;
    let client;

    try {
        // 获取连接
        client = await pool.connect();

        // 开始事务
        await client.query('BEGIN');

        // 检查手机号是否已存在
        const existingUser = await client.query(
            'SELECT * FROM users WHERE phone = $1',
            [phone]
        );

        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.json({ success: false, message: '该手机号已被注册' });
        }

        // 密码加密
        const hashedPassword = await bcrypt.hash(password, 10);

        // 插入新用户，设置默认头像
        await client.query(
            'INSERT INTO users (username, phone, password, avatar_url) VALUES ($1, $2, $3, $4)',
            [username, phone, hashedPassword, DEFAULT_AVATAR]
        );

        // 提交事务
        await client.query('COMMIT');

        res.json({ 
            success: true, 
            message: '注册成功',
            username: username,
            avatarUrl: DEFAULT_AVATAR
        });
    } catch (error) {
        // 如果有错误，回滚事务
        if (client) {
            await client.query('ROLLBACK');
        }
        console.error('注册错误:', error);
        res.json({ 
            success: false, 
            message: '注册失败: ' + (error.detail || error.message || '未知错误')
        });
    } finally {
        // 确保释放连接
        if (client) {
            client.release();
        }
    }
});

// 登录接口
app.post('/login', async (req, res) => {
    const { phone, password } = req.body;

    try {
        // 通过手机号查找用户
        const result = await pool.query(
            'SELECT username, password, avatar_url FROM users WHERE phone = $1',
            [phone]
        );

        if (result.rows.length === 0) {
            return res.json({ success: false, message: '手机号或密码错误' });
        }

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);

        if (match) {
            res.json({ 
                success: true, 
                message: '登录成功',
                username: user.username,
                avatarUrl: user.avatar_url || DEFAULT_AVATAR
            });
        } else {
            res.json({ success: false, message: '手机号或密码错误' });
        }
    } catch (error) {
        console.error('登录错误:', error);
        res.json({ success: false, message: '登录失败，请重试' });
    }
});

// 添加联系人接口
app.post('/contacts/add', async (req, res) => {
    const { username, contactUsername } = req.body;
    console.log('添加联系人请求:', { username, contactUsername });

    // 验证输入
    if (!username || !contactUsername) {
        return res.status(400).json({ 
            success: false, 
            message: '用户名和联系人用户名不能为空' 
        });
    }

    // 检查是否添加自己
    if (username === contactUsername) {
        return res.status(400).json({ 
            success: false, 
            message: '不能添加自己为联系人' 
        });
    }

    try {
        // 检查要添加的用户是否存在
        const userExists = await pool.query(
            'SELECT username FROM users WHERE username = $1',
            [contactUsername]
        );
        console.log('查询用户结果:', userExists.rows);

        if (userExists.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: '用户不存在' 
            });
        }

        // 检查是否已经联系人
        const isContact = await pool.query(
            'SELECT * FROM contacts WHERE user_id = $1 AND contact_id = $2',
            [username, contactUsername]
        );
        console.log('检查联系人结果:', isContact.rows);

        if (isContact.rows.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: '该用户已经是你的联系人' 
            });
        }

        // 添加联系人（双向添加）
        await pool.query(
            'INSERT INTO contacts (user_id, contact_id) VALUES ($1, $2), ($2, $1)',
            [username, contactUsername]
        );
        console.log('联系人���加成功');

        res.json({ success: true, message: '添加联系人成功' });
    } catch (error) {
        console.error('添加联系人错误:', error);
        // 返回更详细的错误信息
        res.status(500).json({ 
            success: false, 
            message: '添加联系人失败',
            error: error.message 
        });
    }
});

// 获取联系人列表接口
app.get('/contacts/:username', async (req, res) => {
    try {
        const { username } = req.params;
        console.log('获取联系人列表请求:', username);

        const result = await pool.query(
            `SELECT u.username, COALESCE(u.avatar_url, $2) as avatar_url, c.is_blocked
            FROM users u 
            INNER JOIN contacts c ON u.username = c.contact_id 
            WHERE c.user_id = $1`,
            [username, DEFAULT_AVATAR]
        );

        console.log('查询结果:', result.rows);
        const contacts = result.rows || [];
        res.json(contacts);
    } catch (error) {
        console.error('获取联系人列表失败:', error);
        res.status(500).json([]);
    }
});

// 添加一个路由来处理 chat.html 的请求
app.get('/chat', (req, res) => {
    res.sendFile(__dirname + '/public/chat.html');
});

// 获取聊天历史
app.get('/messages/:user1/:user2', async (req, res) => {
    try {
        const { user1, user2 } = req.params;
        const result = await pool.query(
            `SELECT * FROM messages 
            WHERE (sender_username = $1 AND receiver_username = $2)
            OR (sender_username = $2 AND receiver_username = $1)
            ORDER BY created_at ASC`,
            [user1, user2]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('获取聊天历史失败:', error);
        res.status(500).json({ message: '获取聊天历史失败' });
    }
});

// 配置文件上传
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/avatars')
    },
    filename: function (req, file, cb) {
        // 使用时间戳确保文件名唯一
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'avatar-' + req.body.username + '-' + uniqueSuffix + path.extname(file.originalname))
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB
    },
    fileFilter: function (req, file, cb) {
        // 只允许上传图片
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('只允许上传图片文件'));
        }
        cb(null, true);
    }
});

// 更新头像接口
app.post('/update-avatar', upload.single('avatar'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: '请选择要上传的图片'
            });
        }

        const username = req.body.username;
        const avatarUrl = '/uploads/avatars/' + req.file.filename;
        
        // 获取用户当前的头像URL
        const result = await pool.query(
            'SELECT avatar_url FROM users WHERE username = $1',
            [username]
        );

        // 如果有旧头像，删除它
        if (result.rows[0]?.avatar_url) {
            const oldAvatarPath = path.join(__dirname, 'public', result.rows[0].avatar_url);
            if (fs.existsSync(oldAvatarPath) && !oldAvatarPath.includes('23.jpg')) {
                fs.unlinkSync(oldAvatarPath);
            }
        }

        // 更新数据库中的头像URL
        await pool.query(
            'UPDATE users SET avatar_url = $1 WHERE username = $2',
            [avatarUrl, username]
        );

        res.json({
            success: true,
            message: '头像更新成功',
            avatarUrl: avatarUrl
        });
    } catch (error) {
        console.error('更新头像失败:', error);
        // 如果更新失败��删除上传的文件
        if (req.file) {
            const filePath = path.join(__dirname, 'public', '/uploads/avatars/', req.file.filename);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        }
        res.status(500).json({
            success: false,
            message: '头像更新失败: ' + error.message
        });
    }
});

// 更新用户名接口
app.post('/update-username', async (req, res) => {
    const { oldUsername, newUsername } = req.body;
    let client;

    try {
        client = await pool.connect();
        await client.query('BEGIN');

        // 检查新用户名是否已存在
        const existingUser = await client.query(
            'SELECT username FROM users WHERE username = $1',
            [newUsername]
        );

        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.json({
                success: false,
                message: '该用户名已被使用'
            });
        }

        // 更新用户名
        await client.query(
            'UPDATE users SET username = $1 WHERE username = $2',
            [newUsername, oldUsername]
        );

        // 更新相关表中的用户名
        await client.query(
            'UPDATE contacts SET user_id = $1 WHERE user_id = $2',
            [newUsername, oldUsername]
        );
        await client.query(
            'UPDATE contacts SET contact_id = $1 WHERE contact_id = $2',
            [newUsername, oldUsername]
        );
        await client.query(
            'UPDATE messages SET sender_username = $1 WHERE sender_username = $2',
            [newUsername, oldUsername]
        );
        await client.query(
            'UPDATE messages SET receiver_username = $1 WHERE receiver_username = $2',
            [newUsername, oldUsername]
        );

        await client.query('COMMIT');

        res.json({
            success: true,
            message: '用户名更新成功'
        });
    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
        console.error('更新用户名失败:', error);
        res.status(500).json({
            success: false,
            message: '用户名更新失败'
        });
    } finally {
        if (client) {
            client.release();
        }
    }
});

// 修改密码接口
app.post('/api/change-password', async (req, res) => {
    const { username, currentPassword, newPassword } = req.body;

    try {
        // 验证当前密码
        const result = await pool.query(
            'SELECT password FROM users WHERE username = $1',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: '用户不存在' });
        }

        const isValidPassword = await bcrypt.compare(
            currentPassword,
            result.rows[0].password
        );

        if (!isValidPassword) {
            return res.status(400).json({ message: '当前密码错误' });
        }

        // 加密新密码
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // 更新密码
        await pool.query(
            'UPDATE users SET password = $1 WHERE username = $2',
            [hashedNewPassword, username]
        );

        res.json({ message: '密码修改成功' });
    } catch (error) {
        console.error('修改密码错误:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 删除消息接口
app.post('/api/delete-messages', async (req, res) => {
    const { username, contactUsername, deleteType } = req.body;

    if (!username || !contactUsername) {
        return res.status(400).json({
            success: false,
            message: '缺少必要参数'
        });
    }

    try {
        let result;
        if (deleteType === 'all') {
            // 删除所有消息
            result = await pool.query(
                `DELETE FROM messages 
                WHERE (sender_username = $1 AND receiver_username = $2)
                OR (sender_username = $2 AND receiver_username = $1)
                RETURNING id`,
                [username, contactUsername]
            );
        } else if (deleteType === 'selected') {
            // 由于目前没有实现消息选择功能，暂时和删除全部一样
            result = await pool.query(
                `DELETE FROM messages 
                WHERE (sender_username = $1 AND receiver_username = $2)
                OR (sender_username = $2 AND receiver_username = $1)
                RETURNING id`,
                [username, contactUsername]
            );
        }

        res.json({
            success: true,
            message: '消息删除成功',
            count: result.rowCount
        });
    } catch (error) {
        console.error('删除消息错误:', error);
        res.status(500).json({
            success: false,
            message: '删除消息失败'
        });
    }
});

// 删除联系人接口
app.post('/api/delete-contact', async (req, res) => {
    const { username, contactUsername } = req.body;
    let client;

    try {
        client = await pool.connect();
        await client.query('BEGIN');

        // 删除联系人关系（双向）
        await client.query(
            `DELETE FROM contacts 
            WHERE (user_id = $1 AND contact_id = $2)
            OR (user_id = $2 AND contact_id = $1)`,
            [username, contactUsername]
        );

        // 删除相关的聊天记录
        await client.query(
            `DELETE FROM messages 
            WHERE (sender_username = $1 AND receiver_username = $2)
            OR (sender_username = $2 AND receiver_username = $1)`,
            [username, contactUsername]
        );

        await client.query('COMMIT');

        res.json({
            success: true,
            message: '联系人删除成功'
        });
    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
        console.error('删除联系人错误:', error);
        res.status(500).json({
            success: false,
            message: '删除联系人失败'
        });
    } finally {
        if (client) {
            client.release();
        }
    }
});

// 屏蔽联系人接口
app.post('/api/toggle-block-contact', async (req, res) => {
    const { username, contactUsername } = req.body;

    if (!username || !contactUsername) {
        return res.status(400).json({
            success: false,
            message: '缺少必要参数'
        });
    }

    try {
        // 检查是否已经屏蔽
        const result = await pool.query(
            'SELECT is_blocked FROM contacts WHERE user_id = $1 AND contact_id = $2',
            [username, contactUsername]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: '联系人不存在'
            });
        }

        const isCurrentlyBlocked = result.rows[0].is_blocked || false;
        
        // 更新屏蔽状态
        await pool.query(
            'UPDATE contacts SET is_blocked = $1 WHERE user_id = $2 AND contact_id = $3',
            [!isCurrentlyBlocked, username, contactUsername]
        );

        res.json({
            success: true,
            message: isCurrentlyBlocked ? '已取消屏蔽' : '已屏蔽该联系人',
            isBlocked: !isCurrentlyBlocked
        });
    } catch (error) {
        console.error('屏蔽联系人失败:', error);
        res.status(500).json({
            success: false,
            message: '操作失败，请重试'
        });
    }
});

const PORT = 3001;
server.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);
}); 