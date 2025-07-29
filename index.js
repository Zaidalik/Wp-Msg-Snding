require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const rimraf = require('rimraf'); 
const cors = require('cors');
const db = require('./db');
// Your DB module, must export a query method or similar

const {
    default: makeWASocket,
    useMultiFileAuthState,
    DisconnectReason
} = require('@whiskeysockets/baileys');

const app = express();
app.use(cookieParser()); // ✅ Parse cookies
app.use(express.json()); // ✅ Parse JSON body
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'jdiji762oadmd23456416asi215dm123', // use a strong secret in production
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
         maxAge: 2 * 60 * 60 * 1000, // 2 hours
        sameSite: 'lax',        // adjust to 'none' if using HTTPS with different domain
        secure: false           // set to true if using HTTPS
    }
}));

app.use(cors({
    origin: 'http://localhost:3000', // your frontend URL
    credentials: true               // allow cookies across origins
}));
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
    console.log('Session on', req.path, ':', req.session);
    next();
});

// Global vars 
const connectingFlags = {};
const latestQRs = {}; // Keyed by userId
const sendMessageSock = {};

//function getAuthFolder(userId) {
//    return path.join(__dirname, 'auth', `user_${userId}`);
//}
function getAuthFolder(userId) {
    const folderPath = path.join(__dirname, 'auth', `user_${userId}`);
    if (!fs.existsSync(folderPath)) {
        fs.mkdirSync(folderPath, { recursive: true });  // ✅ create if it doesn't exist
        console.log(`📁 Created auth folder for user ${userId}`);
    }
    return folderPath;
}
const userSockets = {}; // 🧠 Track each user's WhatsApp connection

let connecting = false; // Prevent multiple simultaneous connections

// Middleware to protect routes
function requireLogin(req, res, next) {
    if (req.session && req.session.loggedIn) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Helper to clean phone number for WhatsApp JID
function cleanPhone(rawPhone) {
    if (!rawPhone) return null;
    let cleaned = rawPhone.replace(/\D/g, '');
    if (cleaned.startsWith('0')) cleaned = '92' + cleaned.slice(1);
    return cleaned;
}



app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


app.post('/login', async (req, res) => {
    const { FirstName, password } = req.body;
    //console.log("Login request received with FirstName:", FirstName, "and password:", password);

    try {
        const [rows] = await db.query('SELECT * FROM Auth.users WHERE firstname = ?', [FirstName]);

        if (rows.length === 0) {
            return res.status(401).send('Invalid username or password');
        }
const user = rows[0];
console.log("Fetched user from DB:", user);

if (!password || !user.Password) {
    console.error("Missing password or hashed password.");
    return res.status(400).send('Invalid request');
}

const match = await bcrypt.compare(password, user.Password);
if (!match) {
    return res.status(401).send('Invalid username or password');
}

        req.session.loggedIn = true;
        req.session.user = {
            id: user.id,
            name: user.FirstName,
            credits: user.Credits,
            TotalMesseges: user.TotalMesseges
        };

        req.session.save(async (err) => {
            if (err) {
                console.error('❌ Session save error:', err);
                return res.status(500).send('Session error');
            }

            userSockets[user.id] = await startSock(user.id);
            res.redirect('/dashboard');
        });


    } catch (err) {
        console.error("Login error:", err);
        res.status(500).send('🔥 Server error');
    }
});


app.post('/Signup', async (req, res) => {
    try {
        const { FirstName, LastName, Email, Password, PhoneNumber } = req.body;

        // Check if user already exists by email
        const [existingUser] = await db.query('SELECT * FROM auth.users WHERE Email = ?', [Email]);


        if (existingUser.length > 0) {
            return res.status(400).send('User with this email already exists');
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(Password, 10);

        // Insert new user, id is auto-increment assumed, Credits default to 0
        const result = await db.query(
            `INSERT INTO auth.users (FirstName, LastName, Email, Password, PhoneNumber, Credits,TotalMesseges) VALUES (?, ?, ?, ?, ?, ?,?)`,
            [FirstName, LastName, Email, hashedPassword, PhoneNumber, 20,0]
        );

        res.status(201).send('User registered successfully');
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal server error');
    }
});

app.get('/api/custom-message', requireLogin, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const [rows] = await db.query('SELECT CustomMessage FROM Auth.Users WHERE id = ?', [userId]);

        if (!rows.length) {
            return res.status(404).send('Message not found');
        }

        res.json({ message: rows[0].CustomMessage || '' });
    } catch (err) {
        console.error('❌ Error fetching custom message:', err);
        res.status(500).send('Server error');
    }
});
app.post('/save-message', requireLogin, async (req, res) => {
    const userId = req.session.user.id;
    const message = req.body.message;

    try {
        await db.query('UPDATE Auth.Users SET CustomMessage = ? WHERE id = ?', [message, userId]);
        res.send('✅ Custom message saved!');
    } catch (err) {
        console.error('❌ Failed to save custom message:', err);
        res.status(500).send('Server error');
    }
});

app.get('/customMessage.html', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'customMessage.html'));
});


app.get('/logout/:userId', async (req, res) => {
    const userId = req.params.userId;
    const sessionPath = `./auth/user_${userId}`;
    const sock = userSockets[userId];

    if (!sock) {
        return res.status(400).send('❌ WhatsApp not connected for this user.');
    }

    try {
        // ✅ Logout via Baileys
        await sock.logout();

        // ✅ Delete folder after logout
        const fs = require('fs/promises');
        const exists = await fs.access(sessionPath).then(() => true).catch(() => false);
        if (exists) {
            await fs.rm(sessionPath, { recursive: true, force: true });
        }

        // ✅ Clean up sockets
        delete userSockets[userId];
        delete sendMessageSock[userId];
        delete latestQRs[userId];
        delete activeSockets[userId];

        res.send('✅ WhatsApp session logged out and session files deleted');
    } catch (err) {
        console.error('❌ Error during logout:', err);
        res.status(500).send('❌ Failed to logout WhatsApp session');
    }
});


// App-only logout (does not logout WhatsApp)
app.get('/app-logout', (req, res) => {
    if (!req.session) return res.redirect('/login');

    req.session.destroy(err => {
        if (err) {
            console.error('Session destroy error:', err);
            return res.status(500).send('Error logging out');
        }
        console.log('🚪 User logged out of app (WhatsApp session still active)');
        res.redirect('/login');
    });
});

app.get('/qr.html', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'qr.html'));
});
app.get('/index', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});



// Optional: Redirect "/" to "/index"
app.get('/', (req, res) => {
    res.redirect('/index');
});


app.get('/dashboard',requireLogin,  (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});



app.get('/api/qr', (req, res) => {
    const userId = req.session?.user?.id;

    if (!userId) {
        return res.status(401).send({ error: 'Not logged in' });
    }

    const connected = activeSockets[userId] === true;
    const qr = latestQRs[userId];

    return res.json({ qr, connected });
});





app.get('/api/user-info', (req, res) => {


    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Not logged in' });
    }
    res.json({
        userId: req.session.user.id,      // ✅ include userId
        username: req.session.user.name,
        credits: req.session.user.credits,
        TotalMesseges: req.session.user.TotalMesseges
    });


});
app.post('/send/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const order = req.body;
        console.log('Session on /send:', req.session);

        if (!userId) return res.status(401).send('❌ Unauthorized: user not logged in.');

        // ✅ Extract and clean phone number
        let rawPhone = order.shipping_address?.phone || order.customer?.phone;
        if (!rawPhone) return res.status(400).send('❌ Phone number missing');

        let cleanedPhone = rawPhone.replace(/\D/g, '');
        if (cleanedPhone.startsWith('0')) {
            cleanedPhone = '92' + cleanedPhone.slice(1);
        }
        const jid = `${cleanedPhone}@s.whatsapp.net`;

let userSock = userSockets[userId];

if (!userSock || !activeSockets[userId]) {

    console.log(`🔁 WhatsApp socket not connected. Attempting reconnect for user ${userId}...`);

    await startSock(userId);

    const maxWait = 15000;
    const start = Date.now();
    while (!activeSockets[userId] && Date.now() - start < maxWait) {
        await new Promise(res => setTimeout(res, 500));
    }

    userSock = userSockets[userId];

    if (!userSock || !activeSockets[userId]) {
        // 🟡 Queue the message before responding
        if (!pendingMessages[userId]) {
            pendingMessages[userId] = [];
        }
        pendingMessages[userId].push({ jid, content: { text: message } });

        console.log(`🕒 Message queued for user ${userId} due to socket being unavailable.`);
        return res.status(202).send('🕒 WhatsApp not connected. Message has been queued for retry after login.');
    }
}



        // ✅ Fetch Credits, CustomMessage, and PhoneNumber
        const [userResults] = await db.query(
            'SELECT Credits, CustomMessage, PhoneNumber FROM Auth.Users WHERE id = ?',
            [userId]
        );
        const user = userResults?.[0];

        if (!user || user.Credits <= 0) {
            return res.status(403).send('❌ Not enough credits to send a message.');
        }

        // ✅ Prepare values for replacement
        const firstName = order.shipping_address?.first_name || '';
        const lastName = order.shipping_address?.last_name || '';
        const fullName = `${firstName} ${lastName}`.trim();
        const StoreName = order.line_items?.[0]?.vendor || '';
        const orderNumber = order.name?.replace('#', '') || '0000';
        const totalPrice = order.current_total_price || '0.00';
        const currency = order.currency || 'PKR';
        const addressLine1 = order.shipping_address?.address1 || '';
        const addressLine2 = order.shipping_address?.address2 || '';
        const fullAddress = `${addressLine1}\n${addressLine2}`;
        const supportNumber = user.PhoneNumber || '03273627796';

        const replacements = {
            firstName,
            lastName,
            fullName,
            orderNumber,
            totalPrice,
            currency,
            rawPhone,
            addressLine1,
            addressLine2,
            fullAddress,
            supportNumber,
            StoreName
        };

        // ✅ Use custom message if available
        let template = user.CustomMessage ||
            `Dear {fullName}, I am from Wazap. Please confirm your Order {orderNumber}, if yes then your parcel will be delivered to you in 5 to 6 Days.\n\n` +
            `📍 Please Confirm your Address:\n{fullAddress}\n` +
            `📞 {rawPhone}\n\n` +
            `💵 Please Keep {currency} {totalPrice} ready and pay at delivery.\n\n` +
            `❓ If any problem occurs or you need our help, you can contact us on our main Number: {supportNumber}\n\n` +
            `Thank you for Ordering 👍`;

        // ✅ Replace placeholders in template
        Object.entries(replacements).forEach(([key, value]) => {
            template = template.replace(new RegExp(`{${key}}`, 'g'), value);
        });

        const message = template;

        // ✅ Send message via socket
        try {
    if (!activeSockets[userId]) {
        queueMessage(userId, { jid, content: { text: message } });
        return res.status(202).send('🔁 Socket not ready, message queued.');
    }

    await userSock.sendMessage(jid, { text: message });
    await db.query('UPDATE Auth.Users SET Credits = Credits - 1 , TotalMesseges = TotalMesseges + 1   WHERE id = ?', [userId]);

    res.status(200).send('✅ Message sent and credit deducted!');
} catch (err) {
    console.error('❌ Failed to send message:', err);
    queueMessage(userId, { jid, content: { text: message } });
    res.status(500).send('❌ Failed to send, message queued for retry.');
}


    } catch (err) {
        console.error('❌ Error in /send:', err);
        res.status(500).send('❌ Internal server error');
    }
});
 
const pendingMessages = {}; // userId: [messages]

function queueMessage(userId, msg) {
  if (!pendingMessages[userId]) pendingMessages[userId] = [];
  pendingMessages[userId].push(msg);
}
async function flushPendingMessages(userId, sock) {
  if (!pendingMessages[userId] || pendingMessages[userId].length === 0) return;

  console.log(`📨 Flushing ${pendingMessages[userId].length} queued messages for user ${userId}`);

  const messagesToSend = [...pendingMessages[userId]];
  pendingMessages[userId] = []; // Clear queue first to avoid duplicates

  for (const msg of messagesToSend) {
    try {
      await sock.sendMessage(msg.jid, msg.content);
      console.log(`✅ Retried message sent to ${msg.jid} for user ${userId}`);
    } catch (err) {
      console.error(`❌ Failed to resend message to ${msg.jid} for user ${userId}:`, err);
      queueMessage(userId, msg); // Re-queue it if it fails
    }
  }
}


// 🧠 Store active sockets and connection flags per user
const activeSockets = {};

async function startSock(userId, customPath = null) {
    // ⛔ Prevent double connection attempts per user
    if (connectingFlags[userId]) {
        console.log(`⚠️ Already connecting for user ${userId}, skipping...`);
        return;
    }

    connectingFlags[userId] = true;

    try {
        console.log(`🔁 Initializing WhatsApp socket for user ${userId}...`);
        const authFolder = customPath || path.join(__dirname, 'auth', `user_${userId}`);
        if (!fs.existsSync(authFolder)) {
            fs.mkdirSync(authFolder, { recursive: true });
            console.log(`📁 Created auth folder for user ${userId}`);
        }

        const { state, saveCreds } = await useMultiFileAuthState(authFolder);

        const sock = makeWASocket({
            auth: state,
            browser: ['Chrome', 'Windows', '10']
        });

        // Store the socket
        userSockets[userId] = sock;

        // Save credentials on update
        sock.ev.on('creds.update', saveCreds);

        // Handle connection events
        sock.ev.on('connection.update', (update) => {
            const { connection, lastDisconnect, qr } = update;

            if (qr) {
                latestQRs[userId] = qr;
                console.log(`📸 New QR code generated for user ${userId}`);
            }

            if (connection === 'open') {
                console.log(`✅ WhatsApp connected for user ${userId}`);

                activeSockets[userId] = true;                // ✅ Mark socket active
                userSockets[userId] = sock;                  // ✅ Store socket reference
                sendMessageSock[userId] = sock;              // ✅ Store for messaging
                delete latestQRs[userId];                    // ✅ Clear QR

                flushPendingMessages(userId, sock);          // ✅ Resend suspended messages
            }

            if (connection === 'close') {
                const statusCode = lastDisconnect?.error?.output?.statusCode;
                const loggedOut = statusCode === DisconnectReason.loggedOut;

                console.log(`❌ WhatsApp connection closed for user ${userId}. Status code:`, statusCode);

                // Cleanup on disconnect
                delete activeSockets[userId];
                delete userSockets[userId];
                delete sendMessageSock[userId];

                if (loggedOut) {
                    console.log(`🚨 Logged out for user ${userId}, deleting auth data...`);
                    rimraf.sync(authFolder);                  // Delete session
                    delete latestQRs[userId];
                    startSock(userId).catch(console.error);   // Reinit session
                } else {
                    console.log(`🔁 Reconnecting user ${userId} in 5 seconds...`);
                    setTimeout(() => startSock(userId).catch(console.error), 5000);
                }
            }
        });

        return sock;

    } catch (err) {
        console.error(`❌ Failed to start WhatsApp socket for user ${userId}:`, err);
    } finally {
        connectingFlags[userId] = false;
    }
}




// Start server and WhatsApp connection
(async () => {
    try {
        
    } catch (err) {
        console.error('❌ Initial WhatsApp connect failed:', err);
    }
})();

app.listen(process.env.PORT || 3000, () => {
    console.log(`🚀 Server running at http://localhost:${process.env.PORT || 3000}`);
});
