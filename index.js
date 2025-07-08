require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const rimraf = require('rimraf');
const path = require('path');
const cors = require('cors');
const db = require('./db'); // Your DB module, must export a query method or similar

const {
    default: makeWASocket,
    useMultiFileAuthState,
    DisconnectReason
} = require('@whiskeysockets/baileys');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser()); // ✅ Parse cookies
app.use(express.json()); // ✅ Parse JSON body
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'jdiji762oadmd23456416asi215dm123', // use a strong secret in production
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        maxAge: 30 * 60 * 1000, // 30 minutes
        sameSite: 'lax',        // adjust to 'none' if using HTTPS with different domain
        secure: false           // set to true if using HTTPS
    }
}));

app.use(cors({
    origin: 'http://localhost:3000', // your frontend URL
    credentials: true               // allow cookies across origins
}));


app.use((req, res, next) => {
    console.log('Session on', req.path, ':', req.session);
    next();
});

// Global vars
let sock = null;       // WhatsApp socket instance
let latestQR = null;
const authFolder = path.resolve(__dirname, 'auth_data');
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
    res.redirect('/login.html');
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
app.post('/login', async (req, res) => {
    const { FirstName, password } = req.body;
    console.log("Login request received with FirstName:", FirstName, "and password:", password);

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
    credits: user.Credits
};


res.redirect('/qr.html');

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
            `INSERT INTO auth.users (FirstName, LastName, Email, Password, PhoneNumber, Credits) VALUES (?, ?, ?, ?, ?, ?)`,
            [FirstName, LastName, Email, hashedPassword, PhoneNumber, 20]
        );

        res.status(201).send('User registered successfully');
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal server error');
    }
});

app.get('/logout', (req, res) => {
    if (!req.session) return res.redirect('/login');

    req.session.destroy(err => {
        if (err) return res.send('❌ Error logging out');

        (async () => {
            if (sock) {
                try {
                    await sock.logout();
                } catch (e) {
                    console.error('WhatsApp logout error:', e.message);
                }
            }

            rimraf.sync(authFolder);

            console.log('🔁 Restarting WhatsApp socket...');
            startSock().catch(console.error);

            res.redirect('/login');
        })();
    });

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
    res.sendFile(path.join(__dirname,'public', 'customMessage.html'));
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
    res.sendFile(path.join(__dirname,'public', 'qr.html'));
});

app.get('/api/qr', (req, res) => {
    if (sock && sock.user) {
        // Connected, no QR needed
        return res.json({ qr: null, connected: true });
    }
    return res.json({ qr: latestQR, connected: false });
});



app.get('/api/user-info', (req, res) => {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    res.json({
        userId: req.session.user.id,      // ✅ include userId
        username: req.session.user.name,
        credits: req.session.user.credits
    });
});



app.post('/send/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const order = req.body;
        console.log('Session on /send:', req.session);

        if (!userId) return res.status(401).send('❌ Unauthorized: user not logged in.');

        // Extract and clean phone number
        let rawPhone = order.shipping_address?.phone || order.customer?.phone;
        if (!rawPhone) return res.status(400).send('❌ Phone number missing');

        let cleanedPhone = rawPhone.replace(/\D/g, '');
        if (cleanedPhone.startsWith('0')) {
            cleanedPhone = '92' + cleanedPhone.slice(1);
        }
        const jid = `${cleanedPhone}@s.whatsapp.net`;

        if (!sock || sock.user === undefined) {
            return res.status(503).send('❌ WhatsApp not connected.');
        }

        // ✅ Check credits
        const [userData] = await db.query('SELECT Credits, CustomMessage,PhoneNumber FROM Auth.Users WHERE id = ?', [userId]);
        const user = userData?.[0];

        if (!user || user.Credits <= 0) {
            return res.status(403).send('❌ Not enough credits to send a message.');
        }

        // ✅ Prepare values to replace
        const firstName = order.shipping_address?.first_name || '';
        const lastName = order.shipping_address?.last_name || '';
        const fullName = `${firstName} ${lastName}`.trim();
        const orderNumber = order.name?.replace('#', '') || '0000';
        const totalPrice = order.current_total_price || '0.00';
        const currency = order.currency || 'PKR';
        const addressLine1 = order.shipping_address?.address1 || '';
        const addressLine2 = order.shipping_address?.address2 || '';
        const fullAddress = `${addressLine1}\n${addressLine2}`;
        const supportNumber = user.PhoneNumber;

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
            supportNumber
        };

        // ✅ Use custom message or default one
        let template = user.CustomMessage || 
            `Dear {fullName}, I am Syed from 📦. Please confirm your Order {orderNumber}, if yes then your parcel will be delivered to you in 5 to 6 Days.\n\n` +
            `📍 Please Confirm your Address:\n{fullAddress}\n` +
            `📞 {rawPhone}\n\n` +
            `💵 Please Keep {currency} {totalPrice} ready and pay at delivery.\n\n` +
            `❓ If any problem occurs or you need our help, you can contact us on our main Number: {supportNumber}\n\n` +
            `Thank you for Ordering 👍`;

        // ✅ Replace placeholders
        Object.entries(replacements).forEach(([key, val]) => {
            const regex = new RegExp(`{${key}}`, 'g');
            template = template.replace(regex, val);
        });

        const message = template;

        // ✅ Send message
        await sock.sendMessage(jid, { text: message });

        // ✅ Deduct credit
        await db.query('UPDATE Auth.Users SET Credits = Credits - 1 WHERE id = ?', [userId]);

        res.status(200).send('✅ Message sent and credit deducted!');
    } catch (err) {
        console.error('❌ Error in /send:', err);
        res.status(500).send('❌ Internal server error');
    }
});


//app.post('/send', (req, res) => {
//    // Prefer shipping address name
//    const firstName = req.body.shipping_address?.first_name || '';
//    const lastName = req.body.shipping_address?.last_name || '';
//    const fullName = `${firstName} ${lastName}`.trim();

//    console.log("👤 Customer Name:", fullName);

//    res.sendStatus(200);
//});


// WhatsApp connection starter
async function startSock() {
    if (connecting) {
        console.log('⚠️ Already connecting, skipping...');
        return;
    }
    connecting = true;
    try {
        console.log('🔁 Initializing WhatsApp socket...');
        latestQR = null;

        const { state, saveCreds } = await useMultiFileAuthState(authFolder);

        sock = makeWASocket({
            auth: state,
            browser: ['Chrome', 'Windows', '10']
        });

        sock.ev.on('creds.update', saveCreds);

        sock.ev.on('connection.update', (update) => {
            const { connection, lastDisconnect, qr } = update;

            if (qr) {
                latestQR = qr;
                console.log('📸 New QR code generated');
            }

            if (connection === 'open') {
                console.log('✅ WhatsApp connected');
                latestQR = null;
            }

            if (connection === 'close') {
                const statusCode = lastDisconnect?.error?.output?.statusCode;
                const loggedOut = statusCode === DisconnectReason.loggedOut;

                console.log('❌ WhatsApp connection closed. Status code:', statusCode);

                if (loggedOut) {
                    console.log('🚨 Logged out from WhatsApp, deleting auth data...');
                    rimraf.sync(authFolder);
                    sock = null;
                    startSock().catch(console.error);
                } else {
                    console.log('🔁 Reconnecting in 5 seconds...');
                    setTimeout(() => startSock().catch(console.error), 5000);
                }
            }
        });
    } catch (err) {
        console.error('❌ Failed to start WhatsApp socket:', err);
    } finally {
        connecting = false;
    }
}

// Start server and WhatsApp connection
(async () => {
    try {
        await startSock();
    } catch (err) {
        console.error('❌ Initial WhatsApp connect failed:', err);
    }
})();

app.listen(process.env.PORT || 3000, () => {
    console.log(`🚀 Server running at http://localhost:${process.env.PORT || 3000}`);
});
