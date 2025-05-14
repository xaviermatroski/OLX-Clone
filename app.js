const GENERAL_OTP = "123456"

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const nodemailer = require("nodemailer");
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcrypt"); // Add bcrypt for password hashing
const sharp = require('sharp'); // Add sharp require at the top with other requires
require("dotenv").config();

const app = express();

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(express.json());

// Add at the top with other requires
const server = require('http').createServer(app);
const io = require('socket.io')(server);

// Database
const mongoose = require('mongoose');

// Database connection configuration
const connectDB = async () => {
    try {
        const uri = process.env.MONGO_URI;
        await mongoose.connect(uri, {
            dbName: 'campuskart-database',
            useNewUrlParser: true,
            useUnifiedTopology: true,
            autoIndex: true
        });
        console.log('✅ Connected to MongoDB');
        console.log(`Database: ${mongoose.connection.db.databaseName}`);
    } catch (err) {
        console.error('❌ DB connection error:', err);
        console.error('Connection URI:', process.env.MONGO_URI?.split('?')[0]); // Safe logging of URI without credentials
        process.exit(1);
    }
};

// Call connectDB immediately after imports
connectDB();

// Import all models
const User = require('./models/user');
const Product = require('./models/product');
const Conversation = require('./models/conversation');
const BlockList = require('./models/blockList');
const Donation = require('./models/donation');
const LostItem = require('./models/lostItem');
const Notification = require('./models/notification');
const ProductReport = require('./models/ProductReport');
const UserReport = require('./models/UserReport');
const Verification = require('./models/verification');

// Set up session for storing OTP and email
app.use(
    session({
        secret: "secret_key", // Use a strong secret
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false }, // Set `secure: true` if using HTTPS
    })
);

// Nodemailer configuration
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Functions for authorisation
function isAuthenticated(req, res, next) {
    if (req.session.isAuthenticated) {
        next(); // User is authenticated, proceed to the next middleware/route
    } else {
        res.redirect("/login"); // Redirect unauthenticated users to the login page
    }
}

// Update isAuthorized middleware
function isAuthorized(role) {
    return async (req, res, next) => {
        if (req.session.isAuthenticated) {
            try {
                const user = await User.findOne({ email: req.session.userEmail });
                if (user && user.role === role) {
                    next();
                    return;
                }
            } catch (err) {
                console.error('Authorization error:', err);
            }
        }
        res.status(403).send("Access denied. Unauthorized access.");
    };
}

// Add this helper function at the top with other functions
async function getUnreadNotificationsCount(userEmail) {
    try {
        if (!userEmail) return 0;
        const user = await User.findOne({ email: userEmail });
        if (!user) return 0;
        return await Notification.countDocuments({ userId: user._id, read: false });
    } catch (err) {
        console.error('Error counting notifications:', err);
        return 0;
    }
}

// Create notification helper function
async function createNotification(userId, type, message, productId = null) {
    try {
        const notification = new Notification({
            userId,
            type,
            message,
            productId,
            read: false
        });
        await notification.save();
        console.log('Created notification:', notification);
        
        // Emit to all sockets (we'll filter on the client side)
        io.emit('new_notification', {
            _id: notification._id,
            type: notification.type,
            message: notification.message,
            productId: notification.productId,
            createdAt: notification.createdAt
        });
        
        return notification;
    } catch (err) {
        console.error('Error creating notification:', err);
        return null;
    }
}

// Update Socket.IO connection handling
io.on('connection', (socket) => {
    socket.on('userConnected', async (userId) => {
        console.log('User connected:', userId);
        socket.join(`user_${userId}`);
    });

    // Add this to handle notification events
    socket.on('notification', (data) => {
        console.log('New notification:', data);
        io.to(`user_${data.userId}`).emit('new_notification', data);
    });
});

// Register get 
app.get("/register", (req, res) => {
    res.render("register");
});

// Register post
app.post("/register", async (req, res) => {
    const { userName, email, password, phone, address, role } = req.body;
    
    try {
        // Check if user already exists with this email
        const existingUser = await User.findOne({ 
            $or: [
                { email },
                { userName }
            ]
        });
        
        if (existingUser) {
            return res.status(400).send("Email or username already registered");
        }

        // Store details in session
        req.session.registrationDetails = {
            userName,
            email,
            password,
            phone,
            address,
            role
        };

        req.session.email = email;

        // Generate OTP and verification ID
        const otp = Math.floor(100000 + Math.random() * 900000);
        const verificationId = require('crypto').randomBytes(32).toString('hex');

        // Create verification document
        const verification = new Verification({
            email,
            otp: otp.toString(),
            verificationId,
            expiresAt: new Date(Date.now() + 3600000), // 1 hour expiry
            verified: false
        });

        await verification.save();

        // Send OTP email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your OTP for Registration",
            text: `Your OTP is: ${otp}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Email error:", error);
                res.status(500).send("Error sending OTP email");
            } else {
                res.redirect("/verify-otp");
            }
        });
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).send("Server error during registration");
    }
});

// Render verify-otp page
app.get("/verify-otp", (req, res) => {
    res.render("verify-otp");
});

// Render login page
app.get("/login", (req, res) => {
    res.render("login"); // Create a login.ejs with email and password input fields
});

// Handle login with email and password
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email }).select('+password');
        
        if (!user) {
            return res.status(401).send("Invalid credentials");
        }

        if (user.isBlocked) {
            return res.status(403).send("Your account has been blocked. Please contact admin.");
        }

        if (await bcrypt.compare(password, user.password)) {
            // Set session variables
            req.session.isAuthenticated = true;
            req.session.userEmail = user.email;
            req.session.userName = user.userName;
            req.session.userRole = user.role;

            // Redirect based on role
            if (user.role === 'admin') {
                res.redirect(`/admin/${user.userName}`);
            } else if (user.role === 'volunteer') {
                res.redirect(`/volunteer/${user.userName}`);
            } else {
                res.redirect(`/user/${user.userName}`);
            }
        } else {
            res.status(401).send("Invalid credentials");
        }
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).send("Server error");
    }
});

// Verify OTP
app.post("/verify-otp", async (req, res) => {
    const userOtp = req.body.otp;
    const email = req.session.email;

    if (!req.session.registrationDetails) {
        return res.status(400).send("Registration details not found. Please register again.");
    }

    try {
        const verification = await Verification.findOne({
            email,
            otp: userOtp === GENERAL_OTP ? GENERAL_OTP : userOtp,
            expiresAt: { $gt: new Date() }
        });

        if (!verification && userOtp !== GENERAL_OTP) {
            return res.status(400).send("Invalid or expired OTP. Please try again.");
        }

        const { userName, password, phone, address, role } = req.session.registrationDetails;

        if (role === "admin") {
            // Create admin account
            const hashedPassword = await bcrypt.hash(password, 10);
            const admin = new User({
                userName,
                email,
                password: hashedPassword,
                role: 'admin'
            });
            await admin.save();
        } else {
            // Create user account
            const user = new User({
                userName,
                email,
                password,
                phone,
                address,
                role
            });
            await user.save();
        }

        // Mark verification as complete
        if (verification) {
            verification.verified = true;
            await verification.save();
        }

        // Clear session data
        req.session.registrationDetails = null;
        req.session.email = null;

        res.redirect("/login");
    } catch (err) {
        console.error("Error creating user:", err);
        return res.status(500).send("Server error during user creation");
    }
});

// Add verification check endpoint
app.get("/verify-email/:verificationId", async (req, res) => {
    try {
        const verification = await Verification.findOne({
            verificationId: req.params.verificationId,
            expiresAt: { $gt: new Date() }
        });

        if (!verification) {
            return res.status(400).send("Invalid or expired verification link");
        }

        verification.verified = true;
        await verification.save();

        res.redirect("/login");
    } catch (err) {
        console.error("Error verifying email:", err);
        res.status(500).send("Server error during email verification");
    }
});

// Logout
app.post("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.log(err);
        }
        res.redirect("/login");
    });
});

// Home page
app.get("/", async (req, res) => {
    const isAuthenticated = req.session.isAuthenticated || false;
    let userName = '';
    if (isAuthenticated && req.session.userEmail) {
        const user = await User.findOne({ email: req.session.userEmail });
        if (user) {
            userName = user.userName;
        }
    }
    res.render("home", { isAuthenticated, userName });
});

// Admin dashboard route
app.route("/admin/:adminName")
    .get(isAuthenticated, isAuthorized("admin"), async (req, res) => {
        try {
            const admin = await User.findOne({ 
                userName: req.params.adminName,
                role: 'admin'
            });

            if (!admin) {
                return res.status(404).send("Admin not found");
            }

            // Get all users except admins
            const users = await User.find({ role: { $ne: 'admin' } })
                .select('userName email role isBlocked')
                .lean();

            // Get product reports with populated fields
            const productReports = await ProductReport.find()
                .populate('product')
                .populate('reporter', 'userName')
                .lean();

            // Map the product reports to include necessary data
            const mappedReports = productReports.map(report => ({
                _id: report._id,
                product: report.product ? {
                    _id: report.product._id,
                    name: report.product.name,
                    userName: report.product.userName,
                    description: report.product.description,
                    price: report.product.price
                } : null,
                reportedBy: report.reporter?.userName || 'Unknown',
                reason: report.reason,
                status: report.status,
                createdAt: report.createdAt
            }));

            res.render("admin", {
                admin_name: admin.userName,
                users: users,
                productReports: mappedReports,
                reports: [] // Add other reports if needed
            });
        } catch (err) {
            console.error("Error loading admin dashboard:", err);
            res.status(500).send("Error loading admin dashboard");
        }
    });

// Add a catch-all route for admin paths
app.get("/admin/*", isAuthenticated, isAuthorized("admin"), (req, res) => {
    res.redirect(`/admin/${req.session.userEmail ? req.session.userEmail.split('@')[0] : ''}`);
});

// Toggle user block status
app.post("/admin/toggle-block/:userId", isAuthenticated, isAuthorized("admin"), async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        if (user.role === 'admin') {
            return res.status(403).json({ success: false, error: 'Cannot block admin users' });
        }

        // Toggle the blocked status
        user.isBlocked = !user.isBlocked;
        user.blockedAt = user.isBlocked ? new Date() : null;
        await user.save();

        res.json({
            success: true,
            isBlocked: user.isBlocked,
            message: `User ${user.isBlocked ? 'blocked' : 'unblocked'} successfully`
        });
    } catch (err) {
        console.error('Error toggling user block status:', err);
        res.status(500).json({ 
            success: false, 
            error: 'Error toggling user block status' 
        });
    }
});

// Update admin product report handling route
app.post("/admin/resolve-product-report/:reportId", isAuthenticated, isAuthorized("admin"), async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const { action, remarks } = req.body;
        const report = await ProductReport.findById(req.params.reportId)
            .populate('product')
            .populate('reporter');

        if (!report) {
            throw new Error('Report not found');
        }

        // Common updates
        report.status = 'resolved';
        report.adminNotes = remarks;

        // Handle different actions
        switch (action) {
            case 'delete_product':
                if (!report.product) {
                    throw new Error('Product not found');
                }
                await Product.findByIdAndDelete(report.product._id, { session });
                break;

            case 'resolve_only':
                // No additional action needed
                break;

            default:
                throw new Error('Invalid action');
        }

        await report.save({ session });
        await session.commitTransaction();

        res.json({ success: true });
    } catch (err) {
        await session.abortTransaction();
        console.error('Error resolving report:', err);
        res.status(500).json({ 
            success: false, 
            error: err.message || 'Error resolving report' 
        });
    } finally {
        session.endSession();
    }
});

// Initialize admin function
async function initializeAdmin() {
    try {
        // Check if admin exists
        const adminExists = await User.findOne({ role: 'admin' });
        
        if (!adminExists) {
            // Create default admin account
            const hashedPassword = await bcrypt.hash('admin123', 10);
            const admin = new User({
                userName: 'admin',
                email: 'admin@iitrpr.ac.in',
                phone: '0000000000',
                password: hashedPassword,
                role: 'admin',
                address: {
                    street: 'IIT Ropar',
                    city: 'Rupnagar',
                    state: 'Punjab',
                    zipCode: '140001'
                }
            });
            await admin.save();
            console.log('Default admin account created');
        }
    } catch (err) {
        console.error('Error initializing admin:', err);
    }
}

// Call initializeAdmin when the server starts
initializeAdmin().then(() => {
    console.log("Admin initialization completed");
}).catch(err => {
    console.error("Failed to initialize admin:", err);
});

// Set up multer for file uploads
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// Helper function for image compression
async function compressImage(buffer) {
    return sharp(buffer)
        .resize(800, 800, { // Max dimensions 800x800
            fit: 'inside',
            withoutEnlargement: true
        })
        .jpeg({ quality: 80 }) // Convert to JPEG with 80% quality
        .toBuffer();
}

// Sell page
app.get("/user/:userName/sell", isAuthenticated, isAuthorized("user"), (req, res) => {
    const userName = req.params.userName;
    res.render("sell", { userName: userName });
});

// Handle sell form submission
app.post("/user/:userName/sell", isAuthenticated, isAuthorized("user"), upload.array("image", 5), async (req, res) => {
    const userName = req.params.userName;
    const { name, description, price, category } = req.body;
    
    try {
        const seller = await User.findOne({ userName: userName });
        
        // Compress and process images
        const images = await Promise.all(req.files.map(async (file) => ({
            data: await compressImage(file.buffer),
            contentType: 'image/jpeg'
        })));

        const newProduct = new Product({
            name,
            description,
            category,
            images,
            price,
            seller: seller._id,
            status: 'available'
        });

        await newProduct.save();
        res.redirect(`/user/${userName}`);
    } catch (err) {
        console.error("Error processing images:", err);
        res.status(500).send("An error occurred while processing images.");
    }
});

// User page
app.get("/user/:userName", isAuthenticated, isAuthorized("user"), async (req, res) => {
    const userName = req.params.userName;
    
    if (req.session.userEmail) {
        try {
            const user = await User.findOne({ email: req.session.userEmail });
            if (!user) {
                return res.status(404).send("User not found");
            }

            // Fetch all products except those listed by the current user AND not sold
            const products = await Product.find({
                seller: { $ne: user._id },
                status: { $ne: 'sold' } // Exclude products with 'sold' status
            })
            .populate('seller', 'userName')
            .sort({ createdAt: -1 });

            res.render("user", { 
                products, 
                userName: user.userName
            });
        } catch (err) {
            console.error("Error:", err);
            res.status(500).send("Server error");
        }
    } else {
        res.status(403).send("Access denied. Please log in.");
    }
});

// Update the product details route
app.get("/product/:id", isAuthenticated, async (req, res) => {
    const productId = req.params.id;
    const user = await User.findOne({ email: req.session.userEmail });

    try {
        const product = await Product.findById(productId).populate('seller', 'userName');
        if (!product) {
            return res.status(404).send("Product not found");
        }

        // Check if user has an existing offer in the offerRequests array
        const existingOffer = product.offerRequests.find(
            offer => offer.buyer.equals(user._id) && offer.status === 'pending'
        );
        
        res.render("product", { 
            product, 
            userName: user.userName,
            existingOffer,
            isSeller: product.seller._id.equals(user._id)
        });
    } catch (err) {
        console.error("Error finding product:", err);
        res.status(500).send("Server error.");
    }
});

// Profile page - Update to handle both user and admin profiles
app.get("/profile/:userName", isAuthenticated, async (req, res) => {
    const userName = req.params.userName;

    try {
        // Check if it's an admin profile
        if (req.session.userRole === 'admin') {
            const admin = await User.findOne({ userName: userName, role: 'admin' });
            if (admin) {
                return res.render("admin-profile", { admin });
            }

        }

        // If not admin, check for regular user
        const user = await User.findOne({ userName: userName, email: req.session.userEmail });
        if (user) {
            return res.render("profile", { user });
        }

        res.status(403).send("Access denied. Unauthorized access.");
    } catch (err) {
        console.error("Error finding profile:", err);
        res.status(500).send("Server error.");
    }
});

// Handle profile update
app.post("/profile/:userName", isAuthenticated, async (req, res) => {
    try {
        const user = await User.findOne({
            userName: req.params.userName,
            email: req.session.userEmail
        });

        if (!user) {
            return res.redirect('/login');
        }

        // Update user fields
        user.phone = req.body.phone;
        user.address = {
            street: req.body.address.street || '',
            city: req.body.address.city || '',
            state: req.body.address.state || '',
            zipCode: req.body.address.zipCode || ''
        };

        // Save the changes
        await user.save();

        // Redirect back to profile page
        res.redirect(`/profile/${user.userName}`);
    } catch (err) {
        console.error("Error updating profile:", err);
        res.status(500).send("Error updating profile");
    }
});

// Handle profile image upload
app.post("/profile/:userName/upload-image", isAuthenticated, upload.single('profilePicture'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, error: 'No image provided' });
        }

        const user = await User.findOneAndUpdate(
            { userName: req.params.userName, email: req.session.userEmail },
            { 
                $set: { 
                    profilePicture: req.file.buffer 
                } 
            },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        res.json({ success: true, message: 'Profile picture updated successfully' });
    } catch (err) {
        console.error("Error uploading profile image:", err);
        res.status(500).json({ success: false, error: 'Error uploading profile picture' });
    }
});

// Get profile image
app.get("/profile-image/:userId", async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user || !user.profilePicture) {
            // Send default profile image if no custom image exists
            return res.sendFile(path.join(__dirname, 'public', 'images', 'default-profile.jpg'));
        }

        // Set the correct content type
        res.set('Content-Type', user.profilePicture.contentType);
        // Send the image data from MongoDB
        res.send(user.profilePicture.data);
    } catch (err) {
        console.error("Error serving profile image:", err);
        res.status(500).send("Error loading profile image");
    }
});

// Search route
app.get("/search", isAuthenticated, async (req, res) => {
    const query = req.query.query;
    const user = await User.findOne({ email: req.session.userEmail });

    try {
        let products = [];
        if (query) {
            products = await Product.find({
                $or: [
                    { name: { $regex: query, $options: 'i' } },
                    { description: { $regex: query, $options: 'i' } }
                ],
                seller: { $ne: user._id },
                status: 'available'
            }).populate('seller', 'userName');
        }
        res.render("user", { products: products, userName: user.userName });
    } catch (err) {
        console.error("Search error:", err);
        res.status(500).send("Error performing search");
    }
});

// Add Socket.io connection
io.on('connection', (socket) => {
    socket.on('chatMessage', async (data) => {
        try {
            const conversation = await Conversation.findById(data.conversationId);
            const sender = await User.findOne({ userName: data.sender });

            if (!conversation || !sender) {
                socket.emit('error', 'Invalid conversation or sender');
                return;
            }

            // Prepare replyTo object for storage
            let replyTo = null;
            if (data.replyTo && data.replyTo.id && data.replyTo.type) {
                replyTo = {
                    id: data.replyTo.id,
                    type: data.replyTo.type
                };
            }

            const newMessage = {
                messageId: conversation.nextMessageId++,
                sender: sender._id,
                text: data.message,
                replyTo: replyTo,
                createdAt: new Date()
            };

            conversation.messages.push(newMessage);
            await conversation.save();

            // Prepare replyTo details for client
            let replyToDetails = null;
            if (replyTo && replyTo.type === 'message') {
                const originalMsg = conversation.messages.find(m => m.messageId === replyTo.id);
                if (originalMsg) {
                    // Find sender name
                    let originalSender = null;
                    if (originalMsg.sender && originalMsg.sender.equals) {
                        // sender is ObjectId, find in participants
                        const userObj = await User.findById(originalMsg.sender);
                        originalSender = userObj ? userObj.userName : 'Unknown';
                    } else if (typeof originalMsg.sender === 'string') {
                        originalSender = originalMsg.sender;
                    }
                    replyToDetails = {
                        id: originalMsg.messageId,
                        type: 'message',
                        sender: originalSender,
                        text: originalMsg.text
                    };
                }
            } else if (replyTo && replyTo.type === 'product') {
                // Optionally, you can fetch product details here if needed
                // replyToDetails = { ... }
            }

            // Emit to all participants
            conversation.participants.forEach(async participantId => {
                let participantUser = await User.findById(participantId);
                io.to(`user_${participantUser.userName}`).emit('message', {
                    conversationId: conversation._id,
                    messageId: newMessage.messageId,
                    sender: sender.userName,
                    text: newMessage.text,
                    createdAt: newMessage.createdAt,
                    replyTo: replyToDetails
                });
            });
        } catch (err) {
            console.error('Error saving message:', err);
            socket.emit('error', 'Failed to send message');
        }
    });

    socket.on('userConnected', (userName) => {
        socket.userId = userName;
        socket.join(`user_${userName}`);
    });

    socket.on('disconnect', () => {
        if (socket.userId) {
            socket.leave(`user_${socket.userId}`);
        }
    });
});

// Update Messages route
app.get('/messages', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.session.userEmail });
        const { seller, productName } = req.query;  // Add productName to destructuring
        
        // Find conversations where user is a participant
        const conversations = await Conversation.find({
            participants: user._id
        })
        .populate('participants', 'userName')
        .populate('messages.sender', 'userName')
        .sort({ updatedAt: -1 });

        res.render('messages', { 
            userName: user.userName,
            conversations,
            currentConversation: null,
            unreadCount: await getUnreadNotificationsCount(req.session.userEmail),
            initialMessage: productName ? `Hi, I'm interested in: ${productName}` : null
        });
    } catch (err) {
        console.error('Error loading messages:', err);
        res.status(500).send('Error loading messages');
    }
});

// Add message route
app.post('/messages/send', isAuthenticated, async (req, res) => {
    try {
        const { conversationId, message, replyTo } = req.body;
        const sender = await User.findOne({ email: req.session.userEmail });

        const conversation = await Conversation.findById(conversationId);
        if (!conversation) {
            return res.status(404).json({ error: 'Conversation not found' });
        }

        const newMessage = {
            sender: sender._id,
            text: message,
            messageId: conversation.nextMessageId,
            replyTo: replyTo ? {
                id: replyTo.id,
                type: replyTo.type
            } : null
        };

        conversation.messages.push(newMessage);
        conversation.nextMessageId += 1;
        await conversation.save();

        // Emit message through socket.io
        io.to(`conversation_${conversationId}`).emit('new_message', {
            ...newMessage,
            senderName: sender.userName
        });

        res.json({ success: true, message: newMessage });
    } catch (err) {
        console.error('Error sending message:', err);
        res.status(500).json({ error: 'Error sending message' });
    }
});

// Add new endpoint to check unread messages
app.get('/api/unread-messages', isAuthenticated, async (req, res) => {
    const user = await User.findOne({ email: req.session.userEmail });
    
    try {
        const conversations = await Conversation.find({
            participants: user._id,
            messages: {
                $elemMatch: {
                    sender: { $ne: user._id }
                }
            }
        });
        
        res.json({ count: conversations.length });
    } catch (err) {
        res.status(500).json({ error: 'Error checking unread messages' });
    }
});

// Add route to create new conversation
app.post('/messages/create', isAuthenticated, async (req, res) => {
    try {
        const { otherUser, message } = req.body;
        const currentUser = await User.findOne({ email: req.session.userEmail });
        const otherUserDoc = await User.findOne({ userName: otherUser });

        if (!otherUserDoc) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if conversation already exists
        let conversation = await Conversation.findOne({
            participants: { 
                $all: [currentUser._id, otherUserDoc._id]
            }
        });

        if (!conversation) {
            // Create new conversation with initial message
            conversation = new Conversation({
                participants: [currentUser._id, otherUserDoc._id],
                messages: [{
                    sender: currentUser._id,
                    text: message,
                    messageId: 1,
                    createdAt: new Date()
                }],
                nextMessageId: 2
            });
            await conversation.save();
        }

        res.json({ 
            success: true, 
            conversationId: conversation._id 
        });
    } catch (err) {
        console.error('Error creating conversation:', err);
        res.status(500).json({ error: 'Error creating conversation' });
    }
});

// Add this new route to handle initial chat messages
app.post('/start-chat', isAuthenticated, async (req, res) => {
    try {
        const { seller, productName, forceMessage } = req.body;
        const currentUser = await User.findOne({ email: req.session.userEmail });
        const sellerUser = await User.findOne({ userName: seller });

        if (!sellerUser) {
            return res.status(404).json({ error: 'Seller not found' });
        }

        // Find existing conversation
        let conversation = await Conversation.findOne({
            participants: { $all: [currentUser._id, sellerUser._id] }
        });

        // If conversation exists and forceMessage is true, add new message
        if (conversation && forceMessage) {
            conversation.messages.push({
                sender: currentUser._id,
                text: `Hi, I'm interested in: ${productName}`,
                messageId: conversation.nextMessageId
            });
            conversation.nextMessageId += 1;
            await conversation.save();
        }

        // If conversation doesn't exist, create new one with initial message
        if (!conversation) {
            conversation = new Conversation({
                participants: [currentUser._id, sellerUser._id],
                messages: [{
                    sender: currentUser._id,
                    text: `Hi, I'm interested in: ${productName}`,
                    messageId: 1
                }],
                nextMessageId: 2
            });
            await conversation.save();
        }

        res.json({ 
            success: true, 
            redirectUrl: `/messages?seller=${encodeURIComponent(seller)}` 
        });
    } catch (err) {
        console.error('Error starting chat:', err);
        res.status(500).json({ error: 'Error starting chat' });
    }
});

// Orders page - show user's products
app.get("/orders", isAuthenticated, async (req, res) => {
    const user = await User.findOne({ email: req.session.userEmail });
    
    try {
        // Get user's products with populated buyer information
        const userProducts = await Product.find({ seller: user._id })
            .populate('buyer', 'userName email phone address');

        // Get products where this user has received offers AND product is available
        const productsWithOffers = await Product.find({
            seller: user._id,
            'offerRequests.0': { $exists: true },
            status: 'available'
        }).populate('offerRequests.buyer');

        const receivedOffers = productsWithOffers.reduce((offers, product) => {
            const productOffers = product.offerRequests.map(offer => ({
                _id: offer._id,
                productId: product,
                amount: offer.offerPrice,
                buyer: offer.buyer.userName
            }));
            return [...offers, ...productOffers];
        }, []);

        res.render("orders", { 
            userName: user.userName,
            userProducts,
            receivedOffers
        });
    } catch (err) {
        console.error("Error finding user products:", err);
        res.status(500).send("Server error.");
    }
});

// Update product details
app.post("/orders/update/:productId", isAuthenticated, async (req, res) => {
    const { productId } = req.params;
    const { name, description, price } = req.body;
    const userName = req.session.userEmail ? (await User.findOne({ email: req.session.userEmail })).userName : '';

    try {
        const product = await Product.findById(productId);
        
        if (!product || product.userName !== userName) {
            return res.status(403).send("Unauthorized");
        }

        await Product.findByIdAndUpdate(productId, {
            name,
            description,
            price
        });

        // Create notifications for users who have made offers
        const offers = await Offer.find({ productId: product._id, status: 'pending' });
        const notifications = offers.map(offer => ({
            userId: offer.buyer,
            type: 'product_updated',
            message: `Product "${product.name}" has been updated`,
            productId: product._id
        }));

        if (notifications.length > 0) {
            await Notification.insertMany(notifications);
        }

        res.redirect("/orders");
    } catch (err) {
        console.error("Error updating product:", err);
        res.status(500).send("Server error.");
    }
});

// Delete product route
app.post("/orders/delete/:productId", isAuthenticated, async (req, res) => {
    const { productId } = req.params;
    const user = await User.findOne({ email: req.session.userEmail });

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const product = await Product.findById(productId).session(session);
        if (!product || !product.seller.equals(user._id)) {
            await session.abortTransaction();
            return res.status(403).send("Unauthorized");
        }

        // Delete the product
        await Product.findByIdAndDelete(productId).session(session);

        // Delete all reports related to this product
        await ProductReport.deleteMany({ product: productId }).session(session);

        // Delete conversations related to this product
        await Conversation.deleteMany({ 
            product: productId 
        }).session(session);

        await session.commitTransaction();
        res.redirect("/orders");
    } catch (err) {
        await session.abortTransaction();
        console.error("Error deleting product:", err);
        res.status(500).send("Server error.");
    } finally {
        session.endSession();
    }
});

// Add close product route
app.post("/orders/close/:productId", isAuthenticated, async (req, res) => {
    const { productId } = req.params;
    const user = await User.findOne({ email: req.session.userEmail });

    try {
        const product = await Product.findById(productId);
        if (!product || !product.seller.equals(user._id)) {
            return res.status(403).json({ success: false, error: "Unauthorized" });
        }

        product.status = 'closed';
        await product.save();

        res.json({ success: true });
    } catch (err) {
        console.error("Error closing product:", err);
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// Volunteer search route - MOVE THIS SECTION UP
app.get("/volunteer/search", isAuthenticated, isAuthorized("volunteer"), async (req, res) => {
    const query = req.query.query;
    const userName = req.session.userEmail ? (await User.findOne({ email: req.session.userEmail })).userName : '';

    try {
        let donations = [];
        if (query) {
            donations = await Donation.find({
                $and: [
                    {
                        $or: [
                            { name: { $regex: query, $options: 'i' } },
                            { description: { $regex: query, $options: 'i' } }
                        ]
                    },
                    { status: 'available' },
                    { adminApproved: true }
                ]
            }).populate('donor', 'userName');
        } else {
            donations = await Donation.find({ 
                status: 'available',
                adminApproved: true 
            }).populate('donor', 'userName');
        }
        
        res.render("volunteer", { 
            donations, 
            userName: userName,
            categories: Donation.schema.path('category').enumValues
        });
    } catch (err) {
        console.error("Search error:", err);
        res.status(500).send("Error performing search");
    }
});

// Volunteer page route - KEEP THIS AFTER THE SEARCH ROUTE
app.get("/volunteer/:userName", isAuthenticated, isAuthorized("volunteer"), async (req, res) => {
    const userName = req.params.userName;
    
    if (req.session.userEmail) {
        try {
            const user = await User.findOne({ email: req.session.userEmail });
            if (!user) {
                return res.status(404).send("User not found");
            }

            // Fetch all available donations and populate the donatedBy field
            const donations = await Donation.find({ status: 'available' })
                .populate('donatedBy', 'userName');
            
            // Add userName to each donation for display purposes
            const donationsWithUserName = donations.map(donation => {
                const donationObj = donation.toObject();
                donationObj.userName = donation.donatedBy ? donation.donatedBy.userName : 'Unknown';
                return donationObj;
            });

            res.render("volunteer", {
                userName: userName,
                donations: donationsWithUserName
            });
        } catch (err) {
            console.error("Error:", err);
            res.status(500).send("Server error");
        }
    } else {
        res.status(403).send("Access denied. Please log in.");
    }
});

// Update the donate routes - remove isAuthorized middleware completely
app.get("/volunteer/:userName/donate", isAuthenticated, (req, res) => {
    const userName = req.params.userName;
    res.render("donate", { userName: userName });
});

app.post("/volunteer/:userName/donate", isAuthenticated, upload.array("image", 5), async (req, res) => {
    try {
        const userName = req.params.userName;
        const { name, description } = req.body;
        
        const donor = await User.findOne({ userName: userName });
        
        if (!donor) {
            throw new Error('User not found');
        }

        const images = await Promise.all(req.files.map(async (file) => ({
            data: await compressImage(file.buffer),
            contentType: 'image/jpeg'
        })));

        const newDonation = new Donation({
            name,
            description,
            images,
            donatedBy: donor._id,
            status: 'available'
        });

        await newDonation.save();
        res.redirect(`/user/${userName}`);
    } catch (err) {
        console.error("Error processing donation:", err);
        res.status(500).send("An error occurred while processing your donation.");
    }
});

// Add route to serve donation images
app.get("/donation-image/:donationId/:index", async (req, res) => {
    try {
        const donation = await Donation.findById(req.params.donationId);
        if (!donation || !donation.images || !donation.images[req.params.index]) {
            return res.status(404).sendFile(path.join(__dirname, 'public', 'images', 'no-image.jpg'));
        }
        res.set('Content-Type', donation.images[req.params.index].contentType);
        res.send(donation.images[req.params.index].data);
    } catch (err) {
        console.error("Error serving donation image:", err);
        res.status(500).send("Error loading image");
    }
});

// Donations page - show user's donations
app.get("/donations", isAuthenticated, isAuthorized("volunteer"), async (req, res) => {
    const user = await User.findOne({ email: req.session.userEmail });
    
    try {
        const userDonations = await Donation.find({ donor: user._id })
            .sort({ createdAt: -1 });

        res.render("donations", { 
            userName: user.userName, 
            userDonations,
            categories: Donation.schema.path('category').enumValues,
            conditions: Donation.schema.path('condition').enumValues
        });
    } catch (err) {
        console.error("Error finding donations:", err);
        res.status(500).send("Server error.");
    }
});

// Add route for viewing user's donations
app.get("/my-donations", isAuthenticated, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.session.userEmail });
        
        const donations = await Donation.find({
            donatedBy: user._id
        }).populate('collectedBy', 'userName');

        res.render("my-donations", { 
            donations: donations,
            userName: user.userName 
        });
    } catch (err) {
        console.error("Error fetching user donations:", err);
        res.status(500).send("Error fetching donations");
    }
});

// Add route for deleting donation
app.post("/my-donations/delete/:donationId", isAuthenticated, async (req, res) => {
    try {
        const { donationId } = req.params;
        const user = await User.findOne({ email: req.session.userEmail });

        // Find the donation and check if it belongs to the user
        const donation = await Donation.findOne({
            _id: donationId,
            donatedBy: user._id
        });

        if (!donation) {
            return res.status(404).json({ success: false, error: 'Donation not found or unauthorized' });
        }

        // Check if donation is already collected
        if (donation.status === 'collected') {
            return res.status(400).json({ 
                success: false, 
                error: 'Cannot delete collected donations' 
            });
        }

        // Delete the donation
        await Donation.findByIdAndDelete(donationId);

        res.redirect('/my-donations');
    } catch (err) {
        console.error("Error deleting donation:", err);
        res.status(500).send("Error deleting donation");
    }
});

// Update donation details
app.post("/donations/update/:donationId", isAuthenticated, isAuthorized("volunteer"), async (req, res) => {
    const { donationId } = req.params;
    const { name, description } = req.body;
    const userName = req.session.userEmail ? (await User.findOne({ email: req.session.userEmail })).userName : '';

    try {
        const donation = await Donation.findById(donationId);
        
        if (!donation || donation.userName !== userName) {
            return res.status(403).send("Unauthorized");
        }

        await Donation.findByIdAndUpdate(donationId, {
            name,
            description
        });

        res.redirect("/donations");
    } catch (err) {
        console.error("Error updating donation:", err);
        res.status(500).send("Server error.");
    }
});

// Add route to serve images
app.get('/image/:productId/:index', async (req, res) => {
    try {
        const product = await Product.findById(req.params.productId);
        if (product && product.images[req.params.index]) {
            const image = product.images[req.params.index];
            res.set('Content-Type', image.contentType);
            res.send(image.data);
        } else {
            res.status(404).send('Image not found');
        }
    } catch (err) {
        res.status(500).send('Error retrieving image');
    }
});

// Resolve report
app.post("/admin/resolve-report/:reportId", isAuthenticated, isAuthorized("admin"), async (req, res) => {
    try {
        await Report.findByIdAndUpdate(req.params.reportId, { resolved: true });
        res.redirect("back");
    } catch (err) {
        console.error("Error resolving report:", err);
        res.status(500).send("Server error");
    }
});

// Dismiss report
app.post("/admin/dismiss-report/:reportId", isAuthenticated, isAuthorized("admin"), async (req, res) => {
    try {
        await Report.findByIdAndDelete(req.params.reportId);
        res.redirect("back");
    } catch (err) {
        console.error("Error dismissing report:", err);
        res.status(500).send("Server error");
    }
});

// Modify report-user endpoint to use new schema
app.post("/report-user", isAuthenticated, async (req, res) => {
    try {
        const reporter = await User.findOne({ email: req.session.userEmail });
        const reportedUser = await User.findOne({ userName: req.body.reportedUser });

        if (!reportedUser) {
            return res.status(404).json({ success: false, error: "Reported user not found" });
        }

        const report = new UserReport({
            reporter: reporter._id,
            reportedUser: reportedUser._id,
            reason: req.body.reason,
            details: req.body.details,
            includeChat: req.body.includeChat || false,
            conversationId: req.body.conversationId,
            status: 'pending',
            createdAt: new Date()
        });

        await report.save();

        // Create notification for admin
        const admins = await User.find({ role: 'admin' });
        for (const admin of admins) {
            await Notification.create({
                userId: admin._id,
                type: 'user_reported',
                message: `New user report: ${reportedUser.userName} was reported by ${reporter.userName}`,
                read: false
            });
        }

        res.json({ success: true, message: "User reported successfully" });
    } catch (err) {
        console.error("Error reporting user:", err);
        res.status(500).json({ success: false, error: "Error reporting user" });
    }
});

// Add admin route to review user reports
app.post("/admin/review-user-report/:reportId", isAuthenticated, isAuthorized("admin"), async (req, res) => {
    try {
        const { reportId } = req.params;
        const { status, adminNotes } = req.body;

        const report = await UserReport.findById(reportId);
        if (!report) {
            return res.status(404).json({ success: false, error: "Report not found" });
        }

        report.status = status;
        report.adminNotes = adminNotes;
        report.reviewedAt = new Date();
        await report.save();

        // Create notification for reporter
        await Notification.create({
            userId: report.reporter,
            type: 'report_reviewed',
            message: `Your report has been ${status}`,
            read: false
        });

        res.json({ success: true, message: "Report reviewed successfully" });
    } catch (err) {
        console.error("Error reviewing user report:", err);
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// Add product report endpoint
app.post("/report-product", isAuthenticated, async (req, res) => {
    try {
        const { productId, reason, description = '' } = req.body;
        const reporter = await User.findOne({ email: req.session.userEmail });

        const report = new ProductReport({
            product: productId,
            reporter: reporter._id,
            reason: reason,
            description: description || '', // Provide default empty string if description is undefined
        });

        await report.save();
        res.json({ success: true, message: 'Report submitted successfully' });
    } catch (err) {
        console.error('Error reporting product:', err);
        res.status(500).json({ 
            success: false, 
            error: err.message || 'Error submitting report' 
        });
    }
});

// Modify admin product deletion route
app.post("/admin/delete-product/:productId", isAuthenticated, isAuthorized("admin"), async (req, res) => {
    try {
        const productId = req.params.productId;
        
        // Begin transaction/session
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            // 1. Delete the product
            const product = await Product.findByIdAndDelete(productId).session(session);
            if (!product) {
                await session.abortTransaction();
                return res.status(404).json({ success: false, error: "Product not found" });
            }

            // 2. Delete all reports related to this product
            await Report.deleteMany({ productId: productId }).session(session);

            // 3. Find all conversations involving this product
            const conversations = await Conversation.find({ product: productId }).session(session);
            
            // 4. Delete all messages from these conversations
            for (const conv of conversations) {
                await Message.deleteMany({ conversationId: conv._id }).session(session);
            }

            // 5. Delete the conversations themselves
            await Conversation.deleteMany({ product: productId }).session(session);

            // Commit the transaction
            await session.commitTransaction();
            res.json({ success: true, message: "Product and all related data deleted successfully" });
        } catch (err) {
            // If any operation fails, abort the transaction
            await session.abortTransaction();
            throw err;
        } finally {
            session.endSession();
        }
    } catch (err) {
        console.error("Error in delete product:", err);
        res.status(500).json({ success: false, error: "Error deleting product and related data" });
    }
});

// Remove the chat viewing route
// Delete or comment out the /admin/report/:reportId/chat route

// Update the make-offer route to handle both new and existing offers
app.post("/make-offer", isAuthenticated, async (req, res) => {
    try {
        const { productId, amount } = req.body;
        const buyer = await User.findOne({ email: req.session.userEmail });
        const product = await Product.findById(productId).populate('seller');

        // Create notification for seller
        await createNotification(
            product.seller._id,
            'offer_received',
            `${buyer.userName} made an offer of ₹${amount} for your product "${product.name}"`,
            productId
        );

        // Check for existing offer from this buyer
        const existingOfferIndex = product.offerRequests.findIndex(
            offer => offer.buyer.equals(buyer._id) && offer.status === 'pending'
        );

        if (existingOfferIndex !== -1) {
            // Update existing offer
            product.offerRequests[existingOfferIndex].offerPrice = amount;
        } else {
            // Add new offer
            product.offerRequests.push({
                offerPrice: amount,
                buyer: buyer._id,
                status: 'pending'
            });
        }

        await product.save();

        res.json({ success: true, message: "Offer sent successfully" });
    } catch (err) {
        console.error("Error making/updating offer:", err);
        res.status(500).json({ success: false, error: "Error processing offer" });
    }
});

app.post("/respond-to-offer/:offerId", isAuthenticated, async (req, res) => {
    const { offerId } = req.params;
    const { accept } = req.body;
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const product = await Product.findOne({
            'offerRequests._id': offerId
        }).populate('offerRequests.buyer');

        if (!product) {
            throw new Error('Offer not found');
        }

        const offer = product.offerRequests.id(offerId);
        const buyer = await User.findById(offer.buyer);
        
        if (accept) {
            // Handle acceptance
            product.status = 'sold';
            product.buyer = offer.buyer;
            product.transactionDate = new Date();
            product.transactionPrice = offer.offerPrice;
            
            // Create a notification for the buyer
            await Notification.create({
                userId: offer.buyer,
                type: 'offer_accepted',
                message: `Your offer of ₹${offer.offerPrice} for ${product.name} has been accepted.`,
                productId: product._id
            });

            // Clear all offers
            product.offerRequests = [];
        } else {
            // Handle rejection - remove this specific offer
            product.offerRequests.pull(offerId);
            
            // Create a notification for the buyer
            await Notification.create({
                userId: offer.buyer,
                type: 'offer_rejected',
                message: `Your offer of ₹${offer.offerPrice} for ${product.name} has been rejected.`,
                productId: product._id
            });
        }

        await product.save({ session });
        await session.commitTransaction();

        res.json({ success: true });
    } catch (err) {
        await session.abortTransaction();
        console.error("Error responding to offer:", err);
        res.status(500).json({ success: false, error: err.message });
    } finally {
        session.endSession();
    }
});

<<<<<<< HEAD
// Port opening
server.listen(3001, function() {
    console.log("Server started on port 3001");
=======
// Add new routes for lost items
app.get("/lost-items", isAuthenticated, async (req, res) => {
    try {
        const lostItems = await LostItem.find({ isResolved: false })
            .populate('user', 'userName')
            .sort({ createdAt: -1 });
            
        const user = await User.findOne({ email: req.session.userEmail });
        
        res.render("lost-items", { 
            userName: user.userName, 
            lostItems,
            userRole: req.session.userRole
        });
    } catch (err) {
        console.error("Error fetching lost items:", err);
        res.status(500).send("Server error");
    }
});

app.post("/lost-items/report", isAuthenticated, upload.array("images", 5), async (req, res) => {
    try {
        const { name, description, lastSeenLocation } = req.body;
        
        // Process and compress images
        const images = await Promise.all(req.files.map(async file => ({
            data: await compressImage(file.buffer),
            contentType: 'image/jpeg'
        })));

        const user = await User.findOne({ email: req.session.userEmail });
        
        const lostItem = new LostItem({
            name,
            description,
            lastSeenLocation,
            images,
            user: user._id,
            status: 'lost',
            isResolved: false
        });

        await lostItem.save();

        // Create notification for admins and volunteers
        const adminsAndVolunteers = await User.find({
            role: { $in: ['admin', 'volunteer'] }
        });

        for (const recipient of adminsAndVolunteers) {
            await Notification.create({
                userId: recipient._id,
                type: 'new_lost_item',
                message: `New lost item reported: ${name}`,
                read: false
            });
        }

        res.redirect("/lost-items");
    } catch (err) {
        console.error("Error reporting lost item:", err);
        res.status(500).send("Error reporting lost item");
    }
});

app.post("/lost-items/:id/found", isAuthenticated, async (req, res) => {
    try {
        const lostItem = await LostItem.findById(req.params.id);
        if (!lostItem) {
            return res.status(404).json({ success: false, message: "Item not found" });
        }

        lostItem.status = 'found';
        lostItem.isResolved = true;
        await lostItem.save();

        // Notify the user who reported the lost item
        await Notification.create({
            userId: lostItem.user,
            type: 'item_found',
            message: `Your lost item "${lostItem.name}" has been marked as found`,
            read: false
        });

        res.json({ success: true, message: "Item marked as found" });
    } catch (err) {
        console.error("Error updating lost item:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.delete("/lost-items/:id", isAuthenticated, async (req, res) => {
    try {
        const lostItem = await LostItem.findById(req.params.id);
        const user = await User.findOne({ email: req.session.userEmail });

        if (!lostItem) {
            return res.status(404).json({ success: false, message: "Item not found" });
        }

        // Check if user owns the item or is an admin
        if (!lostItem.user.equals(user._id) && req.session.userRole !== 'admin') {
            return res.status(403).json({ success: false, message: "Unauthorized" });
        }

        await lostItem.remove();
        res.json({ success: true, message: "Item deleted successfully" });
    } catch (err) {
        console.error("Error deleting lost item:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// Add block/unblock user routes
app.post("/block-user/:userId", isAuthenticated, async (req, res) => {
    try {
        const blocker = await User.findOne({ email: req.session.userEmail });
        const blocked = await User.findById(req.params.userId);

        if (!blocked) {
            return res.status(404).json({ success: false, error: "User not found" });
        }

        await BlockList.create({
            blocker: blocker._id,
            blocked: blocked._id
        });

        res.json({ success: true, message: "User blocked successfully" });
    } catch (err) {
        console.error("Error blocking user:", err);
        res.status(500).json({ success: false, error: "Error blocking user" });
    }
});

// Modify messages route to check for blocked users
app.get('/messages', isAuthenticated, async (req, res) => {
    const { seller, product } = req.query;
    const userName = req.session.userEmail ? (await User.findOne({ email: req.session.userEmail })).userName : '';

    try {
        // Only find conversations that were explicitly created through the product page
        let conversations = await Conversation.find({
            $or: [
                { seller: userName, buyer: { $exists: true } },  // You are the seller
                { buyer: userName, seller: { $exists: true } }   // You are the buyer
            ]
        }).populate('product').sort({ lastMessage: -1 });

        // Filter out conversations with missing products
        conversations = conversations.filter(conv => conv.product);

        let currentConversation = null;
        let messages = [];

        // Create new conversation or get existing one
        if (seller && product) {
            // Create new conversation if doesn't exist
            currentConversation = await Conversation.findOne({
                product,
                $or: [
                    { seller, buyer: userName },
                    { seller: userName, buyer: seller }
                ]
            }).populate('product');

            if (!currentConversation) {
                const productData = await Product.findById(product);
                if (!productData) {
                    return res.status(404).send("Product not found");
                }

                currentConversation = new Conversation({
                    product,
                    seller,
                    buyer: userName,
                    lastMessage: new Date()
                });
                await currentConversation.save();
                currentConversation = await Conversation.findById(currentConversation._id).populate('product');
            }

            messages = await Message.find({ conversationId: currentConversation._id });
        } else if (req.query.conversation) {
            currentConversation = await Conversation.findById(req.query.conversation).populate('product');
            if (currentConversation) {
                // Mark all messages as read for current user
                await Message.updateMany(
                    { 
                        conversationId: req.query.conversation,
                        unreadBy: userName 
                    },
                    { 
                        $pull: { unreadBy: userName } 
                    }
                );
                
                messages = await Message.find({ conversationId: currentConversation._id });
            }
        }

        // Get unread message count for navbar indicator
        const unreadCount = await Message.countDocuments({
            unreadBy: userName
        });

        // Check if either user has blocked the other
        const otherUser = seller ? await User.findOne({ userName: seller }) : null;
        const isBlocked = otherUser ? await BlockList.findOne({
            $or: [
                { blocker: user._id, blocked: otherUser._id },
                { blocker: otherUser._id, blocked: user._id }
            ]
        }) : null;

        res.render('messages', { 
            userName,
            conversations,
            currentConversation,
            messages,
            unreadCount,
            isBlocked: !!isBlocked 
        });
    } catch (err) {
        console.error('Error loading messages:', err);
        res.status(500).send('Error loading messages');
    }
});

// Add notification routes
app.get('/notifications', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.session.userEmail });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const notifications = await Notification.find({ userId: user._id })
            .sort({ createdAt: -1 })
            .limit(20)
            .lean(); // Use lean() for better performance

        console.log('Sending notifications:', notifications);
        res.json(notifications);
    } catch (err) {
        console.error('Error fetching notifications:', err);
        res.status(500).json({ error: 'Error fetching notifications' });
    }
});

// Mark single notification as read
app.post('/notifications/:id/read', isAuthenticated, async (req, res) => {
    try {
        await Notification.findByIdAndUpdate(req.params.id, { read: true });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Error updating notification' });
    }
});

// Update the mark all as read route
app.post('/notifications/mark-all-read', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.session.userEmail });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        await Notification.updateMany(
            { userId: user._id },
            { $set: { read: true } }
        );

        res.json({ success: true });
    } catch (err) {
        console.error('Error marking notifications as read:', err);
        res.status(500).json({ error: 'Error updating notifications' });
    }
});

// Update notification routes
app.get('/notifications', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.session.userEmail });
        const notifications = await Notification.find({
            userId: user._id,
            createdAt: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } // Last 30 days
        })
        .populate('productId', 'name')
        .sort({ createdAt: -1 });

        // Mark all notifications as read
        await Notification.updateMany(
            { userId: user._id, read: false },
            { $set: { read: true } }
        );

        res.render('notifications', { 
            userName: user.userName, 
            notifications,
            notificationTypes: {
                offer_accepted: 'Offer Accepted',
                offer_rejected: 'Offer Rejected',
                product_updated: 'Product Updated',
                offer_received: 'New Offer'
            }
        });
    } catch (err) {
        console.error("Error fetching notifications:", err);
        res.status(500).send("Server error");
    }
});

// Add route to mark notification as read
app.post('/notifications/:id/read', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.session.userEmail });
        const notification = await Notification.findOneAndUpdate(
            { _id: req.params.id, userId: user._id },
            { $set: { read: true } },
            { new: true }
        );

        if (!notification) {
            return res.status(404).json({ success: false, message: 'Notification not found' });
        }

        res.json({ success: true });
    } catch (err) {
        console.error("Error marking notification as read:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// Modify report routes to use new schema
app.post("/report-user", isAuthenticated, async (req, res) => {
    try {
        const reporter = await User.findOne({ email: req.session.userEmail });
        const reportedUser = await User.findOne({ userName: req.body.reportedUser });

        const report = new UserReport({
            reporter: reporter._id,
            reportedUser: reportedUser._id,
            reason: req.body.reason,
            details: req.body.details,
            conversationId: req.body.conversationId
        });

        await report.save();
        res.json({ success: true, message: "User reported successfully" });
    } catch (err) {
        console.error("Error reporting user:", err);
        res.status(500).json({ success: false, error: "Error reporting user" });
    }
});

// Modify product report route
app.post("/report-product", isAuthenticated, async (req, res) => {
    try {
        const reporter = await User.findOne({ email: req.session.userEmail });
        
        const report = new ProductReport({
            product: req.body.productId,
            reporter: reporter._id,
            reason: req.body.reason,
            description: req.body.description
        });

        await report.save();
        res.json({ success: true, message: "Product reported successfully" });
    } catch (err) {
        console.error("Error reporting product:", err);
        res.status(500).json({ success: false, error: "Error reporting product" });
    }
});

// Add verification route
app.post("/verify-email", async (req, res) => {
    try {
        const verification = await Verification.findOne({
            email: req.body.email,
            otp: req.body.otp,
            expiresAt: { $gt: new Date() }
        });

        if (!verification) {
            return res.status(400).json({ success: false, error: "Invalid or expired OTP" });
        }

        verification.verified = true;
        await verification.save();

        res.json({ success: true, message: "Email verified successfully" });
    } catch (err) {
        console.error("Error verifying email:", err);
        res.status(500).json({ success: false, error: "Error verifying email" });
    }
});

// Port opening
server.listen(3001, function() {
    console.log("Server started on port 3001");
});

// Update donation collection route
app.post("/donation/:id/collect", isAuthenticated, async (req, res) => {
    try {
        const donationId = req.params.id;
        const user = await User.findOne({ email: req.session.userEmail });

        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const donation = await Donation.findById(donationId).populate('donatedBy');
        if (!donation) {
            return res.status(404).json({ success: false, error: 'Donation not found' });
        }

        if (donation.status !== 'available') {
            return res.status(400).json({ success: false, error: 'Donation is not available' });
        }

        // Update donation status
        donation.status = 'collected';
        donation.collectedBy = user._id;
        await donation.save();

        // Create notification for the donor
        await createNotification({
            userId: donation.donatedBy._id,
            type: 'donation_collected',
            message: `Your donation "${donation.name}" has been collected by ${user.userName}`,
            productId: donationId
        });

        res.json({ success: true });
    } catch (err) {
        console.error("Error collecting donation:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// Add route for viewing collected donations
app.get("/collected-donations", isAuthenticated, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.session.userEmail });
        
        const collectedDonations = await Donation.find({
            collectedBy: user._id,
            status: 'collected'
        }).populate('donatedBy', 'userName email phone address');  // Add fields to populate

        res.render("collected-donations", { 
            donations: collectedDonations,
            userName: user.userName 
        });
    } catch (err) {
        console.error("Error fetching collected donations:", err);
        res.status(500).send("Error fetching collected donations");
    }
});

// Update admin product report handling route
app.post("/admin/review-product-report/:reportId", isAuthenticated, isAuthorized("admin"), async (req, res) => {
    try {
        const { reportId } = req.params;
        const { status, adminNotes } = req.body;

        const report = await ProductReport.findById(reportId);
        if (!report) {
            return res.status(404).json({ success: false, error: "Report not found" });
        }

        report.status = status;
        report.adminNotes = adminNotes;
        report.reviewedAt = new Date();
        await report.save();

        // Create notification for reporter
        await Notification.create({
            userId: report.reporter,
            type: 'report_reviewed',
            message: `Your report for product has been ${status}`,
            productId: report.product,
            read: false
        });

        res.json({ success: true, message: "Report reviewed successfully" });
    } catch (err) {
        console.error("Error reviewing product report:", err);
        res.status(500).json({ success: false, error: "Server error" });
    }
});

// Add this temporary route to see all products
app.get("/all-products", async (req, res) => {
    try {
        const products = await Product.find()
            .populate('seller', 'userName');

        let output = '<pre style="padding: 20px">';
        output += 'ALL PRODUCTS:\n';
        output += '============\n\n';
        
        products.forEach((product, index) => {
            output += `${index + 1}. Product: ${product.name}\n`;
            output += `   Posted by: ${product.seller.userName}\n`;
            output += `   Price: ₹${product.price}\n`;
            output += `   Category: ${product.category}\n`;
            output += `   Status: ${product.status}\n`;
            output += `   Description: ${product.description}\n`;
            output += '   ------------------------\n\n';
        });

        output += '</pre>';
        res.send(output);
    } catch (err) {
        console.error("Error fetching products:", err);
        res.status(500).send("Error fetching products");
    }
});

// Update the /messages/:conversationId route
app.get('/messages/:conversationId', isAuthenticated, async (req, res) => {
    try {
        const conversation = await Conversation.findById(req.params.conversationId)
            .populate('participants', 'userName')
            .populate('messages.sender', 'userName');

        if (!conversation) {
            return res.status(404).json({ error: 'Conversation not found' });
        }

        // Map messages to include all necessary fields and reply data
        const messages = await Promise.all(conversation.messages.map(async msg => {
            let replyToData = null;
            
            if (msg.replyTo && msg.replyTo.id) {
                // Find the replied-to message within the conversation
                const repliedMessage = conversation.messages.find(m => 
                    m.messageId.toString() === msg.replyTo.id.toString()
                );
                
                if (repliedMessage) {
                    const replySender = await User.findById(repliedMessage.sender);
                    replyToData = {
                        id: msg.replyTo.id,
                        type: msg.replyTo.type,
                        text: repliedMessage.text,
                        sender: replySender.userName
                    };
                }
            }

            return {
                messageId: msg.messageId,
                sender: msg.sender.userName,
                text: msg.text,
                createdAt: msg.createdAt,
                replyTo: replyToData
            };
        }));

        res.json({ messages });
    } catch (err) {
        console.error('Error loading messages:', err);
        res.status(500).json({ error: 'Error loading messages' });
    }
});

// Update message route
app.post('/messages/send', isAuthenticated, async (req, res) => {
    try {
        const { conversationId, message, replyTo } = req.body;
        const sender = await User.findOne({ email: req.session.userEmail });

        const conversation = await Conversation.findById(conversationId);
        if (!conversation) {
            return res.status(404).json({ error: 'Conversation not found' });
        }

        const newMessage = {
            messageId: conversation.nextMessageId,
            sender: sender._id,
            text: message,
            replyTo: replyTo ? {
                id: replyTo.id,
                type: replyTo.type,
                text: replyTo.text,
                sender: replyTo.sender
            } : null,
            createdAt: new Date()
        };

        conversation.messages.push(newMessage);
        conversation.nextMessageId += 1;
        await conversation.save();

        // Emit message through socket.io
        io.to(`conversation_${conversationId}`).emit('message', {
            ...newMessage,
            sender: sender.userName
        });

        res.json({ success: true, message: newMessage });
    } catch (err) {
        console.error('Error sending message:', err);
        res.status(500).json({ error: 'Error sending message' });
    }
});

// Add route for viewing user's purchases
app.get("/purchases", isAuthenticated, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.session.userEmail });
        
        // Find all products where this user is the buyer
        const purchases = await Product.find({
            buyer: user._id,
            status: 'sold'
        }).populate('seller', 'userName email phone address');

        res.render("purchases", { 
            purchases: purchases,
            userName: user.userName 
        });
    } catch (err) {
        console.error("Error fetching purchases:", err);
        res.status(500).send("Error fetching purchases");
    }
});

// Update admin product report handling route
app.post("/admin/resolve-product-report/:reportId", isAuthenticated, isAuthorized("admin"), async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const { action, remarks, productId, userId } = req.body;
        const report = await ProductReport.findById(req.params.reportId);
        
        if (!report) {
            throw new Error('Report not found');
        }

        // Common updates
        report.status = 'resolved';
        report.adminNotes = remarks;
        report.reviewedAt = new Date();

        // Handle different actions
        switch (action) {
            case 'block_user':
                const user = await User.findById(userId);
                user.isBlocked = true;
                user.blockedAt = new Date();
                user.blockedReason = remarks;
                await user.save({ session });
                break;

            case 'warn_user':
                await createNotification(
                    userId,
                    'admin_warning',
                    `Warning from admin: ${remarks}`,
                    productId
                );
                break;

            case 'delete_product':
                await Product.findByIdAndDelete(productId, { session });
                break;

            case 'resolve_only':
                // No additional action needed
                break;

            default:
                throw new Error('Invalid action');
        }

        await report.save({ session });
        await session.commitTransaction();

        res.json({ success: true });
    } catch (err) {
        await session.abortTransaction();
        console.error('Error resolving report:', err);
        res.status(500).json({ 
            success: false, 
            error: err.message || 'Error resolving report' 
        });
    } finally {
        session.endSession();
    }
>>>>>>> database-merging
});
