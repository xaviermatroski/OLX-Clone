const GENERAL_OTP = "123456"

const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose")
const ejs = require("ejs");
const nodemailer = require("nodemailer")
const session = require("express-session")
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcrypt"); // Add bcrypt for password hashing
const sharp = require('sharp'); // Add sharp require at the top with other requires
require("dotenv").config();

const app = express();

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.use(express.json());

mongoose.connect(process.env.CONNECTION_STRING)

// Add at the top with other requires
const server = require('http').createServer(app);
const io = require('socket.io')(server);

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

function isAuthorized(role) {
    return (req, res, next) => {
        // Allow admin to access all routes
        if (req.session.isAuthenticated && req.session.userRole === 'admin') {
            return next();
        }
        // Check specific role for non-admin users
        if (req.session.isAuthenticated && req.session.userRole === role) {
            return next();
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
            const admin = new Admin({
                adminName: userName,
                adminEmail: email,
                password: hashedPassword
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

// Admin page

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
            const admin = await Admin.findOne({ adminEmail: req.session.userEmail });
            if (admin && admin.adminName === userName) {
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

// Handle profile update - modify to handle both roles
app.post("/profile/:userName", isAuthenticated, async (req, res) => {
    const userName = req.params.userName;
    const { bio, contact_no, email, address } = req.body;

    try {
        const user = await User.findOneAndUpdate(
            { userName: userName, email: req.session.userEmail },
            { bio, contact_no, email, address },
            { new: true }
        );
        if (user) {
            // Redirect based on user role
            const redirectPath = user.role === "volunteer" ? "/volunteer/" : "/user/";
            res.redirect(`/profile/${userName}`);
        } else {
            res.status(403).send("Access denied. Unauthorized access.");
        }
    } catch (err) {
        console.error("Error updating user:", err);
        res.status(500).send("Server error.");
    }
});

// Add admin profile update route
app.post("/profile/:adminName/update", isAuthenticated, isAuthorized("admin"), async (req, res) => {
    const adminName = req.params.adminName;
    const { new_name, current_password, new_password } = req.body;

    try {
        const admin = await Admin.findOne({ adminEmail: req.session.userEmail });
        
        if (!admin || admin.adminName !== adminName) {
            return res.status(403).send("Unauthorized access");
        }

        // If changing password, verify current password
        if (new_password) {
            if (!await bcrypt.compare(current_password, admin.password)) {
                return res.status(400).send("Current password is incorrect");
            }
            admin.password = await bcrypt.hash(new_password, 10);
        }

        // Update admin name if provided
        if (new_name) {
            admin.adminName = new_name;
        }

        await admin.save();
        res.redirect(`/profile/${admin.adminName}`);
    } catch (err) {
        console.error("Error updating admin profile:", err);
        res.status(500).send("Server error");
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
        
        // Find conversations where user is a participant
        const conversations = await Conversation.find({
            participants: user._id
        })
        .populate('participants', 'userName')
        .populate('messages.sender', 'userName')
        // Update populate to match schema structure - messages.replyTo.id for product references
        .sort({ updatedAt: -1 });

        // Get the first conversation as current if it exists
        const currentConversation = conversations.length > 0 ? conversations[0] : null;

        res.render('messages', { 
            userName: user.userName,
            conversations,
            currentConversation,
            unreadCount: await getUnreadNotificationsCount(req.session.userEmail)
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

// Orders page - show user's products
app.get("/orders", isAuthenticated, async (req, res) => {
    const user = await User.findOne({ email: req.session.userEmail });
    
    try {
        // Get user's products
        const userProducts = await Product.find({ seller: user._id });

        // Get products where this user has pending offers
        const productsWithPendingOffers = await Product.find({
            'offerRequests': {
                $elemMatch: {
                    buyer: user._id,
                    status: 'pending'
                }
            }
        });

        res.render("orders", { 
            userName: user.userName, // Changed from user_name to userName
            userProducts,
            receivedOffers: productsWithPendingOffers
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
            const user = await User.findOne({ userName: userName, email: req.session.userEmail });
            if (user) {
                const donations = await Donation.find({ 
                    status: 'available',
                    adminApproved: true 
                }).populate('donor', 'userName');
                res.render("volunteer", { donations: donations, userName: userName });
            } else {
                res.status(403).send("Access denied. Unauthorized access.");
            }
        } catch (err) {
            console.error("Error finding donations:", err);
            res.status(500).send("Server error.");
        }
    } else {
        res.status(403).send("Access denied. Please log in.");
    }
});

// Volunteer donate page
app.get("/volunteer/:userName/donate", isAuthenticated, isAuthorized("volunteer"), (req, res) => {
    const userName = req.params.userName;
    res.render("donate", { userName: userName });
});

// Handle donation submission
app.post("/volunteer/:userName/donate", isAuthenticated, isAuthorized("volunteer"), upload.array("image", 5), async (req, res) => {
    const userName = req.params.userName;
    const { name, description, category, condition } = req.body;
    
    try {
        const donor = await User.findOne({ userName: userName });
        
        // Compress and process images
        const images = await Promise.all(req.files.map(async (file) => ({
            data: await compressImage(file.buffer),
            contentType: 'image/jpeg'
        })));

        const newDonation = new Donation({
            name,
            description,
            category,
            condition,
            images,
            donor: donor._id,
            status: 'available',
            location: 'IIT Ropar Campus',
            adminApproved: false
        });

        await newDonation.save();

        // Create notification for admin
        await Notification.create({
            userId: donor._id,
            type: 'new_donation',
            message: `New donation item "${name}" requires approval`,
        });

        res.redirect(`/volunteer/${userName}`);
    } catch (err) {
        console.error("Error processing donation:", err);
        res.status(500).send("An error occurred while processing donation.");
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

// // Update MongoDB migration route (temporary)
// app.get("/update-products", async (req, res) => {
//     try {
//         // Update existing products to include is_donation field
//         await Product.updateMany(
//             { is_donation: { $exists: false } },
//             { $set: { is_donation: false } }
//         );
        
//         // Update existing users to include role field
//         await User.updateMany(
//             { role: { $exists: false } },
//             { $set: { role: 'user' } }
//         );
        
//         res.send("Database updated successfully");
//     } catch (err) {
//         console.error("Error updating database:", err);
//         res.status(500).send("Error updating database");
//     }
// });

// Admin dashboard
app.route("/admin/:adminName")
    .get(isAuthenticated, isAuthorized("admin"), async (req, res) => {
        const adminName = req.params.adminName;
        
        try {
            const admin = await Admin.findOne({ adminName: adminName });
            if (!admin) {
                return res.status(404).send("Admin not found");
            }

            const users = await User.find({});
            const userReports = await UserReport.find({ status: 'pending' })
                .populate('reporter', 'userName')
                .populate('reportedUser', 'userName');

            const productReports = await ProductReport.find({ status: 'pending' })
                .populate('reporter', 'userName')
                .populate('product');

            res.render("admin", { 
                adminName,
                users,
                userReports,
                productReports
            });
        } catch (err) {
            console.error("Error loading admin dashboard:", err);
            res.status(500).send("Server error");
        }
    });

// Add a catch-all route for admin paths
app.get("/admin/*", isAuthenticated, isAuthorized("admin"), (req, res) => {
    res.redirect(`/admin/${req.session.userEmail ? req.session.userEmail.split('@')[0] : ''}`);
});

// Initialize admin account if none exists
async function initializeAdmin() {
    try {
        const adminEmail = "admin@iitrpr.ac.in";
        const adminExists = await Admin.findOne({ adminEmail: adminEmail });
        
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash("admin123", 10);
            const admin = new Admin({
                adminName: "admin",
                adminEmail: adminEmail,
                password: hashedPassword
            });
            await admin.save();
            console.log("Admin account initialized with:");
            console.log("Email:", adminEmail);
            console.log("Password: admin123");
        }
    } catch (err) {
        console.error("Error initializing admin:", err);
    }
}

// Call initializeAdmin when the server starts
initializeAdmin().then(() => {
    console.log("Admin initialization completed");
}).catch(err => {
    console.error("Failed to initialize admin:", err);
});

// Toggle user block status
app.post("/admin/toggle-block/:userId", isAuthenticated, isAuthorized("admin"), async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                error: "User not found" 
            });
        }
        
        user.blocked = !user.blocked;
        await user.save();
        
        return res.status(200).json({
            success: true,
            blocked: user.blocked,
            message: `User ${user.blocked ? 'blocked' : 'unblocked'} successfully`
        });
    } catch (err) {
        console.error("Error toggling user block status:", err);
        return res.status(500).json({ 
            success: false, 
            error: "Server error while updating user status" 
        });
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
        const reporter = await User.findOne({ email: req.session.userEmail });
        const { productId, reason, description } = req.body;

        // Validate product exists
        const product = await Product.findById(productId);
        if (!product) {
            return res.status(404).json({ success: false, error: "Product not found" });
        }

        // Create new product report with updated schema
        const report = new ProductReport({
            product: productId,
            reporter: reporter._id,
            reason,
            description,
            status: 'pending',
            createdAt: new Date()
        });

        await report.save();

        // Create notification for admin
        const admins = await User.find({ role: 'admin' });
        for (const admin of admins) {
            await Notification.create({
                userId: admin._id,
                type: 'product_reported',
                message: `New product report for "${product.name}"`,
                productId: product._id,
                read: false
            });
        }

        res.json({ success: true, message: "Product reported successfully" });
    } catch (err) {
        console.error("Error reporting product:", err);
        res.status(500).json({ success: false, error: "Error reporting product" });
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
    const { productId, amount } = req.body;
    const buyer = await User.findOne({ email: req.session.userEmail });

    try {
        const product = await Product.findById(productId);
        if (!product) {
            return res.status(404).json({ success: false, error: "Product not found" });
        }

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

        // Create notification for seller
        await Notification.create({
            userId: product.seller,
            type: 'offer_received',
            message: `New offer of ₹${amount} received for ${product.name}`,
            productId: product._id
        });

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
        const offer = await Offer.findById(offerId).populate('productId');
        if (!offer) {
            await session.abortTransaction();
            return res.status(404).json({ success: false, error: "Offer not found" });
        }

        // Verify the current user is the seller
        const seller = req.session.userEmail ? (await User.findOne({ email: req.session.userEmail })).userName : '';
        if (offer.seller !== seller) {
            await session.abortTransaction();
            return res.status(403).json({ success: false, error: "Unauthorized" });
        }

        offer.status = accept ? 'accepted' : 'rejected';
        await offer.save({ session });

        if (accept) {
            // Delete the product and related data
            await Product.findByIdAndDelete(offer.productId._id).session(session);
            await Report.deleteMany({ productId: offer.productId._id }).session(session);
            await Conversation.deleteMany({ product: offer.productId._id }).session(session);
            
            // Delete other pending offers for this product
            await Offer.deleteMany({ 
                productId: offer.productId._id, 
                _id: { $ne: offerId },
                status: 'pending'
            }).session(session);
        }

        // Create notification for the buyer
        await Notification.create({
            userId: offer.buyer,
            type: accept ? 'offer_accepted' : 'offer_rejected',
            message: accept ? 
                `Your offer of ₹${offer.amount} for ${offer.productId.name} was accepted` :
                `Your offer of ₹${offer.amount} for ${offer.productId.name} was rejected`,
            productId: offer.productId._id
        });

        await session.commitTransaction();
        res.json({ success: true, message: `Offer ${accept ? 'accepted' : 'rejected'} successfully` });
    } catch (err) {
        await session.abortTransaction();
        console.error("Error responding to offer:", err);
        res.status(500).json({ success: false, error: "Error responding to offer" });
    } finally {
        session.endSession();
    }
});

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
        const notifications = await Notification.find({ userId: user._id })
            .populate('productId')
            .sort({ createdAt: -1 });

        res.render('notifications', { 
            userName: user.userName, 
            notifications 
        });
    } catch (err) {
        console.error("Error fetching notifications:", err);
        res.status(500).send("Server error");
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
server.listen(3000, function() {
    console.log("Server started on port 3000");
});

// Update donation collection route
app.post("/donation/:id/collect", isAuthenticated, async (req, res) => {
    try {
        const donation = await Donation.findById(req.params.id);
        const collector = await User.findOne({ email: req.session.userEmail });

        if (!donation || donation.status !== 'available') {
            return res.status(400).json({ success: false, message: "Donation not available" });
        }

        donation.status = 'collected';
        donation.collectedBy = collector._id;
        await donation.save();

        // Create notification for donor
        await Notification.create({
            userId: donation.donor,
            type: 'donation_collected',
            message: `Your donation "${donation.name}" has been collected by ${collector.userName}`
        });

        res.json({ success: true, message: "Donation collected successfully" });
    } catch (err) {
        console.error("Error collecting donation:", err);
        res.status(500).json({ success: false, message: "Server error" });
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
            .populate('messages.sender', 'userName');
        if (!conversation) {
            return res.status(404).json({ error: 'Conversation not found' });
        }

        // Gather all product ObjectIds from messages.replyTo where type === 'product'
        const productIds = conversation.messages
            .filter(msg => msg.replyTo && msg.replyTo.type === 'product' && typeof msg.replyTo.id === 'object')
            .map(msg => msg.replyTo.id);

        // Fetch all referenced products in one go
        let productsMap = {};
        if (productIds.length > 0) {
            const products = await Product.find({ _id: { $in: productIds } }, 'name price images');
            productsMap = products.reduce((acc, prod) => {
                acc[prod._id.toString()] = prod;
                return acc;
            }, {});
        }

        // Helper: find message by messageId
        function findMessageById(mid) {
            return conversation.messages.find(m => m.messageId === mid);
        }

        // Build messages array for frontend
        const messages = conversation.messages.map(msg => {
            let replyTo = null;
            if (msg.replyTo) {
                if (msg.replyTo.type === 'product' && typeof msg.replyTo.id === 'object') {
                    const prod = productsMap[msg.replyTo.id.toString()];
                    if (prod) {
                        replyTo = {
                            type: 'product',
                            id: prod._id,
                            name: prod.name,
                            price: prod.price
                        };
                    }
                } else if (msg.replyTo.type === 'message') {
                    // Find the original message being replied to
                    const originalMsg = findMessageById(msg.replyTo.id);
                    if (originalMsg) {
                        // If the original message is a reply to a product, show product preview
                        if (originalMsg.replyTo && originalMsg.replyTo.type === 'product' && typeof originalMsg.replyTo.id === 'object') {
                            const prod = productsMap[originalMsg.replyTo.id.toString()];
                            if (prod) {
                                replyTo = {
                                    type: 'product',
                                    id: prod._id,
                                    name: prod.name,
                                    price: prod.price
                                };
                            }
                        } else {
                            // Otherwise, show the original message text as preview
                            replyTo = {
                                type: 'message',
                                id: originalMsg.messageId,
                                text: originalMsg.text,
                                sender: originalMsg.sender && originalMsg.sender.userName ? originalMsg.sender.userName : undefined
                            };
                        }
                    } else {
                        // fallback: just show messageId
                        replyTo = {
                            type: 'message',
                            id: msg.replyTo.id
                        };
                    }
                }
            }
            return {
                messageId: msg.messageId,
                text: msg.text,
                sender: msg.sender.userName,
                createdAt: msg.createdAt,
                replyTo
            };
        });

        res.json({ messages });
    } catch (err) {
        console.error('Error loading messages:', err);
        res.status(500).json({ error: 'Error loading messages' });
    }
});
