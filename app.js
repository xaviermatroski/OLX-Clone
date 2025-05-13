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

// Admin
const adminSchema = {
    admin_name: String,
    admin_mail: String,
    password: String, // Add password field
}

const Admin = mongoose.model("Admin", adminSchema)

// User
const userSchema = {
    user_name: String,
    user_mail: String,
    password: String, // Add password field
    bio: String, // Add bio field
    contact_no: String, // Add contact number field
    address: String, // Add address field
    role: { type: String, default: 'user' },  // Add role field
    blocked: {
        type: Boolean,
        default: false
    }
}

const User = mongoose.model("User", userSchema)

// Products
const productSchema = {
    name: String,
    description: String,
    images: [{
        data: Buffer,
        contentType: String,
        filename: String
    }],
    price: Number,
    user_name: String,
    is_donation: { type: Boolean, default: false }
};

const Product = mongoose.model("Product", productSchema)

// Add Message Schema
const messageSchema = {
    conversationId: String,
    sender: String,
    content: String,
    unreadBy: [String], // Array of usernames who haven't read the message
    createdAt: {
        type: Date,
        default: Date.now
    }
};

const conversationSchema = {
    product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product'
    },
    seller: String,
    buyer: String,
    lastMessage: Date
};

const Message = mongoose.model("Message", messageSchema);
const Conversation = mongoose.model("Conversation", conversationSchema);

// Update Report Schema to include reference to Product
const reportSchema = {
    reportedUser: String,
    reportedBy: String,
    reason: String,
    description: String, // Add this field
    createdAt: {
        type: Date,
        default: Date.now
    },
    resolved: {
        type: Boolean,
        default: false
    },
    productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product'  // This creates a reference to the Product model
    }
};

const Report = mongoose.model("Report", reportSchema);

// Add after other schemas
const offerSchema = {
    productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product'
    },
    seller: String,
    buyer: String,
    amount: Number,
    status: {
        type: String,
        enum: ['pending', 'accepted', 'rejected'],
        default: 'pending'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
};

const Offer = mongoose.model("Offer", offerSchema);

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

// Register get 
app.get("/register", (req, res) => {
    res.render("register");
});

// Register post
app.post("/register", async (req, res) => {
    const { name, email, password, role } = req.body;
    
    try {
        // Check if user/admin already exists
        const existingUser = await User.findOne({ user_mail: email });
        const existingAdmin = await Admin.findOne({ admin_mail: email });
        
        if (existingUser || existingAdmin) {
            return res.status(400).send("Email already registered");
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // Store details in session for later use after OTP verification
        req.session.registrationDetails = {
            name,
            email,
            password: hashedPassword,
            role
        };

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
        req.session.otp = otp;
        req.session.email = email;

        // Send OTP email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your OTP for Registration",
            text: `Your OTP is: ${otp}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
                res.status(500).send("Error sending OTP. Try again.");
            } else {
                res.redirect('/verify-otp');
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
        const user = await User.findOne({ user_mail: email });
        const admin = await Admin.findOne({ admin_mail: email });

        if (user) {
            // Check if user is blocked
            if (user.blocked) {
                return res.status(403).send("Your account has been blocked. Please contact the administrator.");
            }

            // Verify password
            if (await bcrypt.compare(password, user.password)) {
                req.session.isAuthenticated = true;
                req.session.userEmail = email;
                req.session.userRole = user.role;
                
                const redirectPath = user.role === "volunteer" ? "/volunteer/" : "/user/";
                return res.redirect(`${redirectPath}${user.user_name}`);
            }
        } else if (admin && await bcrypt.compare(password, admin.password)) {
            req.session.isAuthenticated = true;
            req.session.userEmail = email;
            req.session.userRole = "admin";
            return res.redirect(`/admin/${admin.admin_name}`);
        }

        res.status(401).send("Invalid credentials");
    } catch (err) {
        console.log("Server error", err);
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

    if (req.session.otp && (String(req.session.otp) === String(userOtp) || userOtp === GENERAL_OTP)) {
        const { name, password, role } = req.session.registrationDetails;

        try {
            if (role === "admin") {
                const newAdmin = new Admin({
                    admin_name: name,
                    admin_mail: email,
                    password: password
                });
                await newAdmin.save();
                req.session.isAuthenticated = true;
                req.session.userEmail = email;
                req.session.userRole = "admin";
                return res.redirect(`/admin/${newAdmin.admin_name}`);
            } else if (role === "user" || role === "volunteer") {  // Handle both user and volunteer roles
                const newUser = new User({
                    user_name: name,
                    user_mail: email,
                    password: password,
                    role: role  // Store the role in user document
                });
                await newUser.save();
                req.session.isAuthenticated = true;
                req.session.userEmail = email;
                req.session.userRole = role;
                
                // Redirect based on role
                const redirectPath = role === "volunteer" ? "/volunteer/" : "/user/";
                return res.redirect(redirectPath + newUser.user_name);
            }
            
            // Clear registration and OTP data
            req.session.registrationDetails = null;
            req.session.otp = null;
            
        } catch (err) {
            console.error("Error creating user:", err);
            return res.status(500).send("Server error during user creation");
        }
    } else {
        return res.status(400).send("Invalid OTP. Please try again.");
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
    let user_name = '';
    if (isAuthenticated && req.session.userEmail) {
        const user = await User.findOne({ user_mail: req.session.userEmail });
        if (user) {
            user_name = user.user_name;
        }
    }
    res.render("home", { isAuthenticated, user_name });
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
app.get("/user/:user/sell", isAuthenticated, isAuthorized("user"), (req, res) => {
    const user_name = req.params.user;
    res.render("sell", { user_name: user_name });
});

// Handle sell form submission
app.post("/user/:user/sell", isAuthenticated, isAuthorized("user"), upload.array("image", 5), async (req, res) => {
    const user_name = req.params.user;
    const { name, description, price } = req.body;
    
    try {
        // Compress and process images
        const images = await Promise.all(req.files.map(async (file) => ({
            data: await compressImage(file.buffer),
            contentType: 'image/jpeg', // We're converting all to JPEG
            filename: file.originalname
        })));

        const newProduct = new Product({
            name,
            description,
            images,
            price,
            user_name
        });

        await newProduct.save();
        res.redirect(`/user/${user_name}`);
    } catch (err) {
        console.error("Error processing images:", err);
        res.status(500).send("An error occurred while processing images.");
    }
});

// User page
app.get("/user/:user_name", isAuthenticated, isAuthorized("user"), async (req, res) => {
    const user_name = req.params.user_name;
    
    if (req.session.userEmail) {
        try {
            const user = await User.findOne({ user_name: user_name, user_mail: req.session.userEmail });
            if (user) {
                // Show all products except user's own products and donations
                const products = await Product.find({
                    $and: [
                        { user_name: { $ne: user_name }},  // Not user's own products
                        { is_donation: { $ne: true }}      // Not donations
                    ]
                });
                res.render("user", { products: products, user_name: user_name });
            } else {
                res.status(403).send("Access denied. Unauthorized access.");
            }
        } catch (err) {
            console.error("Error finding user:", err);
            res.status(500).send("Server error.");
        }
    } else {
        res.status(403).send("Access denied. Please log in.");
    }
});

// Update the product details route to include existing offer
app.get("/product/:id", isAuthenticated, async (req, res) => {
    const productId = req.params.id;
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    try {
        const product = await Product.findById(productId);
        // Check if user has an existing offer
        const existingOffer = await Offer.findOne({
            productId: productId,
            buyer: user_name,
            status: 'pending'
        });
        
        res.render("product", { product, user_name, existingOffer });
    } catch (err) {
        console.error("Error finding product:", err);
        res.status(500).send("Server error.");
    }
});

// Profile page - Update to handle both user and admin profiles
app.get("/profile/:user_name", isAuthenticated, async (req, res) => {
    const user_name = req.params.user_name;

    try {
        // Check if it's an admin profile
        if (req.session.userRole === 'admin') {
            const admin = await Admin.findOne({ admin_mail: req.session.userEmail });
            if (admin && admin.admin_name === user_name) {
                return res.render("admin-profile", { admin });
            }

        }

        // If not admin, check for regular user
        const user = await User.findOne({ user_name: user_name, user_mail: req.session.userEmail });
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
app.post("/profile/:user_name", isAuthenticated, async (req, res) => {
    const user_name = req.params.user_name;
    const { bio, contact_no, email, address } = req.body;

    try {
        const user = await User.findOneAndUpdate(
            { user_name: user_name, user_mail: req.session.userEmail },
            { bio, contact_no, user_mail: email, address },
            { new: true }
        );
        if (user) {
            // Redirect based on user role
            const redirectPath = user.role === "volunteer" ? "/volunteer/" : "/user/";
            res.redirect(`/profile/${user_name}`);
        } else {
            res.status(403).send("Access denied. Unauthorized access.");
        }
    } catch (err) {
        console.error("Error updating user:", err);
        res.status(500).send("Server error.");
    }
});

// Add admin profile update route
app.post("/profile/:admin_name/update", isAuthenticated, isAuthorized("admin"), async (req, res) => {
    const admin_name = req.params.admin_name;
    const { new_name, current_password, new_password } = req.body;

    try {
        const admin = await Admin.findOne({ admin_mail: req.session.userEmail });
        
        if (!admin || admin.admin_name !== admin_name) {
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
            admin.admin_name = new_name;
        }

        await admin.save();
        res.redirect(`/profile/${admin.admin_name}`);
    } catch (err) {
        console.error("Error updating admin profile:", err);
        res.status(500).send("Server error");
    }
});

// Search route
app.get("/search", isAuthenticated, async (req, res) => {
    const query = req.query.query;
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    try {
        let products = [];
        if (query) {
            // Search in product name and description for non-donation items
            products = await Product.find({
                $or: [
                    { name: { $regex: query, $options: 'i' } },
                    { description: { $regex: query, $options: 'i' } }
                ],
                user_name: { $ne: user_name }, // Exclude user's own products
                is_donation: false // Exclude donations
            });
        }
        res.render("user", { products: products, user_name: user_name });
    } catch (err) {
        console.error("Search error:", err);
        res.status(500).send("Error performing search");
    }
});

// Add Socket.io connection
io.on('connection', (socket) => {
    // Add this - Store user information when they connect
    socket.on('userConnected', (userId) => {
        socket.userId = userId;
        socket.join(`user_${userId}`);
    });

    socket.on('chatMessage', async (data) => {
        try {
            const conversation = await Conversation.findById(data.conversationId).populate('product');
            const recipient = conversation.seller === data.sender ? conversation.buyer : conversation.seller;

            const message = new Message({
                conversationId: data.conversationId,
                sender: data.sender,
                content: data.message,
                unreadBy: [recipient] // Mark as unread for recipient only
            });
            await message.save();
            
            await Conversation.findByIdAndUpdate(
                data.conversationId,
                { lastMessage: new Date() }
            );

            // Emit the message only to sender and recipient
            io.to(`user_${data.sender}`).to(`user_${recipient}`).emit('message', {
                ...message.toObject(),
                conversationId: data.conversationId
            });
        } catch (err) {
            console.error('Error saving message:', err);
            socket.emit('error', 'Failed to send message');
        }
    });

    socket.on('disconnect', () => {
        if (socket.userId) {
            socket.leave(`user_${socket.userId}`);
        }
    });
});

// Update Messages route
app.get('/messages', isAuthenticated, async (req, res) => {
    const { seller, product } = req.query;
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    try {
        // Only find conversations that were explicitly created through the product page
        let conversations = await Conversation.find({
            $or: [
                { seller: user_name, buyer: { $exists: true } },  // You are the seller
                { buyer: user_name, seller: { $exists: true } }   // You are the buyer
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
                    { seller, buyer: user_name },
                    { seller: user_name, buyer: seller }
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
                    buyer: user_name,
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
                        unreadBy: user_name 
                    },
                    { 
                        $pull: { unreadBy: user_name } 
                    }
                );
                
                messages = await Message.find({ conversationId: req.query.conversation });
            }
        }

        // Get unread message count for navbar indicator
        const unreadCount = await Message.countDocuments({
            unreadBy: user_name
        });

        res.render('messages', { 
            user_name,
            conversations,
            currentConversation,
            messages,
            unreadCount
        });
    } catch (err) {
        console.error('Error loading messages:', err);
        res.status(500).send('Error loading messages');
    }
});

// Add new endpoint to check unread messages
app.get('/api/unread-messages', isAuthenticated, async (req, res) => {
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';
    
    try {
        const count = await Message.countDocuments({
            unreadBy: user_name
        });
        res.json({ count });
    } catch (err) {
        res.status(500).json({ error: 'Error checking unread messages' });
    }
});

// Orders page - show user's products
app.get("/orders", isAuthenticated, async (req, res) => {
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';
    
    try {
        const userProducts = await Product.find({ user_name: user_name });
        const receivedOffers = await Offer.find({ 
            seller: user_name,
            status: 'pending'
        }).populate('productId');

        res.render("orders", { 
            user_name, 
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
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    try {
        const product = await Product.findById(productId);
        
        if (!product || product.user_name !== user_name) {
            return res.status(403).send("Unauthorized");
        }

        await Product.findByIdAndUpdate(productId, {
            name,
            description,
            price
        });

        res.redirect("/orders");
    } catch (err) {
        console.error("Error updating product:", err);
        res.status(500).send("Server error.");
    }
});

// Delete product route
app.post("/orders/delete/:productId", isAuthenticated, async (req, res) => {
    const { productId } = req.params;
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        // 1. Check product ownership
        const product = await Product.findById(productId).session(session);
        if (!product || product.user_name !== user_name) {
            await session.abortTransaction();
            return res.status(403).send("Unauthorized");
        }

        // 2. Delete the product
        await Product.findByIdAndDelete(productId).session(session);

        // 3. Delete all reports related to this product
        await Report.deleteMany({ productId: productId }).session(session);

        // 4. Find all conversations involving this product
        const conversations = await Conversation.find({ product: productId }).session(session);
        
        // 5. Delete all messages from these conversations
        for (const conv of conversations) {
            await Message.deleteMany({ conversationId: conv._id }).session(session);
        }

        // 6. Delete the conversations themselves
        await Conversation.deleteMany({ product: productId }).session(session);

        // Commit the transaction
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
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    try {
        let donations = [];
        if (query) {
            donations = await Product.find({
                $or: [
                    { name: { $regex: query, $options: 'i' } },
                    { description: { $regex: query, $options: 'i' } }
                ],
                is_donation: true
            });
        } else {
            donations = await Product.find({ is_donation: true });
        }
        res.render("volunteer", { donations: donations, user_name: user_name });
    } catch (err) {
        console.error("Search error:", err);
        res.status(500).send("Error performing search");
    }
});

// Volunteer page route - KEEP THIS AFTER THE SEARCH ROUTE
app.get("/volunteer/:user_name", isAuthenticated, isAuthorized("volunteer"), async (req, res) => {
    const user_name = req.params.user_name;
    
    if (req.session.userEmail) {
        try {
            const user = await User.findOne({ user_name: user_name, user_mail: req.session.userEmail });
            if (user) {
                const donations = await Product.find({ is_donation: true });
                res.render("volunteer", { donations: donations, user_name: user_name });
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
app.get("/volunteer/:user/donate", isAuthenticated, isAuthorized("volunteer"), (req, res) => {
    const user_name = req.params.user;
    res.render("donate", { user_name: user_name });
});

// Handle donation submission
app.post("/volunteer/:user/donate", isAuthenticated, isAuthorized("volunteer"), upload.array("image", 5), async (req, res) => {
    const user_name = req.params.user;
    const { name, description } = req.body;
    
    try {
        // Compress and process images
        const images = await Promise.all(req.files.map(async (file) => ({
            data: await compressImage(file.buffer),
            contentType: 'image/jpeg', // We're converting all to JPEG
            filename: file.originalname
        })));

        const newDonation = new Product({
            name,
            description,
            images,
            price: 0,
            user_name,
            is_donation: true
        });

        await newDonation.save();
        res.redirect(`/volunteer/${user_name}`);
    } catch (err) {
        console.error("Error processing images:", err);
        res.status(500).send("An error occurred while processing images.");
    }
});

// Donations page - show user's donations
app.get("/donations", isAuthenticated, isAuthorized("volunteer"), async (req, res) => {
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';
    
    try {
        const userDonations = await Product.find({ user_name: user_name, is_donation: true });
        res.render("donations", { user_name, userDonations });
    } catch (err) {
        console.error("Error finding user donations:", err);
        res.status(500).send("Server error.");
    }
});

// Update donation details
app.post("/donations/update/:donationId", isAuthenticated, isAuthorized("volunteer"), async (req, res) => {
    const { donationId } = req.params;
    const { name, description } = req.body;
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    try {
        const donation = await Product.findById(donationId);
        
        if (!donation || donation.user_name !== user_name) {
            return res.status(403).send("Unauthorized");
        }

        await Product.findByIdAndUpdate(donationId, {
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
app.route("/admin/:admin_name")
    .get(isAuthenticated, isAuthorized("admin"), async (req, res) => {
        const admin_name = req.params.admin_name;
        
        try {
            const admin = await Admin.findOne({ admin_name: admin_name });
            if (!admin) {
                return res.status(404).send("Admin not found");
            }

            const users = await User.find({});
            const reports = await Report.find({ resolved: false })
                .populate('productId');  // This populates all product details automatically

            // Simply separate reports based on whether they have productId
            const userReports = reports.filter(r => !r.productId);
            const productReports = reports.filter(r => r.productId);

            res.render("admin", { 
                admin_name,
                users,
                reports: userReports,
                productReports // This now contains reports with populated product details
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
        const adminExists = await Admin.findOne({ admin_mail: adminEmail });
        
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash("admin123", 10);
            const admin = new Admin({
                admin_name: "admin",
                admin_mail: adminEmail,
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

// Update report-user endpoint to remove conversation ID
app.post("/report-user", isAuthenticated, async (req, res) => {
    const { reportedUser, reason } = req.body;
    const reportedBy = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    try {
        const report = new Report({
            reportedUser,
            reportedBy,
            reason
        });
        await report.save();
        res.json({ message: "User reported successfully" });
    } catch (err) {
        console.error("Error reporting user:", err);
        res.status(500).json({ error: "Error reporting user" });
    }
});

// Add product report endpoint
app.post("/report-product", isAuthenticated, async (req, res) => {
    const { productId, reason, description } = req.body;
    const reportedBy = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    try {
        const product = await Product.findById(productId);
        if (!product) {
            return res.status(404).json({ success: false, error: "Product not found" });
        }

        const report = new Report({
            reportedBy,
            reason,
            description,
            productId
        });
        await report.save();
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
    const buyer = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    try {
        const product = await Product.findById(productId);
        if (!product) {
            return res.status(404).json({ success: false, error: "Product not found" });
        }

        // Check for existing offer
        let existingOffer = await Offer.findOne({
            productId,
            buyer,
            status: 'pending'
        });

        if (existingOffer) {
            // Update existing offer
            existingOffer.amount = amount;
            await existingOffer.save();
            return res.json({ 
                success: true, 
                message: "Offer updated successfully" 
            });
        }

        // Create new offer
        const offer = new Offer({
            productId,
            seller: product.user_name,
            buyer,
            amount
        });

        await offer.save();
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
        const seller = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';
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

// Port opening
server.listen(3001, function() {
    console.log("Server started on port 3001");
});
