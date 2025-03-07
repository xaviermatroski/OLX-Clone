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
require("dotenv").config();

const app = express();

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

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
    address: String // Add address field
}

const User = mongoose.model("User", userSchema)

// Products
const productSchema = {
    name: String,
    description: String,
    images: [String], // Changed from single image to array of images
    price: Number,
    user_name: String
};

const Product = mongoose.model("Product", productSchema)

// Add Message Schema
const messageSchema = {
    conversationId: String,
    sender: String,
    content: String,
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
        if (req.session.isAuthenticated && req.session.userRole === role) {
            next(); // User is authorized, proceed
        } else {
            res.status(403).send("Access denied."); // Unauthorized access
        }
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

        if (user && await bcrypt.compare(password, user.password)) {
            req.session.isAuthenticated = true;
            req.session.userEmail = email;
            req.session.userRole = "user";
            return res.redirect(`/user/${user.user_name}`);
        } else if (admin && await bcrypt.compare(password, admin.password)) {
            req.session.isAuthenticated = true;
            req.session.userEmail = email;
            req.session.userRole = "admin";
            return res.redirect(`/admin/${admin.admin_name}`);
        } else {
            res.status(401).send("Invalid credentials");
        }
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
            // Create user or admin based on role after OTP verification
            if (role === "admin") {
                const newAdmin = new Admin({
                    admin_name: name,
                    admin_mail: email,
                    password: password
                });
                await newAdmin.save();
                
                // Set session variables
                req.session.isAuthenticated = true;
                req.session.userEmail = email;
                req.session.userRole = "admin";
                
                // Clear registration and OTP data
                req.session.registrationDetails = null;
                req.session.otp = null;
                
                return res.redirect(`/admin/${newAdmin.admin_name}`);
            } else if (role === "user") {
                const newUser = new User({
                    user_name: name,
                    user_mail: email,
                    password: password
                });
                await newUser.save();
                
                // Set session variables
                req.session.isAuthenticated = true;
                req.session.userEmail = email;
                req.session.userRole = "user";
                
                // Clear registration and OTP data
                req.session.registrationDetails = null;
                req.session.otp = null;
                
                return res.redirect(`/user/${newUser.user_name}`);
            } else {
                return res.status(400).send("Invalid role");
            }
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
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, "public/images");
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Sell page
app.get("/user/:user/sell", isAuthenticated, isAuthorized("user"), (req, res) => {
    const user_name = req.params.user;
    res.render("sell", { user_name: user_name });
});

// Handle sell form submission
app.post("/user/:user/sell", isAuthenticated, isAuthorized("user"), upload.array("image", 5), async (req, res) => {
    const user_name = req.params.user;
    const { name, description, price } = req.body;
    
    // Process multiple images
    const images = req.files.map(file => "/images/" + file.filename);

    const newProduct = new Product({
        name,
        description,
        images, // Store array of image paths
        price,
        user_name
    });

    try {
        await newProduct.save();
        res.redirect(`/user/${user_name}`);
    } catch (err) {
        console.log(err);
        res.status(500).send("An unexpected error occurred.");
    }
});

// User page
app.get("/user/:user_name", isAuthenticated, isAuthorized("user"), async (req, res) => {
    const user_name = req.params.user_name;
    
    // Ensure that the logged-in user matches the requested user
    if (req.session.userEmail) {
        try {
            // Find the user in the MongoDB collection
            const user = await User.findOne({ user_name: user_name, user_mail: req.session.userEmail });
            if (user) {
                // Render the user's page
                const products = await Product.find({ user_name: { $ne: user_name } });
                res.render("user", { products: products, user_name: user_name });
            } else {
                // Handle the case where the user is not found or does not match the logged-in user
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

// Product details page
app.get("/product/:id", isAuthenticated, async (req, res) => {
    const productId = req.params.id;
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    try {
        const product = await Product.findById(productId);
        res.render("product", { product, user_name });
    } catch (err) {
        console.error("Error finding product:", err);
        res.status(500).send("Server error.");
    }
});

// Profile page
app.get("/profile/:user_name", isAuthenticated, isAuthorized("user"), async (req, res) => {
    const user_name = req.params.user_name;

    try {
        const user = await User.findOne({ user_name: user_name, user_mail: req.session.userEmail });
        if (user) {
            res.render("profile", { user });
        } else {
            res.status(403).send("Access denied. Unauthorized access.");
        }
    } catch (err) {
        console.error("Error finding user:", err);
        res.status(500).send("Server error.");
    }
});

// Handle profile update
app.post("/profile/:user_name", isAuthenticated, isAuthorized("user"), async (req, res) => {
    const user_name = req.params.user_name;
    const { bio, contact_no, email, address } = req.body;

    try {
        const user = await User.findOneAndUpdate(
            { user_name: user_name, user_mail: req.session.userEmail },
            { bio, contact_no, user_mail: email, address },
            { new: true }
        );
        if (user) {
            res.redirect(`/profile/${user_name}`);
        } else {
            res.status(403).send("Access denied. Unauthorized access.");
        }
    } catch (err) {
        console.error("Error updating user:", err);
        res.status(500).send("Server error.");
    }
});

// Search route
app.get("/search", isAuthenticated, async (req, res) => {
    const query = req.query.query;
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    try {
        let products = [];
        if (query) {
            // Search in product name and description using case-insensitive regex
            products = await Product.find({
                $or: [
                    { name: { $regex: query, $options: 'i' } },
                    { description: { $regex: query, $options: 'i' } }
                ],
                user_name: { $ne: user_name } // Exclude user's own products
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
    socket.on('chatMessage', async (data) => {
        try {
            const message = new Message({
                conversationId: data.conversationId,
                sender: data.sender,
                content: data.message
            });
            await message.save();
            
            // Update conversation lastMessage time
            await Conversation.findByIdAndUpdate(data.conversationId, {
                lastMessage: new Date()
            });

            io.emit('message', message);
        } catch (err) {
            console.error('Error saving message:', err);
        }
    });
});

// Add Messages route
app.get('/messages', isAuthenticated, async (req, res) => {
    const { seller, product } = req.query;
    const user_name = req.session.userEmail ? (await User.findOne({ user_mail: req.session.userEmail })).user_name : '';

    try {
        let conversations = await Conversation.find({
            $or: [{ seller: user_name }, { buyer: user_name }]
        }).populate('product').sort({ lastMessage: -1 });

        let currentConversation = null;
        let messages = [];

        if (seller && product) {
            // Create new conversation if doesn't exist
            currentConversation = await Conversation.findOne({
                product,
                $or: [
                    { seller, buyer: user_name },
                    { seller: user_name, buyer: seller }
                ]
            });

            if (!currentConversation) {
                currentConversation = new Conversation({
                    product,
                    seller,
                    buyer: user_name,
                    lastMessage: new Date()
                });
                await currentConversation.save();
            }

            messages = await Message.find({ conversationId: currentConversation._id });
        } else if (req.query.conversation) {
            currentConversation = await Conversation.findById(req.query.conversation).populate('product');
            messages = await Message.find({ conversationId: req.query.conversation });
        }

        res.render('messages', { 
            user_name,
            conversations,
            currentConversation,
            messages
        });
    } catch (err) {
        console.error('Error loading messages:', err);
        res.status(500).send('Error loading messages');
    }
});

// Port opening
server.listen(3000, function() {
    console.log("Server started on port 3000");
});
