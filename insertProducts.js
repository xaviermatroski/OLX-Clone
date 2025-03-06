const mongoose = require("mongoose");
// const Product = require("./app").Product; // Adjust the path if necessary

mongoose.connect("mongodb://localhost:27017/olxDB", { useNewUrlParser: true, useUnifiedTopology: true });

const productSchema = new mongoose.Schema({
    name: String,
    description: String,
    image: String, // URL or path to the image
    price: Number
});

const Product = mongoose.model("Product", productSchema);

const products = [
    {
        name: "Laptop",
        description: "A high-performance laptop for all your computing needs.",
        image: "/images/laptop.jpg",
        price: 50000
    },
    {
        name: "Smartphone",
        description: "A latest model smartphone with all the modern features.",
        image: "/images/smartphone.jpg",
        price: 30000
    },
    {
        name: "Headphones",
        description: "Noise-cancelling over-ear headphones for immersive sound.",
        image: "/images/headphones.jpg",
        price: 5000
    },
    {
        name: "Smartwatch",
        description: "A smartwatch with fitness tracking and notifications.",
        image: "/images/smartwatch.jpg",
        price: 10000
    },
    {
        name: "Camera",
        description: "A DSLR camera for professional photography.",
        image: "/images/camera.jpg",
        price: 40000
    },
    // {
    //     name: "Tablet",
    //     description: "A tablet for browsing, reading, and entertainment.",
    //     image: "/images/tablet.jpg",
    //     price: 20000
    // },
    // {
    //     name: "Gaming Console",
    //     description: "A gaming console for the ultimate gaming experience.",
    //     image: "/images/gaming_console.jpg",
    //     price: 35000
    // },
    // {
    //     name: "Bluetooth Speaker",
    //     description: "A portable Bluetooth speaker with excellent sound quality.",
    //     image: "/images/bluetooth_speaker.jpg",
    //     price: 3000
    // },
    // {
    //     name: "Fitness Tracker",
    //     description: "A fitness tracker to monitor your daily activities.",
    //     image: "/images/fitness_tracker.jpg",
    //     price: 2500
    // },
    // {
    //     name: "External Hard Drive",
    //     description: "A 1TB external hard drive for extra storage.",
    //     image: "/images/external_hard_drive.jpg",
    //     price: 6000
    // },
    // {
    //     name: "Wireless Mouse",
    //     description: "A wireless mouse for easy navigation.",
    //     image: "/images/wireless_mouse.jpg",
    //     price: 1000
    // },
    // {
    //     name: "Keyboard",
    //     description: "A mechanical keyboard for a better typing experience.",
    //     image: "/images/keyboard.jpg",
    //     price: 2000
    // }
];

Product.insertMany(products)
    .then(() => {
        console.log("Products inserted successfully!");
        mongoose.connection.close();
    })
    .catch((err) => {
        console.error("Error inserting products:", err);
        mongoose.connection.close();
    });