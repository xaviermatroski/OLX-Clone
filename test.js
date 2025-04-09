const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.CONNECTION_STRING);

// Product Schema
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

const Product = mongoose.model("Product", productSchema);

async function deleteProductByName(productName) {
    try {
        // Find and delete the product
        const result = await Product.findOneAndDelete({ name: productName });
        
        if (result) {
            console.log(`Successfully deleted product: ${productName}`);
            console.log('Deleted product details:', result);
        } else {
            console.log(`No product found with name: ${productName}`);
        }
    } catch (err) {
        console.error('Error deleting product:', err);
    } finally {
        mongoose.connection.close();
    }
}

// Replace the empty string with the product name you want to delete
deleteProductByName("Cricket bat");
