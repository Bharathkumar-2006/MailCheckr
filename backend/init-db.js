const mongoose = require("mongoose");
const User = require("./models/User");
require("dotenv").config();

async function initDB() {
    try {
        console.log("Connecting to MongoDB Atlas...");
        await mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        console.log("Connected successfully!");

        console.log("Ensuring 'users' collection is created...");
        await User.createCollection();
        console.log("Success! The 'users' collection has been verified/created in your Atlas cluster.");
        
        mongoose.connection.close();
        process.exit(0);
    } catch (err) {
        console.error("Error initializing database collections:", err);
        process.exit(1);
    }
}

initDB();
