const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {}); // Added const conn
    console.log("MongoDB connected");
    console.log(`MongoDB Connected to DB: ${conn.connection.name}`);
    console.log(`Host: ${conn.connection.host}`);
  } catch (err) {
    console.error("Error connecting to MongoDB", err);
    process.exit(1);
  }
};

module.exports = connectDB;