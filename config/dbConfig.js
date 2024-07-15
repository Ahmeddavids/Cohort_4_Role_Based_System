const mongoose = require('mongoose');
require('dotenv').config();
const URI = process.env.DATABASE;


mongoose.connect(URI)
.then(() => {
    console.log('Connection to Database successfully');
})
.catch((error) => {
    console.log("Error connecting to Database: ", error.message);
})