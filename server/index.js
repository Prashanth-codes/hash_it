require("dotenv").config();
const mongoose = require('mongoose');

const bcrypt = require('bcrypt');
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fs=require("fs");
const path=require("path");
const User = require("./models/user");

const {authenticateToken} = require('./utilities');


mongoose.connect(process.env.URL)
    .then(() => {
        console.log("Connected to mongodb");
    })
    .catch(err => console.log("Failed to connect to database"));


const app=express();
app.use(express.json());
app.use(cors({origin: "*"}));

app.post('/create-account',async(req,res)=>{
    const {fullName,email,password}=req.body;
    if(!fullName || !email || !password){
        return res.status(400).json({error: true,message: "All fields are required"});
    }
    const isUser = await User.findOne({email});
    
    if(isUser){
        return res.status(400).json({error: true, message: "User Already exists"});
    }

    const hashedPassword = await bcrypt.hash(password,10);
    const user = new User({
        fullName,
        email,
        password: hashedPassword
    })

    await user.save();
    const accessToken = jwt.sign(
        {userId: user._id},
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: "48h",
        }
    );
    return res.status(201).json({error: false,
        user: {fullName: user.fullName,email: user.email},
        accessToken,
        message: "Registration Successful",
    })

});

app.post('/login',async (req,res)=>{
    const {email,password} = req.body;
    if(!email || !password){
        return res.status(400).json({message: "Email and password are required"});
    }
    const user = await User.findOne({email});
    if(!user){
        return res.status(400).json({message: "User not found"});
    }
    const isPasswordValid = await bcrypt.compare(password,user.password);
    if(!isPasswordValid){
        return res.status(400).json({message: "Invalid password"});
    }

    const accessToken = jwt.sign(
        {userId: user._id},
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: "7d",
        }
    );
    return res.json({
        error: false,
        message: "Login Successful",
        user: {fullName: user.fullName,email: user.email},
        accessToken,
    })
})





const port=process.env.PORT || 8000;

app.listen(port,()=>{
    console.log(`Server running successfully`);
});


module.exports = app