import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cors from "cors";
import rateLimit from "express-rate-limit";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

/* ===============================
RATE LIMITER
================================= */

const limiter = rateLimit({
windowMs: 15 * 60 * 1000,
max: 100
});

app.use(limiter);

/* ===============================
ENV VARIABLES
================================= */

const JWT_SECRET = process.env.JWT_SECRET || "accesssecret";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "refreshsecret";

/* ===============================
DATABASE CONNECT
================================= */

const mongoose = require("mongoose");

mongoose.connect("YOUR_CONNECTION_STRING")
.then(()=> console.log("MongoDB Atlas Connected 🔥"))
.catch(err => console.log(err));

/* ===============================
USER SCHEMA
================================= */

const userSchema = new mongoose.Schema({

name: {
type: String,
required: true
},

email: {
type: String,
required: true,
unique: true
},

password: {
type: String,
required: true
},

role: {
type: String,
enum: ["user", "admin"],
default: "user"
},

isBanned: {
type: Boolean,
default: false
},

refreshToken: String

},{ timestamps:true });

const User = mongoose.model("User", userSchema);

/* ===============================
CONTACT SCHEMA
================================= */

const contactSchema = new mongoose.Schema({

name: {
type:String,
required:true
},

email:String,
phone:String,

tags:[String],

userId:{
type:mongoose.Schema.Types.ObjectId,
ref:"User",
required:true
}

},{timestamps:true});

const Contact = mongoose.model("Contact", contactSchema);

/* ===============================
AUTH MIDDLEWARE
================================= */

const authMiddleware = (req,res,next)=>{

const header = req.headers.authorization;

if(!header)
return res.status(401).json({message:"No token ❌"});

const token = header.split(" ")[1];

try{

const decoded = jwt.verify(token,JWT_SECRET);

req.user = decoded;

next();

}catch{

res.status(401).json({message:"Invalid or expired token ❌"});

}

};

/* ===============================
ADMIN MIDDLEWARE
================================= */

const adminMiddleware = (req,res,next)=>{

if(req.user.role !== "admin")
return res.status(403).json({message:"Admin only 🚫"});

next();

};

/* ===============================
REGISTER
================================= */

app.post("/register",async(req,res)=>{

try{

const {name,email,password} = req.body;

if(!name || !email || !password)
return res.status(400).json({message:"All fields required ❌"});

if(password.length < 6)
return res.status(400).json({message:"Password must be 6 characters ❌"});

const existingUser = await User.findOne({email});

if(existingUser)
return res.status(400).json({message:"User already exists ❌"});

const hashedPassword = await bcrypt.hash(password,10);

await User.create({
name,
email,
password:hashedPassword
});

res.json({message:"User registered successfully ✅"});

}catch(error){

res.status(500).json({message:error.message});

}

});

/* ===============================
LOGIN
================================= */

app.post("/login",async(req,res)=>{

try{

const {email,password} = req.body;

if(!email || !password)
return res.status(400).json({message:"Email & password required ❌"});

const user = await User.findOne({email});

if(!user)
return res.status(404).json({message:"User not found ❌"});

if(user.isBanned)
return res.status(403).json({message:"User banned 🚫"});

const isMatch = await bcrypt.compare(password,user.password);

if(!isMatch)
return res.status(400).json({message:"Wrong password ❌"});

const accessToken = jwt.sign(
{ id:user._id, role:user.role },
JWT_SECRET,
{ expiresIn:"15m" }
);

const refreshToken = jwt.sign(
{ id:user._id },
JWT_REFRESH_SECRET,
{ expiresIn:"7d" }
);

user.refreshToken = refreshToken;
await user.save();

res.json({
message:"Login successful ✅",
accessToken,
refreshToken
});

}catch(error){

res.status(500).json({message:error.message});

}

});

/* ===============================
REFRESH TOKEN
================================= */

app.post("/refresh-token",async(req,res)=>{

const {refreshToken} = req.body;

if(!refreshToken)
return res.status(401).json({message:"No refresh token"});

try{

const decoded = jwt.verify(refreshToken,JWT_REFRESH_SECRET);

const user = await User.findById(decoded.id);

if(!user || user.refreshToken !== refreshToken)
return res.status(403).json({message:"Invalid refresh token"});

const newAccessToken = jwt.sign(
{ id:user._id, role:user.role },
JWT_SECRET,
{ expiresIn:"15m"}
);

res.json({accessToken:newAccessToken});

}catch{

res.status(403).json({message:"Invalid refresh token"});

}

});

/* ===============================
PROFILE
================================= */

app.get("/profile",authMiddleware,async(req,res)=>{

const user = await User
.findById(req.user.id)
.select("-password");

res.json({user});

});

/* ===============================
LOGOUT
================================= */

app.post("/logout",authMiddleware,async(req,res)=>{

await User.findByIdAndUpdate(
req.user.id,
{refreshToken:null}
);

res.json({message:"Logged out 👋"});

});

/* ===============================
ADD CONTACT
================================= */

app.post("/add-contact",authMiddleware,async(req,res)=>{

try{

const {name,email,phone,tags} = req.body;

const contact = await Contact.create({
name,
email,
phone,
tags,
userId:req.user.id
});

res.json({
message:"Contact added ✅",
contact
});

}catch(error){

res.status(500).json({message:error.message});

}

});

/* ===============================
GET CONTACTS (Pagination)
================================= */

app.get("/my-contacts",authMiddleware,async(req,res)=>{

const page = parseInt(req.query.page) || 1;
const limit = parseInt(req.query.limit) || 10;

const contacts = await Contact
.find({userId:req.user.id})
.skip((page-1)*limit)
.limit(limit);

res.json({contacts});

});

/* ===============================
UPDATE CONTACT
================================= */

app.put("/update-contact/:id",authMiddleware,async(req,res)=>{

const contact = await Contact.findOneAndUpdate(
{_id:req.params.id,userId:req.user.id},
req.body,
{new:true}
);

if(!contact)
return res.status(404).json({message:"Contact not found ❌"});

res.json({
message:"Contact updated ✅",
contact
});

});

/* ===============================
DELETE CONTACT
================================= */

app.delete("/delete-contact/:id",authMiddleware,async(req,res)=>{

const contact = await Contact.findOneAndDelete({
_id:req.params.id,
userId:req.user.id
});

if(!contact)
return res.status(404).json({message:"Contact not found ❌"});

res.json({message:"Contact deleted 🗑"});

});

/* ===============================
SEARCH CONTACT
================================= */

app.get("/search",authMiddleware,async(req,res)=>{

const keyword = req.query.keyword || "";

const contacts = await Contact.find({

userId:req.user.id,

name:{
$regex:keyword,
$options:"i"
}

});

res.json({contacts});

});

/* ===============================
ADMIN ROUTES
================================= */

app.get("/admin/users",
authMiddleware,
adminMiddleware,
async(req,res)=>{

const users = await User.find().select("-password");

res.json({users});

});

app.patch("/admin/ban/:id",
authMiddleware,
adminMiddleware,
async(req,res)=>{

await User.findByIdAndUpdate(
req.params.id,
{isBanned:true}
);

res.json({message:"User banned 🚫"});

});

/* ===============================
SERVER START
================================= */

const PORT = process.env.PORT || 5000;

app.listen(PORT,()=>{

console.log(`Server running on port ${PORT} 🚀`);

});