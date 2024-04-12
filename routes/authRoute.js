const express=require('express')
const router=express.Router();
const bcrypt=require('bcryptjs');
const User=require('./../models/User');
const {generateJWTToken}=require('./../utils/jwtUtils')
const {authenticateJWT}=require('./../middlewares/authMiddleware')
const validator = require('validator'); 

//Routes user for Registration 
router.post('/register', async (req, res) => {
    try {
        // Check if the email is valid
        if (!validator.isEmail(req.body.email)) {
            return res.status(400).json({ message: 'Invalid email address' });
        }

        // Check if the username is valid
        if (!validator.isAlphanumeric(req.body.username)) {
            return res.status(400).json({ message: 'Username must be alphanumeric' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ email: req.body.email }, { username: req.body.username }] });
        if (existingUser) {
            return res.status(400).json({ message: 'User with this email or username already exists' });
        }

        // Check if password is long enough
        if (req.body.password.length < 8) {
            return res.status(400).json({ message: 'Password must be at least 8 characters long' });
        }

        // Hash the password with saltround of 10
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        // Determine if the user is registering as an admin
        let role = 'user'; // Default role
        if (req.body.admin) {
            role = 'admin';
        }

        // Create a new User
        const newUser = new User({
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword,
            role: role // Assign the determined role
        });

        // Save the User to the Database
        await newUser.save();

        res.status(201).json({ message: 'User Registered Successfully' });

    } catch (error) {
        console.error('Error Registering User', error);
        res.status(500).json({ message: 'Internal Server error' });
    }
});

//Route for user login
router.post('/login',async(req,res)=>{
    try{
        //Find the user by email
        const user=await User.findOne({email:req.body.email});
        if(!user){
            return res.status(401).json({message:'Invalid Email'});
        }

        //Compare the provided Password with Hashed password

        const isPasswordValid= await bcrypt.compare(req.body.password,user.password);
        if(!isPasswordValid){
            return res.status(401).json({message:'Invalid Password'});
        }
        
        //If authentication is successful ,Generate a JWT Token
        const token=generateJWTToken(user);

        //Return the token to the client
        res.status(200).json({token});
    }catch(error){
        console.error('Error logging in :',error);
        res.status(500).json({message:'Internal Server Error'});
    }
});

//protected route
router.get('/protected', authenticateJWT, (req, res) => {
    if (req.user.role === 'admin') {
        // Allow access for admin
        res.json({ message: 'Admin access granted' });
    } else {
        // Return 403 Forbidden for non-admin users
        res.status(403).json({ message: 'Access forbidden, admin role required' });
    }
});

router.get('/adminOnly', authenticateJWT, (req, res) => {
    // Check if user is an admin
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access forbidden, admin role required' });
    }

    // If user is an admin, allow access
    res.json({ message: 'Welcome, admin' });
});

// protected route for regular users
router.get('/user', authenticateJWT, (req, res) => {
    if (req.user.role === 'user') {
        // Allow access for regular users
        res.json({ message: 'User access granted' });
    } else {
        // Return 403 Forbidden for non-regular users
        res.status(403).json({ message: 'Access forbidden, user role required' });
    }
});
        

//Exporting to router file
module.exports=router;