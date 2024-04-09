//To import Mongoose Module
const mongoose=require('mongoose')

//Define User schema
const userSchema=new mongoose.Schema({
    username:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true,
        unique:true
    },
    password:{
        type:String,
        required:true,
        unique:true,
    },
    role:{
            type:String,
            enum:['user','admin'],
            default:'user'
        }
    
});
//create user model using the schema:
const User = mongoose.model('User', userSchema);

//Export the user model:
module.exports=User;