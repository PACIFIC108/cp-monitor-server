const mongoose=require('mongoose');

mongoose.connect('mongodb://127.0.0.1:27017/my_database')
.then(()=>console.log("connected to db"))
.catch((err)=>console.error("connection failed",err));

const userSchema=new mongoose.Schema({
	
	email:{type:String,required:true,unique:true},
	password:{type:String,required:true},
	userName:{type:String,required:true,unique:true}
})


const User=mongoose.model('User',userSchema);
module.exports=User;