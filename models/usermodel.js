const mongoose=require('mongoose');

mongoose.connect('mongodb+srv://pkkrpacific:06546223540@cluster0.ifa043j.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
.then(()=>console.log("connected to db"))
.catch((err)=>console.error("connection failed",err));

const userSchema=new mongoose.Schema({
	
	email:{type:String,required:true,unique:true},
	password:{type:String,required:true},
	userName:{type:String,required:true,unique:true}
})


const User=mongoose.model('User',userSchema);
module.exports=User;
