	const express=require('express')
	const User=require('./models/usermodel')
	const jwt = require("jsonwebtoken");
	const bcrypt = require("bcryptjs");
	const cors = require('cors')
	const cookieParser= require('cookie-parser')
    
	const app=express();

    app.use(express.json()); 
		app.use(cookieParser());
		app.use(cors({
		    origin: 'https://cp-monitor.vercel.app', 
		    credentials: true, // Allow cookies and authorization headers
		    methods: "GET,POST,PUT,DELETE,OPTIONS",  // Ensure all methods are allowed
		    allowedHeaders: "Content-Type,Authorization"
		}));

    

    app.get('/',(req,res)=>{
       res.send('Backend is running...')
    });


    app.get("/auth/checkAuth", (req, res) => {
	    const token = req.cookies.token; // Get token from cookies
       // console.log(token)
			  if (!token) return res.status(401).json({ message: "Unauthorized" });

			   jwt.verify(token, "JaiBajarangBali", (err, decoded) => {
			    if (err) return res.status(401).json({ message: "Invalid token" });

			    res.status(200).json({ message: "Authenticated", user: decoded });
			  });
			});


    app.post('/auth/Login',async (req,res)=>{
    	const {userName ,password} = req.body;
    	// console.log(userName)
	        if (!userName || !userName.trim()) {
		        return res.status(400).json({ message: 'Username is required and cannot be empty' });
		    }
		    if (!password || !password.trim()) {
		        return res.status(400).json({ message: 'Password is required and cannot be empty' });
		    }


    	try{
	    	const user = await User.findOne({userName})
	    	// console.log(user)
	    	if(!user){
				return res.status(400).json({message:'Wrong credentials'})
	    	}

	    	const isMatch = await bcrypt.compare(password,user.password)
	    	if(!isMatch){
				return res.status(400).json({message:'Wrong credentials'})
	    	}
	    	// console.log(isMatch);
	    	const token=jwt.sign({Id:user._id},"JaiBajarangBali",{expiresIn:'1h'})
	    	// console.log(token);
	    	return res
			  .cookie("token", token, {
			    httpOnly: true,
			    sameSite: "strict",
			    maxAge: 60 * 60 * 1000,
			  }) 
			  .json({ token }); 
 
        }catch(err){
        	res.status(500).json({ message: "Server error",err });
        }

    })


	app.post('/auth/Signup',async (req,res)=>{
	     const { email, userName, password } = req.body;

	     console.log(req.body)

	       if (!userName || !userName.trim()) {
		        return res.status(400).json({ message: 'Username is required and cannot be empty' });
		    }
		    if (!email || !email.trim()) {
		        return res.status(400).json({ message: 'Email is required and cannot be empty' });
		    }
		    if (!password || !password.trim()) {
		        return res.status(400).json({ message: 'Password is required and cannot be empty' });
		    }

        try{ 
        	const isPresent =await  User.findOne({
              $or: [
			    { userName: userName },  // Condition to match userName
			    { email: email }         // Condition to match email
			  ]
        	});
 
        	// console.log(isPresent)
          if(isPresent){
              	if(isPresent.email==email && isPresent.userName==userName){
              		return res.status(400).json({message:'Both Email and Username is Already Taken'})
      
              	}
              	else if(isPresent.email==email){
              		return res.status(400).json({message:'Email is Already Taken'})
              	
              	}else  return res.status(400).json({message:'Username is Already Taken'})
          }
        	
        	//salt generation

        	await bcrypt.genSalt(10, async (err, salt) => {
	            if (err) {
	                console.error("Error generating salt:", err);
	                return res.status(500).json({ message: "Server error" });
	            }

	           await bcrypt.hash(password, salt, async (err, hash) => {
	                if (err) {
	                    console.error("Error hashing password:", err);
	                    return res.status(500).json({ message: "Server error" });
	                }

	                try {
	                    // Create user after password hashing
	                    const user = await User.create({
	                        email,
	                        password: hash,
	                        userName
	                    });
	                   

	                    const token = jwt.sign({ Id: user._id }, "JaiBajarangBali", { expiresIn: '1h' });
                         res.send({token})
	                    
                      console.log("Successfully Created")
                } catch (error) {
                    console.error("Error creating user:", error);
                    res.status(500).json({ message: "Server error" });
                }
            });
        });
        }catch(err){
        	res.status(500).json({message:'server error'})
        }
	})
   
    
    app.post('/auth/logout',async (req,res)=>{
    	res.cookie('token','')
    	res.status(201).json({message:'Logout Successfully'})
    })


    const port=3000;
	app.listen(port,()=>{
		console.log(`server is running on ${port}`)
	})






