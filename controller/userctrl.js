const Users=require('../models/userModel')
const bcrypt=require('bcrypt')
const jwt=require('jsonwebtoken')


const userctrl={
    register:async(req,res)=>{
        
        try{
        const{name,email,password}=req.body;
        const user=await Users.findOne({email})
        
        if(user) return res.status(400).json({msg:"this mail already register"})

        if(password.length<6)
        return res.status(400).json({msg:"password is atleast of 6 characters"})

         //password encryption..
         const passwordHash=await bcrypt.hash(password,10)
         const newUser=new Users({
            name,email,password:passwordHash
         })
         //save user
         await newUser.save()

         //create jwt tokens
         const accesstoken=createAccessToken({id:newUser._id})
         const refreshtoken=createRefreshToken({id:newUser._id})
         res.cookie('refreshtoken',refreshtoken,{
            httpOnly:true,
            path:'/user/refresh_token',
            maxAge:7*24*60*60*1000
            
         });
         
         
        //res.json({msg:"sucessfully registered"})
         res.json({accesstoken})     
        }

        catch(err){
          return res.status(500).json({msg:err.message})
        }
    },
    
    login:async(req,res)=>{
        try{
          const{email,password}=req.body;
          const user=await Users.findOne({email})
          if(!user) return res.status(400).json({msg:"user not exists"})
          
          const isMatch=  bcrypt.compare(password,user.password)
          if(!isMatch) return res.status(400).json({msg:"Incorrect Password."})

          //if login sucess ,create accesstoken and refresh token
          const accesstoken=createAccessToken({id:user._id})
         const refreshtoken=createRefreshToken({id:user._id})
         res.cookie('refreshtoken',refreshtoken,{
            httpOnly:true,
            path:'/user/refresh_token',
            maxAge:7*24*60*60*1000
            
         })
          //res.json({msg:"login Sucess"})
          res.json({accesstoken})

        }
        catch(err){
            
          return res.status(500).json({msg:err.message})
        }
    },

    logout:async(req,res)=>{
   try{
    res.clearCookie('refreshtoken',{path:'/user/refresh_token'})
    return res.json({msg:"Logged out"})

   }
   catch(err){
    return res.status(500).json({msg:err.message})
   }
    },

    refreshToken:(req,res)=>{
      try{
        const rf_token=req.cookies.refreshtoken;
        console.log(rf_token);
        if(!rf_token) return res.status(400).json({msg:"Please Login or Register"})

        jwt.verify(rf_token,process.env.REFRESH_TOKEN_SECRET,(err,user)=>{
            if(err)  return res.status(400).json({msg:"Please Login or Register"})

            const accesstoken=createAccessToken({id:user.id})
            res.json({accesstoken})
        })
        res.json({rf_token});

      } catch(err){
        return res.status(500).json({msg:err.message})
      }
       
    },
    getUser:async(req,res)=>{
        try{
            const user=await Users.findById(req.user.id).select('-password')
            if(!user) return res.status(400).json({msg:"User does not exist."})
            res.json(user)

        }
        catch(err){
            return res.status(500).json({msg:err.message})
        }
    },
    addCart:async(req,res)=>{
     try{
          const user=await Users.findById(req.user.id)
            if(!user) return res.status(400).json({msg:"User does not exists."})
            await Users.findOneAndUpdate({_id:req.user.id},{
              cart:req.body.cart

            })
            return res.json({msg:"added to cart"})
          }

     
     catch(err){
      return res.status(500).json({msg:err.message})
     }
    },
    history:async(req,res)=>{
      try{
        const history=await Payments.find({user_id:req.user.id})
        res.json(history)

      }
      catch(err){
        return res.status(500).json({msg:err.message})
      }
    }
    
}

const createAccessToken=(user)=>{
    
    return jwt.sign(user,process.env.ACCESS_TOKEN_SECRET,{expiresIn:'11m'})
    
}
const createRefreshToken=(user)=>{
    
    return jwt.sign(user,process.env.REFRESH_TOKEN_SECRET,{expiresIn:'7d'})
    
}

module.exports=userctrl