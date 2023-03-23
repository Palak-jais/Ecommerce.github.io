require('dotenv').config()
const express=require('express');
const mongoose=require('mongoose');
const cors=require('cors');
const fileUpload=require('express-fileupload');
const cookieParser=require('cookie-parser');

const app=express();

app.use(express.json());
app.use(cookieParser());

app.use(cors());
app.use(fileUpload({
   useTempFiles:true
}))
//routes..
app.use('/user',require('./routes/userRouter'))
app.use('/api',require('./routes/categoryRouter'))
app.use('/api',require('./routes/upload'))
app.use('/api',require('./routes/productRouter'))
app.use('/api',require('./routes/paymentRouter'))



//connect to mongodb
const URI=process.env.MONGODB_URL
mongoose.set('strictQuery',false);
mongoose.connect(URI,{
    useNewUrlParser: true, // <-- no longer necessary
    useUnifiedTopology: true  
},err =>{
    if(err) throw err;
    
    console.log('connected to mongodb');}
);

/*app.get('/', (req, res) => {
    res.json({msg:"hello"})
  });
 */ 

app.listen(5000,()=>{

    console.log("server is running on port 5000");
   
});

