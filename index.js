const express = require('express');
const { json } = require('express');
const cors = require('cors');
require('dotenv').config();
const UserModel = require('./model/User.js');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const uploadMiddleware = multer({dest:'uploads/'});
const fs = require('fs');
const PostModel = require('./model/Post.js');


const saltRounds = parseInt(process.env.SALT_ROUNDS)
const secretKey = process.env.SECRET_KEY
const mongodbuser = process.env.MONGO_DB_USER
const mongodbpass = process.env.MONGO_DB_PASSWORD
const uri = `mongodb+srv://${mongodbuser}:${mongodbpass}@cluster0.q4kkbqi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const port= 4000;
const salt = bcrypt.genSaltSync(saltRounds);

async function connectToDatabase() {
    try {
        await mongoose.connect(uri);
        console.log('Connected to MongoDB');
        // Any other initialization code can go here
    } catch (error) {
        console.error('Error connecting to MongoDB:', error);
    }
}

connectToDatabase();

const app = express();
app.use(cors({credentials:true, origin:'http://localhost:3000'}));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads',express.static(__dirname+'/uploads'));

app.get('/test',(req,res)=>{
    res.json('test ok');
})

app.post('/register', async (req,res)=>{
    const {username,password} = req.body;
    const hash = bcrypt.hashSync(password,salt)
    try {
        const userDoc = await UserModel.create({
            username,
            password: hash
        })
        res.json(userDoc)
    }catch(e){
        res.status(400).json(e);
    }
})

app.post('/login',async(req,res)=>{
    const {username,password} = req.body;
    const userDoc = await UserModel.findOne({username});
    const passOk = bcrypt.compareSync(password,userDoc.password);
    // console.log(passOk);
    // res.json(passOk);
    if(passOk){
        // logged in
        jwt.sign({username,id:userDoc._id},secretKey,{expiresIn:120000},(err,token)=>{
            if(err) throw err;
            res.cookie('token',token,{maxAge:120000, httpOnly:true}).json({
                id:userDoc._id,
                username
            });
        })
    }else{
        res.status(400).json('wrong credentials')
    }
})

app.get('/profile',(req,res)=>{
    const {token} = req.cookies
    if(!token){
        return res.status(401).json({error:'Unauthorized Access'})
    }

    jwt.verify(token,secretKey,{maxAge:120000, httpOnly:true},(err,info)=>{
        if(err) throw err;
        res.json(info)
    })
});

app.post('/logout',(req,res)=>{
    res.cookie('token', '').json('ok')    
})

app.post('/create', uploadMiddleware.single('file') ,async (req,res)=>{
    // const {originalname,path} = req.file;
    const fileData = await fs.readFileSync(req.file.path)
    // console.log(fileData);
    const binary = Buffer.from(fileData)
    // console.log(binary);
    // const parts = originalname.split('.');
    // const ext = parts[parts.length-1]
    // const newPath = path+'.'+ext
    // fs.renameSync(path, newPath)
    // // const fileData = await fs.readFileSync(req.file.path)
    // console.log(fileData);

    const {token} = req.cookies;
    jwt.verify(token, secretKey, {}, async(err,info)=>{
        const {title,summary,content} = req.body;
        if (err) throw err;
        const postDoc = await PostModel.create({
            title,
            summary,
            content,
            cover:binary,
            author:info.id
        })
        res.json(postDoc);
    })

})

app.get("/post",async(req,res)=>{
    let posts = await PostModel.find().populate('author', ['username']).sort({ createdAt: -1 }).limit(20);

    // Transform the cover field of each post to base64
    posts = posts.map(post => {
        if (post.cover instanceof Buffer) { // Check if cover is a Buffer
            return {
                ...post.toObject(), // Convert Mongoose document to plain object
                cover: `data:image/png;base64,${post.cover.toString('base64')}` // Convert cover to base64
            };
        } else {
            return post.toObject(); // Return original post object if cover is not a Buffer
        }
    });
    res.json(posts)
})

app.get("/post/:id",async(req,res)=>{
    // res.json('ok')
    // console.log(req.params.id);
    var postData = await PostModel.findById(req.params.id).populate('author',['username'])
    postData = {
        ...postData.toObject(),
        cover: `data:image/png;base64,${postData.cover.toString('base64')}`
    }

    res.json(postData) 
})

app.listen(port,()=>{
    console.log('listening on port', port);
})
