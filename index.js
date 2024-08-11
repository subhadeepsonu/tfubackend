const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()
const cors = require("cors")
const express = require("express")
const app = express()
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
app.use(express.json())
app.use(cors({
    origin:"*"
}))
app.get("/flashcard",async (req,res)=>{
    try {
        
        const response = await prisma.card.findMany({
        })
        
        res.json({
            success:true,
            message:response
        })
    } catch (error) {
        res.json({
            success:false,
            message:error.message
        })
    }
})
app.post("/flashcard",async (req,res)=>{
    try {
        const data = req.body
        const token = req.headers.authorization
        
        if(!token){
            res.json({
                success:false,
                message:"Unauthorized"
            })
        }
        
        const check = jwt.verify(token,process.env.jwtSecret)
        if(!check){
            res.json({
                success:false,
                message:"Unauthorized"
            })
        }
        const response = await prisma.card.create({
            data:{
                title:data.title,
                description:data.description
            }
        })
        res.json({
            success:true,
            message:response
        })
    } catch (error) {
        res.json({
            success:false,
            message:error.message
        })
    }
})
app.delete("/flashcard",async (req,res)=>{
    try {
        const data = req.body
        const token = req.headers.authorization
        if(!token){
            res.json({
                success:false,
                message:"Unauthorized"
            })
        }
        const check = jwt.verify(token,process.env.jwtSecret)
        if(!check){
            res.json({
                success:false,
                message:"Unauthorized"
            })
        }
        const response = await prisma.card.delete({
            where:{
                id:data.id
            }
        })
        res.json({
            success:true,
            message:response
        })
    } catch (error) {
        res.json({
            success:false,
            message:error.message
        })
    }
})
app.put("/flashcard",async (req,res)=>{
    try {
        
        const data = req.body
        const token = req.headers.authorization
        if(!token){
            res.json({
                success:false,
                message:"Unauthorized"
            })
        }
        const check = jwt.verify(token,process.env.jwtSecret)
        if(!check){
            res.json({
                success:false,
                message:"Unauthorized"
            })
        }
        const response = await prisma.card.update({
            where:{
                id:data.id
            },
            data:{
                title:data.title,
                description:data.description
            }
        })
        res.json({
            success:true,
            message:response
        })
    } catch (error) {
        res.json({
            success:false,
            message:error.message
        })
    }
})
app.post("/login",async(req,res)=>{
    try {
        const data = req.body
        const response = await prisma.admin.findUnique({
            where:{
                username:data.username
            }
        })
        if(!response){
            res.json({
                success:false,
                message:"User not found"
            })
        }
        const check = bcrypt.compareSync(data.password,response.password)
        if(!check){
            res.json({
                success:false,
                message:"Invalid password"
            })
        }
        const token = jwt.sign({
            id:response.id,
            username:data.username
        },process.env.jwtSecret)
        res.json({
            success:true,
            message:token
        })
    } catch (error) {
        res.json({
            success:false,
            message:error.message
        })
    }
})
app.post("/register",async (req,res)=>{
    try {
        const data = req.body
        const user = await prisma.admin.findUnique({
            where:{
                username:data.username
            }
        })
        if(user){
            res.json({
                success:false,
                message:"User already exists"
            })
        }
        const salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(data.password,salt)
        const response = await prisma.admin.create({
            data:{
                username:data.username,
                password:hash
            }
        })
        const token = jwt.sign({
            id:response.id,
            username:data.username
        },process.env.jwtSecret)
        res.json({
            success:true,
            message:token
        })
    } catch (error) {
        res.json({
            success:false,
            message:error.message
        })
    }
})
app.listen(3000,()=>{
    console.log("listening")
})
