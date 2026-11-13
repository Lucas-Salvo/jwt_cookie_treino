import express from "express"
import cors from "cors"
import {prisma} from "./lib/prisma.ts"
import bcrypt from "bcryptjs"
import cookieParser from "cookie-parser"
import jwt from "jsonwebtoken"

const app = express();
const PORT = 3000;

app.use(express.json())
app.use(cors())
app.use(cookieParser())

function autenticar(req, res, next) {
    const token = req.cookies.token
    if(!token){
        return res.status(401).json({mensagem: "Acesso invalido."})
    }
    try{
        const usuario = jwt.verify(token, JWT_SECRET)
        req.usuario = usuario;
        next();
    }catch(err){
        return res.status(403).json({mensagem: "Token inválido ou expirado."})
    }
}

app.get("/usuarios", async (req, res) => {
    const usuario = await prisma.usuarios.findMany()
    res.json(usuario)
})

app.post("/login", async (req, res) => {
    const { email, senha } = req.body;

    try {
        const usuario = await prisma.usuarios.findUnique({
            where: { email }
        });
        const token = jwt.sign(
            {id: usuario.id, email: usuario.email},
            JWT_SECRET,
            {expiresIn: "2hora" }
        );
        res.cookie("token", token, {
            httpOnly: true, 
            secure: false, //false deixa aceitar conexão http local
            sameSite: "lax", //proteção contra CSRF
            maxAge: 2 * 60 * 60 * 1000 // 2 horas pois sao colocados em MS
        });

        return res.status(200).json({ mensagem: "Login realizado com sucesso" });
    } catch (err) {
        return res.status(500).json({ mensagem: "Erro interno no servidor" });
    }
});

app.post("/usuarios", async (req, res) => {
    const {email, senha, cpf} = req.body
    const usuario = await prisma.usuarios.create({
        data: {
            email,
            senha,
            cpf
        }
    })
    res.json(usuario)
})

app.put("/usuarios", async (req, res) => {
    const {id} = req.params
    const {email, senha, cpf} = req.body
    const usuario = await prisma.usuarios.update({
        where: {id: Number(id)},
        data: {
            email,
            senha,
            cpf
        }
    })
    res.json(usuario)
})

app.delete("/usuarios", async (req, res) => {
    const {id} = req.params
    const usuario = await prisma.usuarios.delete({
        where: {id: Number(id)}
    })
    res.json(usuario)
})

app.listen(PORT, () => {
    console.log("API rodando na porta 3000")
})