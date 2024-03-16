const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const bodyParser = require('body-parser')
require('dotenv').config()

const app = express()

app.use(express.json())
app.use(bodyParser.urlencoded({ extended: true }))

const User = require('./models/User.js')

app.post('/auth/register', async (req, res) => {

    const { name, email, password, confirmPassword } = req.body

    //validations

    if (!name) {
        res.status(422).json({ msg: "Nome é obrigatório" })
    }

    if (!email) {
        res.status(422).json({ msg: "Email e senha obrigatórios" })
    }

    if (!password) {
        res.status(422).json({ msg: "Email e senha obrigatórios" })
    }

    if (confirmPassword != password) {
        res.status(422).json({ msg: "As senhas não são iguais" })
    }

    const userExists = await User.findOne({email: email})

    if(userExists) {
        return res.status(422).json({message: 'usuário ja cadastrado, utilize outro email'})
    }

    const salt = await bcrypt.genSalt(12)

    const hashPassword = await bcrypt.hash(password, salt)

    const user = new User({
        name, 
        email,
        password: hashPassword,
    })

    try {
        await user.save()
        res.status(201).json('Usuário criado')
    } catch (err) {
        console.log(err)
        res.status(500).send('server error', err)
    }
})

app.post('/auth/signin', async (req, res) => {

    const { email, password} = req.body

    if (!email) {
       return res.status(422).json({ msg: "Email Obrigatório" })
    }

    if (!password) {
        return res.status(422).json({ msg: "Senha Obrigatória" })
    }

    // check user exists

    const user = await User.findOne({email: email})

    if(!user) {
        return res.status(422).json({message: 'usuário ja cadastrado, utilize outro email'})
    }

    // check if password match
    const checkedPassword = await bcrypt.compare(password, user.password)

    if(!checkedPassword) {
        return res.status(422).json({message: 'Senha inválida'})
    } 

    try {

        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id,
        },
        secret
    )

    res.status(201).json({message: 'Autenticação feita com sucesso', token})

    } catch {
        console.log(err)
        res.status(500).send('server not found', err)
    }
})

function checkToken(req, res, next) {
    const authHeaders = req.headers['authorization']
    const token = authHeaders && authHeaders.split('')[1]

    if(!token) {
        return res.status(401).json({msg: 'Acesso negado'})
    }
}

// public router

app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id

    // check if user exists
    const user = await User.findOne(id, '-password')

    if(!user) {
        return res.json({msg: 'Usuário não encontrado'})
    }

    res.status(200).json({user})
})

const dbPassword = process.env.DB_PASS

// conexão com mongoDB

mongoose.connect(`mongodb+srv://matheusalvovirtual:${dbPassword}@cluster0.ameb3j8.mongodb.net/?retryWrites=true&w=majority`).then(() => {
    app.listen(3001)
    console.log('db connect')
}).catch((err) => console.log('error db connection', err))

app.listen(3000, () => {
    console.log('start')
})