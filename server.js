const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 8080;
let users = [];

app.use(express.json());

const loginLimiter = rateLimit({
    windowMs : 15 * 60 * 1000,
    max : 5,
    message : 'Too many attempt, please try again later.'
})

app.post('/signup', async (req, res) => {
    try {
        let { username, password } = req.body;

        let salt = await bcrypt.genSalt(10);
        let hashedPassword = await bcrypt.hash(password, salt);

        let newUser = { username, password : hashedPassword };
        users.push(newUser);

        res.status(201).json({ message : 'User saved successfuly.' });
        console.log(users);

    } catch (error) {
        res.status(400).json({ message : 'An error occured when registering the user.' });
    }
})

app.post('/login', loginLimiter, async (req, res) => {
    let { username, password } = req.body;

    let user = users.find(user => user.username === username);
    if(!user) {
        return res.status(400).json({ message : 'Invalid credentials' });
    }

    let isPassword = await bcrypt.compare(password, user.password);
    if(!isPassword) {
        return res.status(400).json({ message : 'Invalid credentials' });
    }

    res.status(200).json({ message : 'Welcome back' });
})

app.listen(PORT, () => {
    console.log(`Server launched at PORT : ${PORT}`);
});