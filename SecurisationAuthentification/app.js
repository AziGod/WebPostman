const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const path = require('path'); 
const sanitizeHtml = require('sanitize-html');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit'); 
const session = require('express-session');



const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limite à 5 tentatives
    message: 'Trop de tentatives de connexion. Réessayez plus tard.',
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(csrf({ cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production' } }));

app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; style-src 'self';"
    );
    next();
});

app.use(session({
    secret: 'votre_secret',
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: false, // Passez à true si vous utilisez HTTPS
        sameSite: 'strict',
    },
}));







app.get('/', function(req, res) {
    res.sendFile(path.join(__dirname, '/index.html'));
  });
  
app.get('/login', (req, res) => {
    res.send(`
        <form id="loginForm" action="/login" method="POST">
            <input type="hidden" name="_csrf" value="${req.csrfToken()}">
            <label for="username">Nom d'utilisateur :</label>
            <input type="text" id="username" name="username" required>
            
            <label for="password">Mot de passe :</label>
            <input type="password" id="password" name="password" required>
            
            <button type="submit">Se connecter</button>
        </form>
    `);
});

app.post('/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === 'password123') {
        res.send('Connexion réussie');
    } else {
        res.status(401).send('Nom d’utilisateur ou mot de passe incorrect');
    }
});
 
app.listen(3000, () => {
    console.log('Serveur en cours d’exécution sur http://localhost:3000');
});