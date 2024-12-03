const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
 
const app = express();
app.use(bodyParser.json());
 
// Simuler une base de données
const users = [];
 
// Middleware pour vérifier les JWT
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!token) return res.status(401).send('Accès non autorisé : Aucun token fourni.');
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send('Token invalide.');
        req.user = user;
        next();
    });
}
 
// Route d'inscription
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Nom d’utilisateur et mot de passe requis.');
 
    // Vérifier si l'utilisateur existe déjà
    const existingUser = users.find(user => user.username === username);
    if (existingUser) return res.status(400).send('Utilisateur déjà existant.');
 
    // Hacher le mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.status(201).send('Utilisateur enregistré avec succès.');
});
 
// Route de connexion
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(user => user.username === username);
    if (!user) return res.status(400).send('Nom d’utilisateur ou mot de passe incorrect.');
 
    // Vérifier le mot de passe
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).send('Nom d’utilisateur ou mot de passe incorrect.');
 
    // Générer un JWT
    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});
 
// Route protégée
app.get('/protected', authenticateToken, (req, res) => {
    res.send(`Bienvenue ${req.user.username}, vous êtes authentifié.`);
});
 
// Démarrer le serveur
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Serveur en cours d’exécution sur http://localhost:${PORT}`);
});