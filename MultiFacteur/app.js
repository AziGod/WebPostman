const express = require('express');
const { generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const app = express();

// Middleware pour servir les fichiers statiques (comme le HTML)
app.use(express.static('public'));  // Assure-toi que ton fichier HTML est dans le dossier "public"
app.use(express.json());

// Simuler un stockage utilisateur
let user = {}; 

// Route pour générer les options d'enregistrement WebAuthn
app.post('/register-options', (req, res) => {
    const options = generateRegistrationOptions({
        rpName: "Exemple WebAuthn",
        userID: "123456",  // Cela peut être dynamique selon ton application
        userName: "UtilisateurExemple",
    });

    user.challenge = options.challenge; // Stocker le challenge côté serveur
    res.json(options);
});

// Route pour enregistrer le credential WebAuthn
app.post('/register', (req, res) => {
    const { body } = req;
    
    try {
        const verification = verifyRegistrationResponse({
            credential: body,
            expectedChallenge: user.challenge,
            expectedOrigin: 'http://localhost:3000', // À adapter selon ton domaine
            expectedRPID: 'localhost', // À adapter selon ton domaine
        });

        if (verification.verified) {
            user.credential = verification.registrationInfo; // Sauvegarder les informations d'enregistrement
            res.send('Inscription réussie');
        } else {
            res.status(400).send('Échec de l’inscription');
        }
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Route pour générer un secret OTP et un QR Code
app.get('/generate-secret', (req, res) => {
    const secret = speakeasy.generateSecret({ name: 'MonApplication' });

    // Générer le QR Code pour l'application d'authentification
    QRCode.toDataURL(secret.otpauth_url, (err, data) => {
        if (err) {
            return res.status(500).send('Erreur lors de la génération du QR Code');
        }
        res.json({ qrCodeData: data, secret: secret.base32 }); // Envoie le secret et le QR Code
    });
});

// Route pour vérifier l'OTP
app.post('/verify-otp', (req, res) => {
    const { token } = req.body;
    const secret = user.secret || ''; // Récupérer le secret de l'utilisateur (tu devras le stocker quelque part, dans la base de données ou session)

    const verified = speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token,
    });

    res.send(verified ? 'Code valide' : 'Code invalide');
});

// Lancer le serveur sur le port 3000
app.listen(3000, () => {
    console.log('Serveur WebAuthn et OTP démarré sur http://localhost:3000');
});
