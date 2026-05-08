'use strict';

require('dotenv').config();
const express    = require('express');
const crypto     = require('crypto');
const path       = require('path');
const mysql      = require('mysql2');
const cors       = require('cors');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const nodemailer = require('nodemailer');

// ═══════════════════════════════════════════════════════════
//  VALIDATION AU DÉMARRAGE
// ═══════════════════════════════════════════════════════════
const REQUIRED_ENV = ['JWT_SECRET', 'DB_HOST', 'DB_USER', 'DB_NAME', 'EMAIL_USER', 'EMAIL_PASS'];
const missingEnv   = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length) {
    console.error(`❌ FATAL — Variables .env manquantes: ${missingEnv.join(', ')}`);
    process.exit(1);
}

const app = express();

// ═══════════════════════════════════════════════════════════
//  CONSTANTES
// ═══════════════════════════════════════════════════════════
const JWT_SECRET    = process.env.JWT_SECRET;
const JWT_EXPIRES   = '24h';
const SALT_ROUNDS   = 12;
const ADMIN_EMAIL   = process.env.ADMIN_EMAIL || process.env.EMAIL_USER;
const PORT          = parseInt(process.env.PORT || '3000', 10);

// ═══════════════════════════════════════════════════════════
//  EMAIL
// ═══════════════════════════════════════════════════════════
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    tls:  { rejectUnauthorized: false },
});

/**
 * Envoie un email HTML.
 * @param {string} to       Destinataire
 * @param {string} subject  Objet
 * @param {string} html     Corps HTML
 * @returns {Promise<boolean>}
 */
async function sendEmail(to, subject, html) {
    if (!to) return false;
    try {
        await transporter.sendMail({
            from: `"WebMarko CRM" <${process.env.EMAIL_USER}>`,
            to,
            subject,
            html,
        });
        console.log(`📧 Email → ${to} | ${subject}`);
        return true;
    } catch (err) {
        console.warn(`⚠️  Email non envoyé (${to}):`, err.message);
        return false;
    }
}

/** Template HTML générique pour les emails */
function emailTemplate(title, bodyHtml) {
    return `
    <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
    <style>
      body{font-family:Arial,sans-serif;background:#f4f7fc;margin:0;padding:0}
      .wrap{max-width:600px;margin:40px auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.08)}
      .header{background:linear-gradient(135deg,#0077b6,#00b4d8);padding:30px 40px;text-align:center}
      .header h1{color:#fff;margin:0;font-size:22px;letter-spacing:-.3px}
      .header p{color:rgba(255,255,255,.8);margin:6px 0 0;font-size:13px}
      .body{padding:36px 40px;color:#1a2a3a;font-size:15px;line-height:1.7}
      .body h2{font-size:18px;color:#0077b6;margin-top:0}
      .info-block{background:#f0f7ff;border-left:4px solid #00b4d8;border-radius:0 8px 8px 0;padding:14px 20px;margin:16px 0;font-size:14px}
      .info-block strong{color:#0077b6}
      .btn{display:inline-block;background:linear-gradient(135deg,#0077b6,#00b4d8);color:#fff!important;text-decoration:none;padding:13px 28px;border-radius:8px;font-weight:700;font-size:15px;margin:20px 0}
      .footer{background:#f4f7fc;padding:20px 40px;text-align:center;font-size:12px;color:#7a9bbf;border-top:1px solid #e0ebf7}
    </style></head><body>
    <div class="wrap">
      <div class="header">
        <h1>WebMarko</h1>
        <p>Agence Web Professionnelle · Maroc</p>
      </div>
      <div class="body">
        <h2>${title}</h2>
        ${bodyHtml}
      </div>
      <div class="footer">
        WebMarko · Casablanca, Maroc · +212 6 00 00 00 00 · contact@webmarko.ma<br>
        © ${new Date().getFullYear()} WebMarko — Tous droits réservés
      </div>
    </div>
    </body></html>`;
}

// ═══════════════════════════════════════════════════════════
//  MIDDLEWARE
// ═══════════════════════════════════════════════════════════

// CORS
const ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    ...(process.env.PROD_ORIGIN ? [process.env.PROD_ORIGIN] : []),
];
app.use(cors({
    origin: (origin, cb) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        cb(new Error(`CORS bloqué: ${origin}`));
    },
    credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Security headers
app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

// ═══════════════════════════════════════════════════════════
//  RATE LIMITING (en mémoire)
// ═══════════════════════════════════════════════════════════
const loginAttempts = new Map(); // ip → { count, lastAttempt }

function rateLimitLogin(req, res, next) {
    const ip    = req.ip;
    const now   = Date.now();
    const entry = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
    if (now - entry.lastAttempt > 15 * 60 * 1000) entry.count = 0; // reset 15 min
    entry.count++;
    entry.lastAttempt = now;
    loginAttempts.set(ip, entry);
    if (entry.count > 10) {
        return res.status(429).json({ error: 'Trop de tentatives — réessayez dans 15 minutes.' });
    }
    next();
}

// ═══════════════════════════════════════════════════════════
//  VALIDATION & SANITISATION
// ═══════════════════════════════════════════════════════════
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function isValidEmail(email) {
    return typeof email === 'string' && EMAIL_REGEX.test(email);
}

/** Supprime les balises <script> et tronque à 500 chars */
function sanitize(str, maxLen = 500) {
    if (typeof str !== 'string') return str;
    return str.trim().replace(/<script[\s\S]*?<\/script>/gi, '').substring(0, maxLen);
}

function required(fields, body) {
    return fields.find(f => !body[f]);
}

// ═══════════════════════════════════════════════════════════
//  JWT MIDDLEWARE
// ═══════════════════════════════════════════════════════════
function authMiddleware(req, res, next) {
    const header = req.headers['authorization'];
    const token  = header && header.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token manquant.' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        return res.status(403).json({ error: 'Token invalide ou expiré.' });
    }
}

function adminOnly(req, res, next) {
    if (req.user?.role !== 'admin') {
        return res.status(403).json({ error: 'Accès réservé aux administrateurs.' });
    }
    next();
}

// ═══════════════════════════════════════════════════════════
//  BASE DE DONNÉES (MySQL pool)
// ═══════════════════════════════════════════════════════════
const db = mysql.createPool({
    host:             process.env.DB_HOST || 'localhost',
    user:             process.env.DB_USER || 'root',
    password:         process.env.DB_PASS || '',
    database:         process.env.DB_NAME || 'webmarko_crm',
    waitForConnections: true,
    connectionLimit:  10,
    queueLimit:       0,
});

/** Requête MySQL avec async/await */
function dbQuery(sql, params = []) {
    return new Promise((resolve, reject) =>
        db.query(sql, params, (err, results) => (err ? reject(err) : resolve(results)))
    );
}

// Vérification de la connexion au démarrage
db.getConnection((err, conn) => {
    if (err) console.error('❌ MySQL — connexion échouée:', err.message);
    else { console.log('✅ MySQL connecté'); conn.release(); }
});

// ═══════════════════════════════════════════════════════════
//  HISTORIQUE
// ═══════════════════════════════════════════════════════════
async function logAction(userId, action, tableName, recordId, details = '') {
    try {
        await dbQuery(
            'INSERT INTO historique (user_id, action, table_name, record_id, details) VALUES (?, ?, ?, ?, ?)',
            [userId, action, tableName, String(recordId), details]
        );
    } catch (e) {
        console.warn('Historique — erreur:', e.message);
    }
}

// ═══════════════════════════════════════════════════════════
//  ──── ROUTES ────
// ═══════════════════════════════════════════════════════════

// ── Test ──────────────────────────────────────────────────
app.get('/test', (_req, res) =>
    res.json({ status: 'ok', version: '3.0', auth: 'JWT', time: new Date().toISOString() })
);

// ── Accueil ────────────────────────────────────────────────
app.get('/', (_req, res) =>
    res.sendFile(path.join(__dirname, 'public', 'webmarko-crm.html'))
);

// ═══════════════════════════════════════════════════════════
//  AUTH
// ═══════════════════════════════════════════════════════════
app.post('/login', rateLimitLogin, async (req, res) => {
    try {
        const email    = sanitize(req.body.email || '').toLowerCase();
        const password = req.body.password || '';

        if (!email || !password)  return res.status(400).json({ error: 'Email et mot de passe requis.' });
        if (!isValidEmail(email)) return res.status(400).json({ error: 'Format email invalide.' });

        const [user] = await dbQuery(
            'SELECT id, email, role, client_id, password_hash FROM users WHERE LOWER(email) = ?',
            [email]
        );
        if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });

        // Support bcrypt ET sha256 (migration progressive)
        let passwordOk = false;
        if (user.password_hash.startsWith('$2')) {
            passwordOk = await bcrypt.compare(password, user.password_hash);
        } else {
            const sha = crypto.createHash('sha256').update(password).digest('hex');
            passwordOk = sha === user.password_hash;
            if (passwordOk) {
                // Migration automatique vers bcrypt
                const newHash = await bcrypt.hash(password, SALT_ROUNDS);
                await dbQuery('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, user.id]);
            }
        }

        if (!passwordOk) return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });

        loginAttempts.delete(req.ip);

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, client_id: user.client_id },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES }
        );

        await logAction(user.id, 'LOGIN', 'users', user.id, `IP: ${req.ip}`);

        const { password_hash: _omit, ...safeUser } = user;
        return res.json({ message: 'Connexion réussie.', token, user: safeUser });
    } catch (err) {
        console.error('/login error:', err);
        return res.status(500).json({ error: 'Erreur serveur.' });
    }
});

// Refresh token
app.post('/refresh-token', authMiddleware, (req, res) => {
    const token = jwt.sign(
        { id: req.user.id, email: req.user.email, role: req.user.role, client_id: req.user.client_id },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES }
    );
    return res.json({ token });
});

// ═══════════════════════════════════════════════════════════
//  DEMANDE D'ACCÈS (formulaire public "Créer un compte")
// ═══════════════════════════════════════════════════════════
/**
 * POST /demande-acces
 * Reçoit une demande de création de compte depuis la page publique.
 * — Enregistre la demande en base (table demandes_acces)
 * — Envoie un email de confirmation au demandeur
 * — Envoie un email de notification à l'admin
 * Aucun auth requis.
 */
app.post('/demande-acces', rateLimitLogin, async (req, res) => {
    try {
        const prenom    = sanitize(req.body.prenom    || '');
        const nom       = sanitize(req.body.nom       || '');
        const email     = sanitize(req.body.email     || '').toLowerCase();
        const telephone = sanitize(req.body.telephone || '');
        const entreprise= sanitize(req.body.entreprise|| '');
        const message   = sanitize(req.body.message   || '', 1000);

        // Validation
        if (!prenom || !nom || !email)    return res.status(400).json({ error: 'Prénom, nom et email sont requis.' });
        if (!isValidEmail(email))          return res.status(400).json({ error: 'Format email invalide.' });

        // Enregistrement en base
        await dbQuery(
            `INSERT INTO demandes_acces (prenom, nom, email, telephone, entreprise, message, statut)
             VALUES (?, ?, ?, ?, ?, ?, 'En attente')`,
            [prenom, nom, email, telephone, entreprise, message]
        );

        // ── Email au demandeur ────────────────────────────────────
        await sendEmail(
            email,
            '✅ Demande reçue — WebMarko CRM',
            emailTemplate('Demande reçue avec succès !', `
                <p>Bonjour <strong>${prenom}</strong>,</p>
                <p>Nous avons bien reçu votre demande d'accès à l'espace client <strong>WebMarko CRM</strong>.</p>
                <div class="info-block">
                    <strong>Récapitulatif de votre demande :</strong><br>
                    Nom : ${prenom} ${nom}<br>
                    Email : ${email}<br>
                    ${telephone ? `Téléphone : ${telephone}<br>` : ''}
                    ${entreprise ? `Entreprise : ${entreprise}<br>` : ''}
                </div>
                <p>Notre équipe traitera votre demande dans les <strong>24 à 48 heures</strong>. 
                   Vous recevrez vos identifiants de connexion par email dès validation.</p>
                <p>Pour toute question, contactez-nous :</p>
                <p>📞 <strong>+212 6 00 00 00 00</strong><br>
                   📧 <strong>contact@webmarko.ma</strong></p>
                <p>Cordialement,<br><strong>L'équipe WebMarko</strong></p>
            `)
        );

        // ── Email à l'admin ────────────────────────────────────────
        await sendEmail(
            ADMIN_EMAIL,
            `📥 Nouvelle demande d'accès — ${prenom} ${nom}`,
            emailTemplate('Nouvelle demande d\'accès CRM', `
                <p>Une nouvelle demande d'accès a été soumise via le formulaire public.</p>
                <div class="info-block">
                    <strong>Informations du demandeur :</strong><br>
                    Nom : <strong>${prenom} ${nom}</strong><br>
                    Email : <strong>${email}</strong><br>
                    ${telephone ? `Téléphone : ${telephone}<br>` : ''}
                    ${entreprise ? `Entreprise : ${entreprise}<br>` : ''}
                    ${message ? `<br>Message : <em>${message}</em>` : ''}
                </div>
                <p>Connectez-vous au CRM pour créer ce client et activer son accès :</p>
                <a class="btn" href="http://localhost:3000">Accéder au CRM</a>
                <p style="font-size:13px;color:#7a9bbf">
                  Une fois le client créé dans le CRM, ses identifiants lui seront automatiquement envoyés par email.
                </p>
            `)
        );

        return res.json({ message: 'Demande envoyée avec succès. Vous recevrez un email de confirmation.' });
    } catch (err) {
        console.error('/demande-acces error:', err);
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'Une demande avec cet email existe déjà.' });
        }
        return res.status(500).json({ error: 'Erreur serveur. Veuillez réessayer.' });
    }
});

/** GET /demandes-acces — Liste des demandes (admin uniquement) */
app.get('/demandes-acces', authMiddleware, adminOnly, async (req, res) => {
    try {
        const rows = await dbQuery(
            'SELECT * FROM demandes_acces ORDER BY created_at DESC LIMIT 100'
        );
        return res.json(rows);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

/** PUT /demandes-acces/:id/statut — Mettre à jour le statut d'une demande */
app.put('/demandes-acces/:id/statut', authMiddleware, adminOnly, async (req, res) => {
    try {
        const { statut } = req.body;
        if (!['En attente', 'Approuvée', 'Refusée'].includes(statut)) {
            return res.status(400).json({ error: 'Statut invalide.' });
        }
        await dbQuery('UPDATE demandes_acces SET statut = ? WHERE id = ?', [statut, req.params.id]);
        return res.json({ message: 'Statut mis à jour.' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// ═══════════════════════════════════════════════════════════
//  CLIENTS
// ═══════════════════════════════════════════════════════════
app.get('/clients', authMiddleware, adminOnly, async (req, res) => {
    try {
        const page    = parseInt(req.query.page)   || 1;
        const limit   = parseInt(req.query.limit)  || 50;
        const search  = req.query.search  || '';
        const secteur = req.query.secteur || '';
        const ville   = req.query.ville   || '';
        const offset  = (page - 1) * limit;

        let where  = 'WHERE 1=1';
        const params = [];

        if (search) {
            where += ' AND (c.prenom LIKE ? OR c.nom LIKE ? OR c.email LIKE ? OR c.entreprise LIKE ?)';
            const s = `%${search}%`;
            params.push(s, s, s, s);
        }
        if (secteur) { where += ' AND c.secteur = ?'; params.push(secteur); }
        if (ville)   { where += ' AND c.ville = ?';   params.push(ville);   }

        const [{ total }] = await dbQuery(`SELECT COUNT(*) AS total FROM clients c ${where}`, params);

        const clients = await dbQuery(`
            SELECT c.*,
                COUNT(DISTINCT s.id) AS nb_sites,
                COUNT(DISTINCT r.id) AS nb_recs
            FROM clients c
            LEFT JOIN sites s ON s.client_id = c.id
            LEFT JOIN reclamations r ON r.client_id = c.id AND r.statut != 'Résolu'
            ${where}
            GROUP BY c.id
            ORDER BY c.created_at DESC
            LIMIT ? OFFSET ?
        `, [...params, limit, offset]);

        return res.json({ data: clients, total, page, limit, pages: Math.ceil(total / limit) });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.get('/clients/:id', authMiddleware, async (req, res) => {
    try {
        if (req.user.role === 'client' && String(req.user.client_id) !== String(req.params.id)) {
            return res.status(403).json({ error: 'Accès refusé.' });
        }
        const [client] = await dbQuery('SELECT * FROM clients WHERE id = ?', [req.params.id]);
        if (!client) return res.status(404).json({ error: 'Client non trouvé.' });
        return res.json(client);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.post('/clients', authMiddleware, adminOnly, async (req, res) => {
    try {
        const prenom      = sanitize(req.body.prenom     || '');
        const nom         = sanitize(req.body.nom        || '');
        const email       = sanitize(req.body.email      || '').toLowerCase();
        const telephone   = sanitize(req.body.telephone  || req.body.tel || '');
        const ville       = sanitize(req.body.ville      || '');
        const entreprise  = sanitize(req.body.entreprise || '');
        const secteur     = sanitize(req.body.secteur    || '');

        if (!prenom || !nom || !email) return res.status(400).json({ error: 'Prénom, nom et email requis.' });
        if (!isValidEmail(email))      return res.status(400).json({ error: 'Format email invalide.' });

        const result = await dbQuery(
            'INSERT INTO clients (prenom, nom, email, telephone, ville, entreprise, secteur) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [prenom, nom, email, telephone, ville, entreprise, secteur || null]
        );
        const clientId = result.insertId;

        // Créer le compte utilisateur (sauf si existant)
        const [existingUser] = await dbQuery('SELECT id FROM users WHERE LOWER(email) = ?', [email]);
        let motDePasse = prenom; // mot de passe initial = prénom

        if (!existingUser) {
            const passHash = await bcrypt.hash(motDePasse, SALT_ROUNDS);
            await dbQuery(
                'INSERT INTO users (email, password_hash, role, client_id) VALUES (?, ?, "client", ?)',
                [email, passHash, clientId]
            );
            console.log(`✅ Compte créé: ${email}`);
        } else {
            await dbQuery(
                'UPDATE users SET client_id = ?, role = "client" WHERE LOWER(email) = ? AND client_id IS NULL',
                [clientId, email]
            );
        }

        await logAction(req.user.id, 'CREATE', 'clients', clientId, `${prenom} ${nom}`);

        // Email de bienvenue au client
        await sendEmail(
            email,
            '🎉 Bienvenue chez WebMarko !',
            emailTemplate('Bienvenue dans votre espace client !', `
                <p>Bonjour <strong>${prenom}</strong>,</p>
                <p>Votre accès à l'espace client <strong>WebMarko CRM</strong> vient d'être créé.</p>
                <div class="info-block">
                    <strong>Vos identifiants de connexion :</strong><br>
                    URL : <strong>http://localhost:3000</strong><br>
                    Email : <strong>${email}</strong><br>
                    Mot de passe initial : <strong>${motDePasse}</strong>
                </div>
                <p>⚠️ Pour votre sécurité, changez votre mot de passe dès la première connexion.</p>
                <p>Depuis votre espace, vous pouvez :</p>
                <ul>
                    <li>🌐 Consulter vos sites web</li>
                    <li>🎫 Soumettre des réclamations</li>
                    <li>💰 Télécharger vos factures</li>
                </ul>
                <p>Besoin d'aide ? Contactez-nous :</p>
                <p>📞 <strong>+212 6 00 00 00 00</strong><br>📧 <strong>contact@webmarko.ma</strong></p>
                <p>Cordialement,<br><strong>L'équipe WebMarko</strong></p>
            `)
        );

        return res.json({ id: clientId, prenom, nom, email, telephone, ville, entreprise, secteur });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Cet email est déjà utilisé.' });
        return res.status(500).json({ error: err.message });
    }
});

app.put('/clients/:id', authMiddleware, adminOnly, async (req, res) => {
    try {
        const { id } = req.params;
        const prenom     = sanitize(req.body.prenom     || '');
        const nom        = sanitize(req.body.nom        || '');
        const email      = sanitize(req.body.email      || '').toLowerCase();
        const telephone  = sanitize(req.body.telephone  || req.body.tel || '');
        const ville      = sanitize(req.body.ville      || '');
        const entreprise = sanitize(req.body.entreprise || '');
        const secteur    = sanitize(req.body.secteur    || '');

        if (!prenom || !nom || !email) return res.status(400).json({ error: 'Champs requis manquants.' });

        await dbQuery(
            'UPDATE clients SET prenom=?, nom=?, email=?, telephone=?, ville=?, entreprise=?, secteur=? WHERE id=?',
            [prenom, nom, email, telephone, ville, entreprise, secteur || null, id]
        );
        await logAction(req.user.id, 'UPDATE', 'clients', id, `${prenom} ${nom}`);
        return res.json({ message: 'Client modifié.' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.delete('/clients/:id', authMiddleware, adminOnly, async (req, res) => {
    try {
        await dbQuery('DELETE FROM clients WHERE id = ?', [req.params.id]);
        await logAction(req.user.id, 'DELETE', 'clients', req.params.id, '');
        return res.json({ message: 'Client supprimé.' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// ═══════════════════════════════════════════════════════════
//  SITES
// ═══════════════════════════════════════════════════════════
app.get('/sites', authMiddleware, async (req, res) => {
    try {
        const page   = parseInt(req.query.page)  || 1;
        const limit  = parseInt(req.query.limit) || 50;
        const search = req.query.search || '';
        const statut = req.query.statut || '';
        const offset = (page - 1) * limit;

        let where  = 'WHERE 1=1';
        const params = [];

        if (req.user.role === 'client') {
            where += ' AND s.client_id = ?';
            params.push(req.user.client_id);
        }
        if (search) {
            where += ' AND (s.nom_site LIKE ? OR s.url LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }
        if (statut) { where += ' AND s.statut = ?'; params.push(statut); }

        const [{ total }] = await dbQuery(`SELECT COUNT(*) AS total FROM sites s ${where}`, params);

        const sites = await dbQuery(`
            SELECT s.*,
                c.prenom AS client_prenom, c.nom AS client_nom,
                c.email  AS client_email,  c.telephone AS client_telephone,
                c.ville  AS client_ville,  c.entreprise AS client_entreprise
            FROM sites s
            LEFT JOIN clients c ON s.client_id = c.id
            ${where}
            ORDER BY s.id DESC
            LIMIT ? OFFSET ?
        `, [...params, limit, offset]);

        return res.json({ data: sites, total, page, limit, pages: Math.ceil(total / limit) });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.post('/sites', authMiddleware, adminOnly, async (req, res) => {
    try {
        const nom_site  = sanitize(req.body.nom_site || req.body.nom || '');
        const url       = sanitize(req.body.url   || '');
        const client_id = req.body.client_id;
        const statut    = sanitize(req.body.statut || 'En ligne');
        const type      = sanitize(req.body.type  || '');
        const tech      = sanitize(req.body.tech  || '');
        const notes     = sanitize(req.body.notes || '');

        if (!nom_site || !url) return res.status(400).json({ error: 'Nom et URL requis.' });

        const result = await dbQuery(
            'INSERT INTO sites (nom_site, url, client_id, statut, type, tech, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [nom_site, url, client_id || null, statut, type, tech || null, notes || null]
        );
        await logAction(req.user.id, 'CREATE', 'sites', result.insertId, nom_site);
        return res.json({ id: result.insertId, nom_site, url, client_id, statut, type, tech, notes });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.put('/sites/:id', authMiddleware, adminOnly, async (req, res) => {
    try {
        const nom_site  = sanitize(req.body.nom_site || req.body.nom || '');
        const url       = sanitize(req.body.url      || '');
        const client_id = req.body.client_id;
        const statut    = sanitize(req.body.statut   || 'En ligne');
        const type      = sanitize(req.body.type     || '');
        const tech      = sanitize(req.body.tech     || '');
        const notes     = sanitize(req.body.notes    || '');

        await dbQuery(
            'UPDATE sites SET nom_site=?, url=?, client_id=?, statut=?, type=?, tech=?, notes=? WHERE id=?',
            [nom_site, url, client_id || null, statut, type, tech || null, notes || null, req.params.id]
        );
        await logAction(req.user.id, 'UPDATE', 'sites', req.params.id, nom_site);
        return res.json({ message: 'Site modifié.' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.delete('/sites/:id', authMiddleware, adminOnly, async (req, res) => {
    try {
        await dbQuery('DELETE FROM sites WHERE id = ?', [req.params.id]);
        await logAction(req.user.id, 'DELETE', 'sites', req.params.id, '');
        return res.json({ message: 'Site supprimé.' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// ═══════════════════════════════════════════════════════════
//  RÉCLAMATIONS
// ═══════════════════════════════════════════════════════════
app.get('/reclamations', authMiddleware, async (req, res) => {
    try {
        const page     = parseInt(req.query.page)  || 1;
        const limit    = parseInt(req.query.limit) || 50;
        const search   = req.query.search   || '';
        const statut   = req.query.statut   || '';
        const priorite = req.query.priorite || '';
        const offset   = (page - 1) * limit;

        let where  = 'WHERE 1=1';
        const params = [];

        if (req.user.role === 'client') { where += ' AND r.client_id = ?'; params.push(req.user.client_id); }
        if (search)   { where += ' AND (r.sujet LIKE ? OR r.description LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
        if (statut)   { where += ' AND r.statut = ?';   params.push(statut); }
        if (priorite) { where += ' AND r.priorite = ?'; params.push(priorite); }

        const [{ total }] = await dbQuery(`SELECT COUNT(*) AS total FROM reclamations r ${where}`, params);

        const recs = await dbQuery(`
            SELECT r.*, c.prenom AS client_prenom, c.nom AS client_nom, c.email AS client_email
            FROM reclamations r
            LEFT JOIN clients c ON r.client_id = c.id
            ${where}
            ORDER BY r.created_at DESC
            LIMIT ? OFFSET ?
        `, [...params, limit, offset]);

        return res.json({ data: recs, total, page, limit, pages: Math.ceil(total / limit) });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.post('/reclamations', authMiddleware, async (req, res) => {
    try {
        const sujet       = sanitize(req.body.sujet       || '');
        const description = sanitize(req.body.description || '');
        const type        = sanitize(req.body.type        || '');
        const statut      = req.user.role === 'admin' ? sanitize(req.body.statut || 'En attente') : 'En attente';
        const priorite    = sanitize(req.body.priorite    || 'Normale');
        const client_id   = req.user.role === 'client' ? req.user.client_id : req.body.client_id;

        if (!sujet || !description) return res.status(400).json({ error: 'Sujet et description requis.' });

        const result = await dbQuery(
            'INSERT INTO reclamations (sujet, description, statut, priorite, client_id, type) VALUES (?, ?, ?, ?, ?, ?)',
            [sujet, description, statut, priorite, client_id, type || null]
        );
        await logAction(req.user.id, 'CREATE', 'reclamations', result.insertId, sujet);

        // Notification admin
        const [cl] = await dbQuery('SELECT * FROM clients WHERE id = ?', [client_id]);
        const emoji = priorite === 'Urgente' ? '🚨' : priorite === 'Haute' ? '⚠️' : '📩';
        await sendEmail(
            ADMIN_EMAIL,
            `${emoji} Nouvelle réclamation — ${sujet}`,
            emailTemplate('Nouvelle réclamation reçue', `
                <p>Une nouvelle réclamation vient d'être soumise.</p>
                <div class="info-block">
                    Client : <strong>${cl?.prenom || ''} ${cl?.nom || ''}</strong><br>
                    Email : ${cl?.email || '—'}<br>
                    Sujet : <strong>${sujet}</strong><br>
                    Type : ${type || '—'}<br>
                    Priorité : <strong>${priorite}</strong><br>
                    Description : <em>${description}</em>
                </div>
            `)
        );

        return res.json({ id: result.insertId, sujet, description, statut, priorite, client_id, type });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.put('/reclamations/:id', authMiddleware, async (req, res) => {
    try {
        const sujet       = sanitize(req.body.sujet       || '');
        const description = sanitize(req.body.description || '');
        const statut      = sanitize(req.body.statut      || 'En attente');
        const priorite    = sanitize(req.body.priorite    || 'Normale');
        const type        = sanitize(req.body.type        || '');
        const client_id   = req.body.client_id;

        if (req.user.role === 'client') {
            const [rec] = await dbQuery('SELECT client_id FROM reclamations WHERE id = ?', [req.params.id]);
            if (!rec || String(rec.client_id) !== String(req.user.client_id)) {
                return res.status(403).json({ error: 'Accès refusé.' });
            }
        }

        await dbQuery(
            'UPDATE reclamations SET sujet=?, description=?, statut=?, priorite=?, type=?, client_id=? WHERE id=?',
            [sujet, description, statut, priorite, type || null, client_id, req.params.id]
        );
        await logAction(req.user.id, 'UPDATE', 'reclamations', req.params.id, `statut: ${statut}`);

        // Email au client si l'admin change le statut
        if (req.user.role === 'admin') {
            const [rec] = await dbQuery(
                'SELECT r.*, c.email, c.prenom FROM reclamations r JOIN clients c ON r.client_id = c.id WHERE r.id = ?',
                [req.params.id]
            );
            if (rec) {
                await sendEmail(
                    rec.email,
                    `📋 Mise à jour de votre réclamation — ${sujet}`,
                    emailTemplate('Réclamation mise à jour', `
                        <p>Bonjour <strong>${rec.prenom}</strong>,</p>
                        <p>Le statut de votre réclamation "<strong>${sujet}</strong>" a été mis à jour.</p>
                        <div class="info-block">Nouveau statut : <strong>${statut}</strong></div>
                        <p>Connectez-vous à votre espace pour plus de détails.</p>
                    `)
                );
            }
        }

        return res.json({ message: 'Réclamation modifiée.' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.delete('/reclamations/:id', authMiddleware, adminOnly, async (req, res) => {
    try {
        await dbQuery('DELETE FROM reclamations WHERE id = ?', [req.params.id]);
        await logAction(req.user.id, 'DELETE', 'reclamations', req.params.id, '');
        return res.json({ message: 'Réclamation supprimée.' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// ═══════════════════════════════════════════════════════════
//  FACTURATION
// ═══════════════════════════════════════════════════════════
app.get('/factures', authMiddleware, async (req, res) => {
    try {
        const page   = parseInt(req.query.page)  || 1;
        const limit  = parseInt(req.query.limit) || 50;
        const statut = req.query.statut || '';
        const offset = (page - 1) * limit;

        let where  = 'WHERE 1=1';
        const params = [];

        if (req.user.role === 'client') { where += ' AND f.client_id = ?'; params.push(req.user.client_id); }
        if (statut) { where += ' AND f.statut = ?'; params.push(statut); }

        const [{ total }] = await dbQuery(`SELECT COUNT(*) AS total FROM factures f ${where}`, params);

        const factures = await dbQuery(`
            SELECT f.*,
                c.prenom AS client_prenom, c.nom AS client_nom,
                c.email  AS client_email,  c.entreprise AS client_entreprise
            FROM factures f
            LEFT JOIN clients c ON f.client_id = c.id
            ${where}
            ORDER BY f.created_at DESC
            LIMIT ? OFFSET ?
        `, [...params, limit, offset]);

        for (const f of factures) {
            f.lignes = await dbQuery('SELECT * FROM facture_lignes WHERE facture_id = ?', [f.id]);
        }

        return res.json({ data: factures, total, page, limit, pages: Math.ceil(total / limit) });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.get('/factures/:id', authMiddleware, async (req, res) => {
    try {
        const [facture] = await dbQuery(`
            SELECT f.*, c.prenom AS client_prenom, c.nom AS client_nom,
                   c.email AS client_email, c.entreprise AS client_entreprise, c.ville AS client_ville
            FROM factures f LEFT JOIN clients c ON f.client_id = c.id WHERE f.id = ?
        `, [req.params.id]);
        if (!facture) return res.status(404).json({ error: 'Facture non trouvée.' });
        facture.lignes = await dbQuery('SELECT * FROM facture_lignes WHERE facture_id = ?', [facture.id]);
        return res.json(facture);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.post('/factures', authMiddleware, adminOnly, async (req, res) => {
    try {
        const { client_id, date_echeance, notes, lignes = [] } = req.body;
        if (!client_id)    return res.status(400).json({ error: 'Client requis.' });
        if (!lignes.length) return res.status(400).json({ error: 'Au moins une ligne requise.' });

        const year     = new Date().getFullYear();
        const [{ cnt }] = await dbQuery('SELECT COUNT(*) AS cnt FROM factures WHERE YEAR(created_at) = ?', [year]);
        const numero   = `FAC-${year}-${String(cnt + 1).padStart(4, '0')}`;

        const tva      = parseFloat(req.body.tva || 20);
        let total_ht   = 0;
        for (const l of lignes) total_ht += parseFloat(l.quantite || 1) * parseFloat(l.prix_unitaire || 0);
        const total_ttc = total_ht * (1 + tva / 100);

        const result = await dbQuery(
            'INSERT INTO factures (numero, client_id, statut, total_ht, tva, total_ttc, date_echeance, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [numero, client_id, 'En attente', total_ht.toFixed(2), tva, total_ttc.toFixed(2), date_echeance || null, sanitize(notes || '')]
        );
        const factureId = result.insertId;

        for (const l of lignes) {
            const sous_total = parseFloat(l.quantite || 1) * parseFloat(l.prix_unitaire || 0);
            await dbQuery(
                'INSERT INTO facture_lignes (facture_id, description, quantite, prix_unitaire, sous_total) VALUES (?, ?, ?, ?, ?)',
                [factureId, sanitize(l.description || ''), l.quantite || 1, l.prix_unitaire || 0, sous_total.toFixed(2)]
            );
        }

        await logAction(req.user.id, 'CREATE', 'factures', factureId, numero);

        // Email au client
        const [cl] = await dbQuery('SELECT * FROM clients WHERE id = ?', [client_id]);
        if (cl) {
            await sendEmail(
                cl.email,
                `💰 Nouvelle facture ${numero} — WebMarko`,
                emailTemplate(`Facture ${numero}`, `
                    <p>Bonjour <strong>${cl.prenom}</strong>,</p>
                    <p>Votre facture a été générée.</p>
                    <div class="info-block">
                        Numéro : <strong>${numero}</strong><br>
                        Montant HT : ${total_ht.toFixed(2)} MAD<br>
                        TVA (${tva}%) : ${(total_ttc - total_ht).toFixed(2)} MAD<br>
                        <strong>Total TTC : ${total_ttc.toFixed(2)} MAD</strong><br>
                        ${date_echeance ? `Échéance : ${date_echeance}` : ''}
                    </div>
                    <p>Connectez-vous à votre espace client pour télécharger la facture.</p>
                `)
            );
        }

        return res.json({ id: factureId, numero, total_ht, tva, total_ttc, statut: 'En attente' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.put('/factures/:id', authMiddleware, adminOnly, async (req, res) => {
    try {
        const { statut, date_echeance, notes, lignes } = req.body;
        await dbQuery(
            'UPDATE factures SET statut=?, date_echeance=?, notes=? WHERE id=?',
            [statut, date_echeance || null, sanitize(notes || ''), req.params.id]
        );

        if (lignes && lignes.length) {
            await dbQuery('DELETE FROM facture_lignes WHERE facture_id = ?', [req.params.id]);
            let total_ht = 0;
            for (const l of lignes) {
                const sous_total = parseFloat(l.quantite || 1) * parseFloat(l.prix_unitaire || 0);
                total_ht += sous_total;
                await dbQuery(
                    'INSERT INTO facture_lignes (facture_id, description, quantite, prix_unitaire, sous_total) VALUES (?, ?, ?, ?, ?)',
                    [req.params.id, sanitize(l.description || ''), l.quantite || 1, l.prix_unitaire || 0, sous_total.toFixed(2)]
                );
            }
            const [{ tva }] = await dbQuery('SELECT tva FROM factures WHERE id = ?', [req.params.id]);
            const total_ttc = total_ht * (1 + (tva || 20) / 100);
            await dbQuery('UPDATE factures SET total_ht=?, total_ttc=? WHERE id=?', [total_ht.toFixed(2), total_ttc.toFixed(2), req.params.id]);
        }

        await logAction(req.user.id, 'UPDATE', 'factures', req.params.id, `statut: ${statut}`);
        return res.json({ message: 'Facture modifiée.' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.delete('/factures/:id', authMiddleware, adminOnly, async (req, res) => {
    try {
        await dbQuery('DELETE FROM facture_lignes WHERE facture_id = ?', [req.params.id]);
        await dbQuery('DELETE FROM factures WHERE id = ?', [req.params.id]);
        await logAction(req.user.id, 'DELETE', 'factures', req.params.id, '');
        return res.json({ message: 'Facture supprimée.' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// ═══════════════════════════════════════════════════════════
//  HISTORIQUE
// ═══════════════════════════════════════════════════════════
app.get('/historique', authMiddleware, adminOnly, async (req, res) => {
    try {
        const page   = parseInt(req.query.page)  || 1;
        const limit  = parseInt(req.query.limit) || 50;
        const offset = (page - 1) * limit;

        const [{ total }] = await dbQuery('SELECT COUNT(*) AS total FROM historique');
        const rows = await dbQuery(`
            SELECT h.*, u.email AS user_email
            FROM historique h
            LEFT JOIN users u ON h.user_id = u.id
            ORDER BY h.created_at DESC
            LIMIT ? OFFSET ?
        `, [limit, offset]);

        return res.json({ data: rows, total, page, limit, pages: Math.ceil(total / limit) });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// ═══════════════════════════════════════════════════════════
//  STATISTIQUES
// ═══════════════════════════════════════════════════════════
app.get('/stats', authMiddleware, adminOnly, async (req, res) => {
    try {
        const [[clients], [sites], [online], [recs], [factures_att], [revenus]] = await Promise.all([
            dbQuery('SELECT COUNT(*) AS v FROM clients'),
            dbQuery('SELECT COUNT(*) AS v FROM sites'),
            dbQuery("SELECT COUNT(*) AS v FROM sites WHERE statut='En ligne'"),
            dbQuery("SELECT COUNT(*) AS v FROM reclamations WHERE statut != 'Résolu'"),
            dbQuery("SELECT COUNT(*) AS v FROM factures WHERE statut='En attente'"),
            dbQuery("SELECT COALESCE(SUM(total_ttc),0) AS v FROM factures WHERE statut='Payée'"),
        ]);
        return res.json({
            total_clients:  clients.v,
            total_sites:    sites.v,
            en_ligne:       online.v,
            total_recs:     recs.v,
            factures_att:   factures_att.v,
            revenus_total:  parseFloat(revenus.v).toFixed(2),
        });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// ═══════════════════════════════════════════════════════════
//  EXPORT CSV
// ═══════════════════════════════════════════════════════════
function csvRes(res, filename, header, rows) {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send('\uFEFF' + header + '\n' + rows.join('\n'));
}

app.get('/export/clients', authMiddleware, adminOnly, async (req, res) => {
    try {
        const rows = await dbQuery('SELECT prenom, nom, email, telephone, ville, entreprise, secteur, created_at FROM clients ORDER BY created_at DESC');
        csvRes(res, 'clients.csv',
            'Prénom,Nom,Email,Téléphone,Ville,Entreprise,Secteur,Date création',
            rows.map(c => `"${c.prenom}","${c.nom}","${c.email}","${c.telephone||''}","${c.ville||''}","${c.entreprise||''}","${c.secteur||''}","${c.created_at||''}"`)
        );
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/export/reclamations', authMiddleware, adminOnly, async (req, res) => {
    try {
        const rows = await dbQuery(`
            SELECT r.sujet, r.type, r.statut, r.priorite, r.created_at,
                   c.prenom AS client_prenom, c.nom AS client_nom
            FROM reclamations r LEFT JOIN clients c ON r.client_id = c.id
            ORDER BY r.created_at DESC
        `);
        csvRes(res, 'reclamations.csv',
            'Sujet,Type,Statut,Priorité,Date,Client',
            rows.map(r => `"${r.sujet}","${r.type||''}","${r.statut}","${r.priorite}","${r.created_at||''}","${r.client_prenom||''} ${r.client_nom||''}"`)
        );
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/export/factures', authMiddleware, adminOnly, async (req, res) => {
    try {
        const rows = await dbQuery(`
            SELECT f.numero, f.statut, f.total_ht, f.tva, f.total_ttc, f.date_echeance, f.created_at,
                   c.prenom AS client_prenom, c.nom AS client_nom, c.entreprise
            FROM factures f LEFT JOIN clients c ON f.client_id = c.id
            ORDER BY f.created_at DESC
        `);
        csvRes(res, 'factures.csv',
            'Numéro,Statut,Total HT,TVA%,Total TTC,Échéance,Date,Client,Entreprise',
            rows.map(f => `"${f.numero}","${f.statut}","${f.total_ht}","${f.tva}","${f.total_ttc}","${f.date_echeance||''}","${f.created_at||''}","${f.client_prenom||''} ${f.client_nom||''}","${f.entreprise||''}"`)
        );
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
//  USERS
// ═══════════════════════════════════════════════════════════
app.get('/users', authMiddleware, adminOnly, async (req, res) => {
    try {
        const users = await dbQuery('SELECT id, email, role, client_id, created_at FROM users ORDER BY id');
        return res.json(users);
    } catch (err) { return res.status(500).json({ error: err.message }); }
});

app.put('/users/:id/password', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'admin' && String(req.user.id) !== String(req.params.id)) {
            return res.status(403).json({ error: 'Accès refusé.' });
        }
        const { password } = req.body;
        if (!password || password.length < 8) return res.status(400).json({ error: 'Mot de passe trop court (min 8 caractères).' });
        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        await dbQuery('UPDATE users SET password_hash = ? WHERE id = ?', [hash, req.params.id]);
        return res.json({ message: 'Mot de passe mis à jour.' });
    } catch (err) { return res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════
//  DÉMARRAGE
// ═══════════════════════════════════════════════════════════
app.listen(PORT, () => {
    console.log('');
    console.log(`🚀 WebMarko CRM v3.0 — http://localhost:${PORT}`);
    console.log('─────────────────────────────────────────────');
    console.log('🔐 JWT Authentication | Rate Limiting | bcrypt');
    console.log('📦 Routes: /clients /sites /reclamations /factures /stats /historique');
    console.log('📩 Nouveau: /demande-acces (formulaire public)');
    console.log('📤 Export CSV: /export/clients /export/reclamations /export/factures');
    console.log('');
});