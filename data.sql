-- ============================================================
--  WebMarko CRM — Schema complet + Données de démo
--  Compatible avec server.js v3.0 (Express + MySQL2 + JWT)
-- ============================================================

CREATE DATABASE IF NOT EXISTS webmarko_crm
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE webmarko_crm;

-- ─────────────────────────────────────────────────────────────
--  TABLES
-- ─────────────────────────────────────────────────────────────

-- ── Clients ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS clients (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    prenom      VARCHAR(50)  NOT NULL,
    nom         VARCHAR(50)  NOT NULL,
    email       VARCHAR(100) NOT NULL UNIQUE,
    telephone   VARCHAR(20),
    ville       VARCHAR(50),
    entreprise  VARCHAR(100),
    secteur     VARCHAR(50),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ── Utilisateurs ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    email         VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,           -- bcrypt (ou SHA-256 migré progressivement)
    role          ENUM('admin','client') DEFAULT 'client',
    client_id     INT,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
);

-- ── Sites ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sites (
    id        INT AUTO_INCREMENT PRIMARY KEY,
    nom_site  VARCHAR(100) NOT NULL,
    url       TEXT         NOT NULL,
    client_id INT,
    statut    VARCHAR(50)  DEFAULT 'En ligne',
    type      VARCHAR(50),
    tech      VARCHAR(100),
    notes     TEXT,
    created_at TIMESTAMP  DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
);

-- ── Réclamations ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reclamations (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    sujet       VARCHAR(255) NOT NULL,
    description TEXT         NOT NULL,
    statut      VARCHAR(50)  DEFAULT 'En attente',
    priorite    VARCHAR(50)  DEFAULT 'Normale',
    type        VARCHAR(100),
    client_id   INT,
    created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
);

-- ── Factures ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS factures (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    numero        VARCHAR(20)   NOT NULL UNIQUE,
    client_id     INT,
    statut        VARCHAR(30)   DEFAULT 'En attente',
    total_ht      DECIMAL(10,2) DEFAULT 0.00,
    tva           DECIMAL(5,2)  DEFAULT 20.00,
    total_ttc     DECIMAL(10,2) DEFAULT 0.00,
    date_echeance DATE          NULL,
    notes         TEXT,
    created_at    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
);

-- ── Lignes de factures ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS facture_lignes (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    facture_id    INT           NOT NULL,
    description   VARCHAR(255)  NOT NULL,
    quantite      DECIMAL(10,2) DEFAULT 1,
    prix_unitaire DECIMAL(10,2) DEFAULT 0.00,
    sous_total    DECIMAL(10,2) DEFAULT 0.00,
    FOREIGN KEY (facture_id) REFERENCES factures(id) ON DELETE CASCADE
);

-- ── Historique des actions ───────────────────────────────────
CREATE TABLE IF NOT EXISTS historique (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT,
    action      VARCHAR(20)  NOT NULL,   -- CREATE | UPDATE | DELETE | LOGIN
    table_name  VARCHAR(50),
    record_id   VARCHAR(50),
    details     TEXT,
    created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- ── Demandes d'accès (formulaire public "Créer un compte") ───
-- Alimenté par POST /demande-acces (aucune auth requise)
CREATE TABLE IF NOT EXISTS demandes_acces (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    prenom      VARCHAR(50)  NOT NULL,
    nom         VARCHAR(50)  NOT NULL,
    email       VARCHAR(100) NOT NULL UNIQUE,
    telephone   VARCHAR(20),
    entreprise  VARCHAR(100),
    message     TEXT,
    statut      ENUM('En attente','Approuvée','Refusée') DEFAULT 'En attente',
    created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────────
--  INDEXES (performance)
-- ─────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_clients_email      ON clients(email);
CREATE INDEX IF NOT EXISTS idx_users_email        ON users(email);
CREATE INDEX IF NOT EXISTS idx_sites_client       ON sites(client_id);
CREATE INDEX IF NOT EXISTS idx_sites_statut       ON sites(statut);
CREATE INDEX IF NOT EXISTS idx_recs_client        ON reclamations(client_id);
CREATE INDEX IF NOT EXISTS idx_recs_statut        ON reclamations(statut);
CREATE INDEX IF NOT EXISTS idx_recs_priorite      ON reclamations(priorite);
CREATE INDEX IF NOT EXISTS idx_factures_client    ON factures(client_id);
CREATE INDEX IF NOT EXISTS idx_factures_statut    ON factures(statut);
CREATE INDEX IF NOT EXISTS idx_historique_user    ON historique(user_id);
CREATE INDEX IF NOT EXISTS idx_historique_date    ON historique(created_at);

-- ── VIEWS (rapports rapides) ──────────────────────────────────
CREATE OR REPLACE VIEW vue_factures_impayees AS
    SELECT f.numero, f.total_ttc, f.date_echeance, f.statut,
           c.prenom, c.nom, c.email, c.entreprise
    FROM factures f
    JOIN clients c ON f.client_id = c.id
    WHERE f.statut = 'En attente'
    ORDER BY f.date_echeance ASC;

CREATE OR REPLACE VIEW vue_clients_sites AS
    SELECT c.id, c.prenom, c.nom, c.email, c.entreprise,
           COUNT(s.id) AS nb_sites,
           SUM(CASE WHEN s.statut='En ligne' THEN 1 ELSE 0 END) AS sites_en_ligne
    FROM clients c
    LEFT JOIN sites s ON c.id = s.client_id
    GROUP BY c.id;

CREATE OR REPLACE VIEW vue_reclamations_ouvertes AS
    SELECT r.id, r.sujet, r.priorite, r.statut, r.created_at,
           c.prenom, c.nom, c.email
    FROM reclamations r
    JOIN clients c ON r.client_id = c.id
    WHERE r.statut != 'Résolu'
    ORDER BY FIELD(r.priorite,'Urgente','Normale','Faible'), r.created_at ASC;

-- ─────────────────────────────────────────────────────────────
--  DONNÉES DE DÉMO
-- ─────────────────────────────────────────────────────────────

-- ── Clients ──────────────────────────────────────────────────
INSERT IGNORE INTO clients (prenom, nom, email, telephone, ville, entreprise, secteur) VALUES
('Mohamed',  'El Amrani', 'mohamed@marco.com',  '+212600000001', 'Marrakech',  'Travel Atlas',      'Tourisme'),
('Salma',    'Bennani',   'salma@marco.com',    '+212600000002', 'Fes',         'Desert Tours',      'Tourisme'),
('Mustapha', 'Lahlou',    'mustapha@marco.com', '+212600000003', 'Rabat',       'Morocco Discover',  'Tourisme'),
('Nadia',    'Tazi',      'nadia@marco.com',    '+212600000004', 'Casablanca',  'Private Trips',     'Tourisme'),
('Hamza',    'Zerouali',  'hamza@marco.com',    '+212600000005', 'Agadir',      'Excursion Pro',     'Tourisme'),
('Ali',      'Kabbaj',    'ali@marco.com',      '+212600000006', 'Tangier',     'Travel Source',     'Tourisme'),
('Karim',    'Ouazzani',  'karim@marco.com',    '+212600000007', 'Ouarzazate',  'Atlas Agency',      'Tourisme'),
('Soufiane', 'Mehdi',     'soufiane@marco.com', '+212600000008', 'Tetouan',     'Sahara Trips',      'Tourisme'),
('Khadija',  'Alaoui',    'khadija@marco.com',  '+212600000009', 'Essaouira',   'Ocean Travel',      'Tourisme'),
('Rachid',   'Idrissi',   'rachid@marco.com',   '+212600000010', 'Meknes',      'Nomad Experience',  'Tourisme');

-- ── Utilisateurs ─────────────────────────────────────────────
-- Note: SHA2 hashes seront migrés vers bcrypt automatiquement au premier login
INSERT IGNORE INTO users (email, password_hash, role, client_id) VALUES
('admin@marco.com',    SHA2('admin123',  256), 'admin',  NULL),
('mohamed@marco.com',  SHA2('Mohamed',   256), 'client', 1),
('salma@marco.com',    SHA2('Salma',     256), 'client', 2),
('mustapha@marco.com', SHA2('Mustapha',  256), 'client', 3),
('nadia@marco.com',    SHA2('Nadia',     256), 'client', 4),
('hamza@marco.com',    SHA2('Hamza',     256), 'client', 5),
('ali@marco.com',      SHA2('Ali',       256), 'client', 6),
('karim@marco.com',    SHA2('Karim',     256), 'client', 7),
('soufiane@marco.com', SHA2('Soufiane',  256), 'client', 8),
('khadija@marco.com',  SHA2('Khadija',   256), 'client', 9),
('rachid@marco.com',   SHA2('Rachid',    256), 'client', 10);

-- ── Sites ────────────────────────────────────────────────────
INSERT IGNORE INTO sites (nom_site, url, client_id, statut, type, tech) VALUES
('Berber Travel',           'https://berber-travel.com',                   1, 'En ligne',    'Tourisme', 'WordPress'),
('Morocco Desert Friends',  'https://moroccodesertfriends.com',            2, 'En ligne',    'Tourisme', 'WordPress'),
('Discovering Morocco',     'https://discoveringmoroccotravel.com',        3, 'Maintenance', 'Tourisme', 'React'),
('Private Tours Marrakech', 'https://private-tours-marrakech.com',         4, 'En ligne',    'Tourisme', 'Next.js'),
('Morocco Travel Source',   'https://moroccotravelsource.com',             6, 'En ligne',    'Tourisme', 'WordPress'),
('Excursions Marrakech',    'https://excursionsinmarrakech.com',           5, 'En ligne',    'Tourisme', 'WordPress'),
('Planning to Morocco',     'https://planningtomorocco.com',               7, 'En ligne',    'Tourisme', 'Laravel'),
('Para Atlas Targa',        'https://paraatlastarga.com',                  8, 'En ligne',    'Tourisme', 'WordPress'),
('Desert Travel Admin',     'https://moroccodeserttravel.wetest.website',  9, 'Maintenance', 'Admin',    'Custom'),
('Your Morocco Holidays',   'https://your-morocco-holidays.com',          10, 'En ligne',    'Tourisme', 'WordPress');

-- ── Réclamations ─────────────────────────────────────────────
INSERT IGNORE INTO reclamations (sujet, description, statut, priorite, type, client_id) VALUES
('Site lent depuis mise à jour',   'Le site met 8 secondes à charger.',         'Résolu',     'Urgente', 'Problème de performance', 1),
('Bug formulaire de contact',      'Les emails ne partent plus du formulaire.',  'Résolu',     'Normale', 'Bug technique',           2),
('Changement logo et couleurs',    'Besoin de changer le logo et les couleurs.', 'En attente', 'Faible',  'Demande de modification', 3),
('Email professionnel bloqué',     "Impossible d'envoyer depuis le domaine.",    'En attente', 'Urgente', 'Email professionnel',      4),
('Page produit erreur 500',        'La page produit affiche une erreur 500.',    'En cours',   'Normale', 'Bug technique',            1);

-- ── Factures ─────────────────────────────────────────────────
INSERT IGNORE INTO factures (numero, client_id, statut, total_ht, tva, total_ttc, date_echeance, notes) VALUES
('FAC-2025-0001', 1, 'Payée',      2500.00, 20, 3000.00, '2025-02-01', 'Création site + hébergement'),
('FAC-2025-0002', 2, 'En attente', 1500.00, 20, 1800.00, '2025-03-15', 'Maintenance mensuelle'),
('FAC-2025-0003', 3, 'En attente',  800.00, 20,  960.00, '2025-04-01', 'Modification design'),
('FAC-2025-0004', 4, 'Payée',      3200.00, 20, 3840.00, '2025-01-20', 'Refonte complète'),
('FAC-2025-0005', 5, 'Annulée',     500.00, 20,  600.00, '2025-02-28', 'Formation CMS');

-- ── Lignes de factures ───────────────────────────────────────
INSERT IGNORE INTO facture_lignes (facture_id, description, quantite, prix_unitaire, sous_total) VALUES
(1, 'Création site WordPress',      1, 2000.00, 2000.00),
(1, 'Hébergement annuel',           1,  500.00,  500.00),
(2, 'Maintenance mensuelle',        1, 1500.00, 1500.00),
(3, 'Modification logo + couleurs', 1,  500.00,  500.00),
(3, 'Retouches pages',              3,  100.00,  300.00),
(4, 'Refonte site complet',         1, 3000.00, 3000.00),
(4, 'Formation client',             2,  100.00,  200.00),
(5, 'Formation WordPress',          1,  500.00,  500.00);

-- ─────────────────────────────────────────────────────────────
--  REQUÊTES UTILES (commentées)
-- ─────────────────────────────────────────────────────────────
-- Voir tous les clients avec leur nombre de sites:
--   SELECT c.prenom, c.nom, COUNT(s.id) AS nb_sites FROM clients c LEFT JOIN sites s ON c.id = s.client_id GROUP BY c.id;
-- Voir les sites en maintenance:
--   SELECT * FROM sites WHERE statut = 'Maintenance';
-- Voir les demandes d'accès en attente:
--   SELECT * FROM demandes_acces WHERE statut = 'En attente' ORDER BY created_at DESC;
-- Voir les factures impayées:
--   SELECT f.numero, c.prenom, c.nom, f.total_ttc, f.date_echeance FROM factures f JOIN clients c ON f.client_id = c.id WHERE f.statut = 'En attente';