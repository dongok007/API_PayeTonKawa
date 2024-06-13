-- Création de la table 'client'
CREATE TABLE client (
    id INT PRIMARY KEY AUTO_INCREMENT,
    nom VARCHAR(50) NOT NULL,
    prenom VARCHAR(50) NOT NULL,
    date_naissance DATE NOT NULL,
    ville VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    contact VARCHAR(15) NOT NULL
);

-- Insertion de données dans la table 'client'
INSERT INTO client (nom, prenom, date_naissance, ville, email, contact) VALUES
('Dupont', 'Jean', '1985-06-15', 'Paris', 'jean.dupont@example.com', '0123456789'),
('Martin', 'Sophie', '1990-09-20', 'Lyon', 'sophie.martin@example.com', '0987654321'),
('Bernard', 'Alice', '1978-12-05', 'Marseille', 'alice.bernard@example.com', '0678901234'),
('Robert', 'Pierre', '1982-04-30', 'Lille', 'pierre.robert@example.com', '0456789012'),
('Lefevre', 'Lucie', '1995-11-11', 'Bordeaux', 'lucie.lefevre@example.com', '0765432198');
