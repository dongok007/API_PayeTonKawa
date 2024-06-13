CREATE TABLE Produit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nom VARCHAR(255) NOT NULL,
    prix DECIMAL(10, 2) NOT NULL,
    description TEXT,
    stock INT NOT NULL
);

INSERT INTO Produit (nom, prix, description, stock) VALUES
('Produit A', 19.99, 'Description du produit A', 100),
('Produit B', 29.99, 'Description du produit B', 150),
('Produit C', 39.99, 'Description du produit C', 200),
('Produit D', 49.99, 'Description du produit D', 250),
('Produit E', 59.99, 'Description du produit E', 300);
