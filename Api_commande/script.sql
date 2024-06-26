-- Création de la table Commande

CREATE TABLE IF NOT EXISTS Commande (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_produit INTEGER NOT NULL,
    id_client INTEGER NOT NULL,
    date DATETIME NOT NULL,
    quantite INTEGER NOT NULL,
    numero_commande TEXT NOT NULL,
    statut TEXT NOT NULL
);


-- Insertion des données dans la table Commande

INSERT INTO Commande (id_produit, id_client, date, quantite, numero_commande, statut) VALUES
(1, 1, '2024-06-21 10:00:00', 5, 'CMD001', 'Pending'),
(2, 2, '2024-06-21 11:00:00', 3, 'CMD002', 'Shipped'),
(3, 1, '2024-06-21 12:00:00', 1, 'CMD003', 'Delivered'),
(1, 3, '2024-06-21 13:00:00', 2, 'CMD004', 'Cancelled'),
(2, 3, '2024-06-21 14:00:00', 4, 'CMD005', 'Processing');