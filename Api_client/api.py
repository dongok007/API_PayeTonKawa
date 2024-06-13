from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import sqlite3
from sqlite3 import Error

app = FastAPI()

DATABASE = "MSPR.db"

# Configuration de la connexion à la base de données
def get_db_connection():
    try:
        connection = sqlite3.connect(DATABASE)
        connection.row_factory = sqlite3.Row  # Permet d'accéder aux colonnes par nom
        return connection
    except Error as e:
        print(f"Error connecting to SQLite: {e}")
        return None

# Initialisation de la base de données
def init_db():
    connection = get_db_connection()
    if connection is None:
        print("Failed to connect to the database.")
        return
    try:
        cursor = connection.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS Client (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            prenom TEXT NOT NULL,
            date_naissance TEXT NOT NULL,
            ville TEXT NOT NULL,
            email TEXT NOT NULL,
            contact TEXT NOT NULL
        );
        """)
        connection.commit()
        cursor.close()
    except Error as e:
        print(f"Error creating table: {e}")
    finally:
        connection.close()

# Modèle de données pour le client
class Client(BaseModel):
    id: int
    nom: str
    prenom: str
    date_naissance: str
    ville: str
    email: str
    contact: str

class ClientCreate(BaseModel):
    nom: str
    prenom: str
    date_naissance: str
    ville: str
    email: str
    contact: str

# Route pour récupérer la liste des clients
@app.get("/clients", response_model=List[Client])
async def read_clients():
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Could not connect to the database")
    cursor = connection.cursor()
    cursor.execute("SELECT id, nom, prenom, date_naissance, ville, email, contact FROM Client")
    result = cursor.fetchall()
    cursor.close()
    connection.close()
    clients = [Client(**dict(row)) for row in result]
    return clients

# Route pour récupérer un client par ID
@app.get("/clients/{client_id}", response_model=Client)
async def read_client(client_id: int):
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Could not connect to the database")
    cursor = connection.cursor()
    cursor.execute("SELECT id, nom, prenom, date_naissance, ville, email, contact FROM Client WHERE id = ?", (client_id,))
    result = cursor.fetchone()
    cursor.close()
    connection.close()
    if result:
        return Client(**dict(result))
    else:
        raise HTTPException(status_code=404, detail="Client not found")

# Route pour créer un nouveau client
@app.post("/clients", response_model=Client)
async def create_client(client: ClientCreate):
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Could not connect to the database")
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO Client (nom, prenom, date_naissance, ville, email, contact) VALUES (?, ?, ?, ?, ?, ?)",
        (client.nom, client.prenom, client.date_naissance, client.ville, client.email, client.contact)
    )
    connection.commit()
    client_id = cursor.lastrowid
    cursor.close()
    connection.close()
    return Client(id=client_id, **client.dict())

# Route pour mettre à jour un client existant
@app.put("/clients/{client_id}", response_model=Client)
async def update_client(client_id: int, client: ClientCreate):
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Could not connect to the database")
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE Client SET nom = ?, prenom = ?, date_naissance = ?, ville = ?, email = ?, contact = ? WHERE id = ?",
        (client.nom, client.prenom, client.date_naissance, client.ville, client.email, client.contact, client_id)
    )
    connection.commit()
    cursor.close()
    connection.close()
    return Client(id=client_id, **client.dict())

# Route pour supprimer un client
@app.delete("/clients/{client_id}", response_model=dict)
async def delete_client(client_id: int):
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Could not connect to the database")
    cursor = connection.cursor()
    cursor.execute("DELETE FROM Client WHERE id = ?", (client_id,))
    connection.commit()
    cursor.close()
    connection.close()
    return {"message": "Client deleted successfully"}

# Initialiser la base de données au démarrage
init_db()
