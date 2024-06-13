from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import sqlite3
from sqlite3 import Error

app = FastAPI()

# Configuration de la connexion à la base de données
def get_db_connection():
    try:
        connection = sqlite3.connect("MSPR.db")
        return connection
    except Error as e:
        print(f"Error connecting to SQLite: {e}")
        return None

# Modèle de données pour le produit
class Product(BaseModel):
    id: int
    name: str
    description: str
    price: float
    quantity: int

class ProductCreate(BaseModel):
    name: str
    description: str
    price: float
    quantity: int

# Route pour récupérer la liste des produits
@app.get("/products", response_model=List[Product])
async def read_products():
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Could not connect to the database")
    cursor = connection.cursor()
    cursor.execute("SELECT id, name, description, price, quantity FROM Product")
    result = cursor.fetchall()
    cursor.close()
    connection.close()
    products = [Product(id=product[0], name=product[1], description=product[2], price=product[3], quantity=product[4]) for product in result]
    return products

# Route pour récupérer un produit par ID
@app.get("/products/{product_id}", response_model=Product)
async def read_product(product_id: int):
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Could not connect to the database")
    cursor = connection.cursor()
    cursor.execute("SELECT id, name, description, price, quantity FROM Product WHERE id = ?", (product_id,))
    result = cursor.fetchone()
    cursor.close()
    connection.close()
    if result:
        return Product(id=result[0], name=result[1], description=result[2], price=result[3], quantity=result[4])
    else:
        raise HTTPException(status_code=404, detail="Product not found")

# Route pour créer un nouveau produit
@app.post("/products", response_model=Product)
async def create_product(product: ProductCreate):
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Could not connect to the database")
    cursor = connection.cursor()
    cursor.execute("INSERT INTO Product (name, description, price, quantity) VALUES (?, ?, ?, ?)", (product.name, product.description, product.price, product.quantity))
    connection.commit()
    product_id = cursor.lastrowid
    cursor.close()
    connection.close()
    return Product(id=product_id, name=product.name, description=product.description, price=product.price, quantity=product.quantity)

# Route pour mettre à jour un produit existant
@app.put("/products/{product_id}", response_model=Product)
async def update_product(product_id: int, product: ProductCreate):
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Could not connect to the database")
    cursor = connection.cursor()
    cursor.execute("UPDATE Product SET name = ?, description = ?, price = ?, quantity = ? WHERE id = ?", (product.name, product.description, product.price, product.quantity, product_id))
    connection.commit()
    cursor.close()
    connection.close()
    return Product(id=product_id, name=product.name, description=product.description, price=product.price, quantity=product.quantity)

# Route pour supprimer un produit
@app.delete("/products/{product_id}", response_model=dict)
async def delete_product(product_id: int):
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Could not connect to the database")
    cursor = connection.cursor()
    cursor.execute("DELETE FROM Product WHERE id = ?", (product_id,))
    connection.commit()
    cursor.close()
    connection.close()
    return {"message": "Product deleted successfully"}
