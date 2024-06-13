import pytest
from fastapi.testclient import TestClient
from api import app, get_db_connection

# Utiliser une base de données SQLite en mémoire pour les tests
DATABASE_URL = "sqlite:///./test.db"

def override_get_db_connection():
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Product (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        quantity INTEGER NOT NULL
    )
    """)
    connection.commit()
    cursor.close()
    return connection

app.dependency_overrides[get_db_connection] = override_get_db_connection

client = TestClient(app)

def test_create_product():
    response = client.post("/products", json={"name": "Test Product", "description": "This is a test product", "price": 10.99, "quantity": 100})
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Test Product"
    assert data["description"] == "This is a test product"
    assert data["price"] == 10.99
    assert data["quantity"] == 100

def test_read_products():
    response = client.get("/products")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0

def test_read_product():
    response = client.post("/products", json={"name": "Another Product", "description": "This is another test product", "price": 5.99, "quantity": 50})
    product_id = response.json()["id"]

    response = client.get(f"/products/{product_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Another Product"
    assert data["description"] == "This is another test product"
    assert data["price"] == 5.99
    assert data["quantity"] == 50

def test_update_product():
    response = client.post("/products", json={"name": "Update Product", "description": "Product to update", "price": 2.99, "quantity": 20})
    product_id = response.json()["id"]

    response = client.put(f"/products/{product_id}", json={"name": "Updated Product", "description": "Updated description", "price": 3.99, "quantity": 25})
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Updated Product"
    assert data["description"] == "Updated description"
    assert data["price"] == 3.99
    assert data["quantity"] == 25

def test_delete_product():
    response = client.post("/products", json={"name": "Delete Product", "description": "Product to delete", "price": 1.99, "quantity": 10})
    product_id = response.json()["id"]

    response = client.delete(f"/products/{product_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Product deleted successfully"

    response = client.get(f"/products/{product_id}")
    assert response.status_code == 404
