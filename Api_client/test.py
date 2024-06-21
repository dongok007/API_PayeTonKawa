import pytest
from fastapi.testclient import TestClient
from api import app, get_db_connection

# Utiliser une base de données en mémoire pour les tests
DATABASE_TEST = ":memory:"

def override_get_db_connection():
    try:
        connection = sqlite3.connect(DATABASE_TEST)
        connection.row_factory = sqlite3.Row
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
        return connection
    except Error as e:
        print(f"Error connecting to SQLite: {e}")
        return None

app.dependency_overrides[get_db_connection] = override_get_db_connection

client = TestClient(app)

def test_create_client():
    response = client.post("/clients", json={
        "nom": "Dongo",
        "prenom": "John",
        "date_naissance": "1990-01-01",
        "ville": "Paris",
        "email": "john.doe@example.com",
        "contact": "0123456789"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["nom"] == "Dongo"
    assert data["prenom"] == "John"
    assert data["date_naissance"] == "1990-01-01"
    assert data["ville"] == "Paris"
    assert data["email"] == "john.doe@example.com"
    assert data["contact"] == "0123456789"

def test_read_clients():
    response = client.get("/clients")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["nom"] == "Doe"
    assert data[0]["prenom"] == "John"

def test_read_client():
    response = client.get("/clients/2")
    assert response.status_code == 200
    data = response.json()
    assert data["nom"] == "Doe"
    assert data["prenom"] == "John"

def test_update_client():
    response = client.put("/clients/1", json={
        "nom": "Doe",
        "prenom": "Jane",
        "date_naissance": "1990-01-01",
        "ville": "Paris",
        "email": "jane.doe@example.com",
        "contact": "0123456789"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["prenom"] == "Jane"
    assert data["email"] == "jane.doe@example.com"

def test_delete_client():
    response = client.delete("/clients/1")
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Client deleted successfully"

    response = client.get("/clients/1")
    assert response.status_code == 404
    data = response.json()
    assert data["detail"] == "Client not found"
