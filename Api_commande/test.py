import pytest
from fastapi.testclient import TestClient
from Commande import app  

client = TestClient(app)

def test_read_commandes():
    response = client.get("/commandes")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_create_commande():
    new_commande = {
        "id_produit": 1,
        "id_client": 1,
        "date": "2024-06-21T10:00:00",
        "quantite": 5,
        "numero_commande": "CMD006",
        "statut": "Pending"
    }
    response = client.post("/commandes", json=new_commande)
    assert response.status_code == 200
    data = response.json()
    assert data["id_produit"] == new_commande["id_produit"]
    assert data["id_client"] == new_commande["id_client"]
    assert data["date"] == new_commande["date"]
    assert data["quantite"] == new_commande["quantite"]
    assert data["numero_commande"] == new_commande["numero_commande"]
    assert data["statut"] == new_commande["statut"]

def test_read_commande():
    response = client.get("/commandes/1")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 1

def test_update_commande():
    updated_commande = {
        "id_produit": 2,
        "id_client": 2,
        "date": "2024-06-22T10:00:00",
        "quantite": 10,
        "numero_commande": "CMD007",
        "statut": "Shipped"
    }
    response = client.put("/commandes/1", json=updated_commande)
    assert response.status_code == 200
    data = response.json()
    assert data["id_produit"] == updated_commande["id_produit"]
    assert data["id_client"] == updated_commande["id_client"]
    assert data["date"] == updated_commande["date"]
    assert data["quantite"] == updated_commande["quantite"]
    assert data["numero_commande"] == updated_commande["numero_commande"]
    assert data["statut"] == updated_commande["statut"]

def test_delete_commande():
    # Assurez-vous qu'il y a une commande avec id 1 dans votre base de données pour ce test
    response = client.delete("/commandes/1")
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Commande deleted successfully"

    # Vérifiez que la commande a été supprimée
    response = client.get("/commandes/1")
    assert response.status_code == 404
    data = response.json()
    assert data["detail"] == "Commande not found"
