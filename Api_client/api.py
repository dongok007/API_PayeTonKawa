from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
import sqlite3
from sqlite3 import Error
import jwt
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

app = FastAPI()

DATABASE = "MSPR.db"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

fake_users_db = {
    "test": {
        "username": "test",
        "hashed_password": "test"
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str

class UserInDB(User):
    hashed_password: str

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

def get_db_connection():
    try:
        connection = sqlite3.connect(DATABASE)
        connection.row_factory = sqlite3.Row
        return connection
    except Error as e:
        print(f"Error connecting to SQLite: {e}")
        return None

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

init_db()

def verify_password(plain_password, hashed_password):
    return plain_password == hashed_password

def get_password_hash(password):
    return password

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/clients", response_model=List[Client])
async def read_clients(current_user: User = Depends(get_current_user)):
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

@app.get("/clients/{client_id}", response_model=Client)
async def read_client(client_id: int, current_user: User = Depends(get_current_user)):
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

@app.post("/clients", response_model=Client)
async def create_client(client: ClientCreate, current_user: User = Depends(get_current_user)):
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

@app.put("/clients/{client_id}", response_model=Client)
async def update_client(client_id: int, client: ClientCreate, current_user: User = Depends(get_current_user)):
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

@app.delete("/clients/{client_id}", response_model=dict)
async def delete_client(client_id: int, current_user: User = Depends(get_current_user)):
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Could not connect to the database")
    cursor = connection.cursor()
    cursor.execute("DELETE FROM Client WHERE id = ?", (client_id,))
    connection.commit()
    cursor.close()
    connection.close()
    return {"message": "Client deleted successfully"}

# Route pour la racine
@app.get("/")
async def root():
    return {"message": "Welcome to the API"}

# Route pour le favicon
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("path_to_your_favicon.ico")

