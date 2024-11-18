from fastapi import FastAPI
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from random import randint
import sympy 
import base64
import requests
import hashlib
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

node_id = 8001

pka = None
public_key = None
ppka = None
partial_public_key = None

ska = None
pska = None
private_key = None

n = None
master_public_key = None
Mpk = None


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins. Replace "*" with specific domain(s) for production.
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods.
    allow_headers=["*"],  # Allows all headers.
)




server = "http://127.0.0.1:8000"
nodeA = "http://127.0.0.1:8001"
nodeB = "http://127.0.0.1:8002"

class PublicKeyResponse(BaseModel):
    ski: int
    pki: str
    hi: str



# Get initial server info
@app.get("/serverinfo")
def serverinfo():
    global n, master_public_key, Mpk
    
    response = requests.post(f"{server}/serverinfo")
    
    if response.status_code == 200:


        data = response.json()  
        
        n = data.get("order_n") 
        master_public_key = data.get("server_public_key")
        
        master_public_key = load_pem_public_key(master_public_key.encode())

        public_numbers = master_public_key.public_numbers()
        x = public_numbers.x
        y = public_numbers.y

        Mpk = [x, y]

        return {
            "n": n,
            "master_public_key": Mpk
        }
    else:
        return {"error": "Failed to fetch server info", "status_code": response.status_code}



# Generate ECC keys for this node
@app.get("/generatekeys")
def generatekeys():

    global pka, ska, public_key, private_key

    ska = randint(1, 2**256 - 1)
    
    curve = ec.SECP256R1()
    
    private_key = ec.derive_private_key(ska, curve)
    
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    x = public_numbers.x
    y = public_numbers.y

    pka = [x, y]

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "private_key": ska, 
        "public_key": public_key_pem.decode(),
        "pka": pka
    }



# Send public key to the server and request partial key generation
@app.get("/send_public_key")
def partial_key_generate():

    global public_key, private_key, pka, ppka, ska, pska, partial_public_key

    response = requests.post(
        f"{server}/receive_public_key",
        json={
            "id": node_id,
            "public_key": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()  
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        
        ski = data.get('ski')
        pki = data.get('pki')
        hi = data.get('hi')
        ri = data.get('ri')
        key = data.get('partial_public_key')

        key = load_pem_public_key(key.encode())


        print("ski :",ski)
        print("pki :",pki)
        print("hi :",hi) 
        print("ri :",ri) 
        print("partial_public_key :",key)
        ## might need to removee ri if not needed 
     
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        recalculated_hi = hashlib.sha256(f"{node_id}{public_key_pem}{pki}".encode()).hexdigest()
        
        if recalculated_hi == hi:
            print("Hash matches. Keys are valid.")
            pska = ski
            ppka = pki
            partial_public_key = key
            return {"hash matched"}

        else:
            return {"error": "Hash mismatch. Invalid partial key pair."}
    else:
        return {"error": "Failed to send public key", "status_code": response.status_code}
    

