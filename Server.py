from fastapi import FastAPI
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import sympy  
import random
import hashlib
from pydantic import BaseModel

app = FastAPI()

Mpk = None
Msk = None
Master_Public_Key = None

server_url = "http://127.0.0.1:8000"
nodeA_url = "http://127.0.0.1:8001"
nodeB_url = "http://127.0.0.1:8002"

# ECC Curves Values : 
p = sympy.randprime(2**255, 2**256)  
q = sympy.randprime(2**255, 2**256)  
n = p * q  

private_key = None
public_key = None

id_public_keys = {}

class PublicKeyRequest(BaseModel):
    id: int
    public_key: str  



# Public Params Generation :
@app.post("/serverinfo")
def serverinfo():
    global Mpk,Msk,p,Master_Public_Key
    
    curve = ec.SECP256R1()
    global private_key
    global public_key
    
    private_key = ec.derive_private_key(p, curve)
    Master_Public_Key = private_key.public_key()

    public_numbers = Master_Public_Key.public_numbers()
    x = public_numbers.x
    y = public_numbers.y

    Mpk = [x, y]
    Msk = p

    print("Master Public key : ",Mpk)
    print("Master Secret Key : ",Msk)

    
    public_bytes = Master_Public_Key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "order_n": n,
        "server_public_key": public_bytes.decode()
    }



def generate_partial_key(id, public_key_pem):

    global p

    ri = random.randint(1, n - 1)

    curve = ec.SECP256R1()

    partial_private_key = ec.derive_private_key(ri, curve)
    
    partial_public_key = partial_private_key.public_key()

    public_numbers = partial_public_key.public_numbers()
    x = public_numbers.x
    y = public_numbers.y
    pki = [x, y]

    hi = hashlib.sha256(f"{id}{public_key_pem}{pki}".encode()).hexdigest()

    ski = ri + p * int(hi, 16)  

    return ski, pki, hi, ri, partial_public_key



@app.post("/receive_public_key")
def receive_public_key(request: PublicKeyRequest):

    print("ID :",request.id)
    print("Public key :",request.public_key)

    if request.id in id_public_keys:
        return {"status": "ID already exists. Skipping key generation."}
    
    id_public_keys[request.id] = request.public_key

    ski, pki, hi, ri, partial_public_key = generate_partial_key(request.id, request.public_key)

    public_bytes = partial_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


    print("ski :",ski)
    print("pki :",pki)
    print("hi :",hi)
    print("ri :",ri)

    return {
        "ski": ski,
        "pki": pki,
        "hi": hi,
        "ri": ri,
        "partial_public_key":public_bytes.decode()
    }
