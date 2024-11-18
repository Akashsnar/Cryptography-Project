from fastapi import FastAPI
from cryptography.hazmat.primitives import serialization
import random
import hashlib
from pydantic import BaseModel
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
import requests
from typing import List


app = FastAPI()

Mpk = None
Msk = None
Master_Public_Key = None

server_url = "http://127.0.0.1:8000"
nodeA_url = "http://127.0.0.1:8001"
nodeB_url = "http://127.0.0.1:8002"

curve = Curve.get_curve('secp256k1')
G = curve.generator  
n = curve.order  

private_key = None
public_key = None

id_public_keys = {}

class PublicKeyRequest(BaseModel):
    id: int  
    public_key: List[int]



@app.post("/serverinfo")
def serverinfo():
    global Mpk, Msk, Master_Public_Key

    global private_key
    global public_key

    Msk = random.randint(1, n - 1)
    Mpk = G*Msk

    print("Master Public key: ", Mpk)
    print("Master Secret Key: ", Msk)

    x = Mpk.x
    y = Mpk.y

    return {
        "order_n": n,
        "master_public_key": [x,y]
    }



def generate_partial_key(id, public_key_pem):
    ri = random.randint(1, n - 1)  

    partial_public_key = G*ri

    pki = [partial_public_key.x, partial_public_key.y]

    hi = hashlib.sha256(f"{id}{public_key_pem}{pki}".encode()).hexdigest()
    ski = ri + int(hi, 16) % n 

    return ski, pki, hi



@app.post("/receive_public_key")
def receive_public_key(request: PublicKeyRequest):
    print("recieved)")
    print("ID:", request.id)
    print("Public key:", request.public_key)

    if request.id in id_public_keys:
        return {"status": "ID already exists. Skipping key generation."}

    id_public_keys[request.id] = request.public_key

    ski, pki, hi = generate_partial_key(request.id, request.public_key)


    print("ski:", ski)
    print("pki:", pki)
    print("hi:", hi)

    return {
        "ski": ski,
        "pki": pki,
        "hi": hi,
    }
