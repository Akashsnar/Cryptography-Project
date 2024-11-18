from fastapi import FastAPI, Depends
from cryptography.hazmat.primitives import serialization
import random
import hashlib
from pydantic import BaseModel
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
import requests
from typing import List
from fastapi.middleware.cors import CORSMiddleware

# app = FastAPI()
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Specify allowed origins
    allow_credentials=True,                  # Allow cookies and credentials
    allow_methods=["*"],                     # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],                     # Allow all headers
)


# State variables for Node A
pka = None
public_key_a = None
ppka = None
partial_public_key_a = None

ska = None
private_key_a = None
pska = None

n = None

#Server Variables
master_public_key = None
Mpk = None

#Other Node Variable :
DeltaB = None
Pkb = None
PPkb = None
nodeid = None

#Session key :
SSK1 = None
SSK2 = None
SSKAB = None

server = "http://127.0.0.1:8000"
nodeA = "http://127.0.0.1:8001"
nodeB = "http://127.0.0.1:8002"
node_id = 8001  # Node A's ID

# Initialize curve and n
curve = Curve.get_curve('secp256k1')
G = curve.generator
n = curve.order

class PublicKeyResponse(BaseModel):
    ski: int
    pki: str
    hi: str
    
class CurvePoints(BaseModel):
    ThetaB : list[int]
    DeltaB : list[int]
    AlphaB : int
    Pkb : list[int]
    PPkb : list[int]
    nodeid: int



@app.get("/serverinfo")
def serverinfo():
    global n, master_public_key, Mpk
    print("hellow")
    response = requests.post(f"{server}/serverinfo")

    if response.status_code == 200:
        data = response.json()

        n = data.get("order_n")
        Mpk = data.get("master_public_key")
        master_public_key = Point(Mpk[0], Mpk[1], curve)

        print("Master Public Key : ", master_public_key)
        print("Mpk : ", Mpk)
        print("order : ", n)

        return {
            "n": n,
            "master_public_key": Mpk
        }
    else:
        return {"error": "Failed to fetch server info", "status_code": response.status_code}


@app.get("/generatekeys")
def generatekeys():
    global ska, public_key_a, private_key_a, pka

    ska = random.randint(1, n - 1)
    public_key_a = G*ska

    x = public_key_a.x
    y = public_key_a.y

    pka = [x, y]

    return {
        "private_key": ska,
        "pka": pka
    }


@app.get("/send_public_key")
def partial_key_generate():
    global public_key_a, private_key_a, pka, ppka, ska, pska, partial_public_key_a

    response = requests.post(
        f"{server}/receive_public_key",
        json={
            "id": node_id,
            "public_key": pka
        }
    )
    print("Data returned")

    if response.status_code == 200:
        data = response.json()

        ski = data.get('ski')
        pki = data.get('pki')
        hi = data.get('hi')

        print("ski:", ski)
        print("pki:", pki)
        print("hi:", hi)

        if(hi == None):
            return {"error": "ID already exists."}

        recalculated_hi = hashlib.sha256(f"{node_id}{pka}{pki}".encode()).hexdigest()

        if recalculated_hi == hi:
            print("Hash matches. Keys are valid.")
            pska = ski
            partial_public_key_a = G*pska
            ppka =[partial_public_key_a.x,partial_public_key_a.y]

        else:
            return {"error": "Hash mismatch. Invalid partial key pair."}
    else:
        return {"error": "Failed to send public key", "status_code": response.status_code}





# A->B

@app.get("/authenticate")
def authenticate():
    global VA, UA, ThetaA, DeltaA, AlphaA

    # Generate random values VA and UA
    VA = random.randint(1, n - 1)
    UA = random.randint(1, n - 1)

    # Calculate ThetaA and DeltaA
    ThetaA = G * VA
    DeltaA = G * UA

    print("ThetaA :", ThetaA)
    print("DeltaA :", DeltaA)

    # Calculate hash
    hash_value = int(hashlib.sha256(f"{node_id}{ThetaA}{DeltaA}".encode()).hexdigest(), 16)
    print("hash :", hash_value)

    # Calculate AlphaA
    AlphaA = VA + (hash_value * (ska + pska))
    print("AlphaA :", AlphaA)

    # Calculate Public Keys
    print("pka :",pka)
    print("ppka :",ppka)

    print("Public Key : ",public_key_a)
    print("Partial Public Key :",partial_public_key_a)


    # Prepare data for verification
    verification_data = {
        "ThetaA": [ThetaA.x, ThetaA.y],
        "DeltaA": [DeltaA.x, DeltaA.y],
        "AlphaA": AlphaA,
        "Pka": pka,
        "PPka": ppka,
        "nodeid":node_id
    }

    print("Check 1 :",G*AlphaA)
    print("Check 2A :",ThetaA + (( (G*ska) + (G*pska) )*hash_value))
    print("Check 2B :",ThetaA + (( (public_key_a) + (partial_public_key_a) )*hash_value))

    # Call /verify_keys
    response = requests.post(f"{nodeB}/verify_keys", json=verification_data)

    # Check response and return the result
    if response.status_code == 200:
        return {
            "generated_values": verification_data,
            "verification_result": response.json()
        }
    else:
        return {
            "error": "Failed to verify keys",
            "status_code": response.status_code,
            "response": response.text
        }


@app.post("/verify_keys")
def verify_keys(data : CurvePoints):

    global DeltaB, Pkb, PPkb, nodeid

    ThetaB = Point(data.ThetaB[0], data.ThetaB[1],curve)
    print("ThetaB :",ThetaB)
    DeltaB = Point(data.DeltaB[0], data.DeltaB[1],curve)
    print("DeltaB :",DeltaB)
    AlphaB = data.AlphaB
    print("AlphaB :",AlphaB)
    Pkb = Point(data.Pkb[0],data.Pkb[1],curve)
    print("Pkb :",Pkb)
    PPkb = Point(data.PPkb[0],data.PPkb[1],curve)
    print("PPkb :",PPkb)
    nodeid = data.nodeid
    print("nodeid :",nodeid)

    hash = int(hashlib.sha256(f"{nodeid}{ThetaB}{DeltaB}".encode()).hexdigest(), 16)


    # Calculate G * AlphaB
    Check1 = G*AlphaB
    print("Check1 :",Check1)

    # Calculate ThetaB + (G_skb + G_pskb) * hash_value
    Check2 = ThetaB + ((Pkb + PPkb)*hash)
    print("Check2 :",Check2)

    if(Check1 == Check2):
        print("Node B Authenticated")
        return {"result": "Node B Authenticated"}

    else:
        print("Node B Not Authenticated")
        return {"result": "Node B Not Authenticated"}



@app.get("/GenerateSessionKey")
def GenerateSessionKey():

    global SSK1, SSK2, SSKAB
    global SSK1,SSK2,SSKAB

    #SSK1
    #SSK1 = DeltaB * UA
    SSK1 = DeltaB * UA
    print("SSK1 : ",SSK1)

    #SSK2
    #SSK2 = (DeltaB * (ska + pska)) + (Pkb * UA) +(PPkb * UA)
    SSK2 = (DeltaB * (ska + pska)) + (Pkb * UA) + (PPkb * UA)
    print("SSK2 : ",SSK2)

    #SSK-1-2-Hash
    SSKAB = hashlib.sha256(f"{node_id}{nodeid}{DeltaA}{DeltaB}{SSK1}{SSK2}".encode()).hexdigest()
    print(SSKAB)
    return {
        "SSKAB":SSKAB
    }

@app.get("/AuthSessionKey")
def AuthSessionKey():

    global SSKAB
    
    responseB = requests.get(f"{nodeB}/GenerateSessionKey")
    responseB_data = responseB.json()
    SSKB = responseB_data["SSKAB"]
    print("SSKAB :", SSKB)

    if(SSKAB == SSKB):
        print("Session Key Correct")
        return {"result": "Session Established"}
    else:
        print("Sessin Key Incorrect")
        return {"result": "Session Not Established"}