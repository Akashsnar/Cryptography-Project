from fastapi import FastAPI
from cryptography.hazmat.primitives import serialization
import random
import hashlib
from pydantic import BaseModel
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
import requests


app = FastAPI()

# State variables for Node B
pkb = None
public_key_b = None
ppkb = None
partial_public_key_b = None

skb = None
private_key_b = None
pskb = None

n = None

#Server Variables
master_public_key = None
Mpk = None

#Other Node Variable :
DeltaA = None
Pka = None
PPka = None
nodeid = None

#Session key :
SSK1 = None
SSK2 = None
SSKAB = None

server = "http://127.0.0.1:8000"
nodeA = "http://127.0.0.1:8001"
nodeB = "http://127.0.0.1:8002"
node_id = 8002  # Node B's ID

# Initialize curve and n
curve = Curve.get_curve('secp256k1')
G = curve.generator
n = curve.order

class PublicKeyResponse(BaseModel):
    ski: int
    pki: str
    hi: str

class CurvePoints(BaseModel):
    ThetaA : list[int]
    DeltaA : list[int]
    AlphaA : int
    Pka : list[int]
    PPka : list[int]
    nodeid: int



@app.get("/serverinfo")
def serverinfo():
    global n, master_public_key, Mpk

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
    global skb, public_key_b, private_key_b, pkb

    skb = random.randint(1, n - 1)
    public_key_b = G * skb

    x = public_key_b.x
    y = public_key_b.y

    pkb = [x, y]

    return {
        "private_key": skb,
        "pkb": pkb
    }


@app.get("/send_public_key")
def partial_key_generate():
    global public_key_b, private_key_b, pkb, ppkb, skb, pskb, partial_public_key_b

    response = requests.post(
        f"{server}/receive_public_key",
        json={
            "id": node_id,
            "public_key": pkb
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

        recalculated_hi = hashlib.sha256(f"{node_id}{pkb}{pki}".encode()).hexdigest()

        if recalculated_hi == hi:
            print("Hash matches. Keys are valid.")
            pskb = ski
            partial_public_key_b = G*pskb
            ppkb = [partial_public_key_b.x,partial_public_key_b.y]

        else:
            return {"error": "Hash mismatch. Invalid partial key pair."}
    else:
        return {"error": "Failed to send public key", "status_code": response.status_code}



@app.get("/authenticate")
def authenticate():
    global VB, UB, ThetaB, DeltaB, AlphaB

    # Generate random values VB and UB
    VB = random.randint(1, n - 1)
    UB = random.randint(1, n - 1)

    # Calculate ThetaA and DeltaB
    ThetaB = G * VB
    DeltaB = G * UB

    print("ThetaB :", ThetaB)
    print("DeltaB :", DeltaB)

    # Calculate hash
    hash_value = int(hashlib.sha256(f"{node_id}{ThetaB}{DeltaB}".encode()).hexdigest(), 16)
    print("hash :", hash_value)

    # Calculate AlphaA
    AlphaB = VB + (hash_value * (skb + pskb))
    print("AlphaB :", AlphaB)

    # Calculate Public Keys
    print("pkb :",pkb)
    print("ppkb :",ppkb)

    print("Public Key : ",public_key_b)
    print("Partial Public Key :",partial_public_key_b)


    # Prepare data for verification
    verification_data = {
        "ThetaB": [ThetaB.x, ThetaB.y],
        "DeltaB": [DeltaB.x, DeltaB.y],
        "AlphaB": AlphaB,
        "Pkb": pkb,
        "PPkb": ppkb,
        "nodeid":node_id
    }

    print("Check 1 :",G*AlphaB)
    print("Check 2A :",ThetaB + (( (G*skb) + (G*pskb) )*hash_value))
    print("Check 2B :",ThetaB + (( (public_key_b) + (partial_public_key_b) )*hash_value))

    # Call /verify_keys
    response = requests.post(f"{nodeA}/verify_keys", json=verification_data)

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

    global DeltaA, Pka, PPka, nodeid

    ThetaA = Point(data.ThetaA[0], data.ThetaA[1],curve)
    print("ThetaA :",ThetaA)
    DeltaA = Point(data.DeltaA[0], data.DeltaA[1],curve)
    print("DeltaA :",DeltaA)
    AlphaA = data.AlphaA
    print("AlphaA :",AlphaA)
    Pka = Point(data.Pka[0],data.Pka[1],curve)
    print("Pka :",Pka)
    PPka = Point(data.PPka[0],data.PPka[1],curve)
    print("PPka :",PPka)
    nodeid = data.nodeid
    print("nodeid :",nodeid)

    hash = int(hashlib.sha256(f"{nodeid}{ThetaA}{DeltaA}".encode()).hexdigest(), 16)


    # Calculate G * AlphaA
    Check1 = G*AlphaA
    print("Check1 :",Check1)

    # Calculate ThetaA + (G_ska + G_pska) * hash_value
    Check2 = ThetaA + ((Pka + PPka)*hash)
    print("Check2 :",Check2)

    if(Check1 == Check2):
        print("Node A Authenticated")
        return {"result": "Node A Authenticated"}

    else:
        print("Node A Not Authenticated")
        return {"result": "Node A Not Authenticated"}



@app.get("/GenerateSessionKey")
def GenerateSessionKey():

    global DeltaA, Pka, PPka, nodeid
    global SSK1,SSK2,SSKAB

    #SSK1
    #SSK1 = DeltaA * UB
    SSK1 = DeltaA * UB
    print("SSK1 : ",SSK1)

    #SSK2
    #SSK2 = (DeltaA * (skb + pskb)) + (Pka * UB) +(PPka * UB)
    SSK2 = (DeltaA * (skb + pskb)) + (Pka * UB) +(PPka * UB)
    print("SSK2 : ",SSK2)

    #SSK-1-2-Hash
    SSKAB = hashlib.sha256(f"{nodeid}{node_id}{DeltaA}{DeltaB}{SSK1}{SSK2}".encode()).hexdigest()
    print(SSKAB)
    return {
        "SSKAB":SSKAB
    }

@app.get("/AuthSessionKey")
def AuthSessionKey():

    global SSKAB
    
    responseA = requests.get(f"{nodeA}/GenerateSessionKey")
    responseA_data = responseA.json()
    SSKA = responseA_data["SSKAB"]
    print("SSKAB :", SSKA )


    if(SSKA == SSKAB):
        print("Session Key Correct")
        return {"result": "Session Established"}
    else:
        print("Sessin Key Incorrect")
        return {"result": "Session Not Established"}