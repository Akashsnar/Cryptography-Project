from fastapi import FastAPI, Depends, HTTPException
from cryptography.hazmat.primitives import serialization
import random
import hashlib
from pydantic import BaseModel
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.ecdsa import ECDSA
import requests
from typing import List
from AES_Python import AES
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import struct
import binascii
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

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

#Message :
Message = None


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

class MessageRequest(BaseModel):
    message: str  

class EncryptedMessageRequest(BaseModel):
    encrypted_message: str  



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
    global ska, public_key_a, private_key_a, pka

    ska = random.randint(1, n - 1)
    public_key_a = G*ska

    x = public_key_a.x
    y = public_key_a.y

    pka = [x, y]

    return {
        "Private_key": ska,
        "Public Key": pka
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
            return{"error": "ID already exists cannot register ID"}

        recalculated_hi = hashlib.sha256(f"{node_id}{pka}{pki}".encode()).hexdigest()

        if recalculated_hi == hi:
            print("Hash matches. Keys are valid.")
            pska = ski
            partial_public_key_a = G*pska
            ppka =[partial_public_key_a.x,partial_public_key_a.y]
            return{
                "partial Private Key":pska,
                "Partial Public Kay":ppka,
                "Given Hash":hi,
                "Recalculated Hash":recalculated_hi,
                "Success":"Hash Value Matched"
            }

        else:
            return {"error": "Hash mismatch. Invalid partial key pair."}
    else:
        return {"error": "Failed to send public key", "status_code": response.status_code}



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

    global DeltaB, Pkb, PPkb, nodeid
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
    

@app.post("/Encryption")
def encryption(request: MessageRequest):
    global SSKAB, Message

    key = binascii.unhexlify(SSKAB)

    if len(key) not in [16, 24, 32]:
        raise ValueError("Session key must be 16, 24, or 32 bytes long.")

    data = request.message
    data_bytes = data.encode('utf-8')

    cipher = AES.new(key, AES.MODE_ECB)

    ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))

    encrypted_hex = binascii.hexlify(ciphertext).decode('utf-8')
    print(f"Original data: {data}")
    print(f"Encrypted data (hex): {encrypted_hex}")

    response = requests.post(f"{nodeB}/Decryption", json={
        "encrypted_message":encrypted_hex
    })

    return {
        "result": "Message Delievered",
        "Encrypted Message":encrypted_hex,
        "Original Message":data
    }

@app.post("/Decryption")
def decryption(request: EncryptedMessageRequest):
    global SSKAB
    global Message

    key = binascii.unhexlify(SSKAB)

    if len(key) not in [16, 24, 32]:
        raise ValueError("Session key must be 16, 24, or 32 bytes long.")

    encrypted_message_hex = request.encrypted_message
    try:
        ciphertext = binascii.unhexlify(encrypted_message_hex)
    except binascii.Error:
        raise HTTPException(status_code=400, detail="Invalid hexadecimal input.")

    cipher = AES.new(key, AES.MODE_ECB)

    try:
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Invalid padding or decryption error.")

    decrypted_text = decrypted_data.decode('utf-8')

    # Output for debugging
    print(f"Encrypted data (hex): {encrypted_message_hex}")
    print(f"Decrypted data: {decrypted_text}")

    Message = decrypted_text

    # Return decrypted text
    return {
        "Message Recieved"
    }

@app.get("/Message") 
def get_message():
    global Message
    if Message is None:
        raise HTTPException(status_code=404, detail="No message has been decrypted yet.")
    
    return {"Message": Message}
