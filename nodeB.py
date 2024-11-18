from fastapi import FastAPI
from pydantic import BaseModel
import httpx
from ecc.curve import Curve
from ecc.key import Key


app = FastAPI()

server_url = "http://127.0.0.1:8000"
nodeA_url = "http://127.0.0.1:8001"
nodeB_url = "http://127.0.0.1:8002"


# Sample Connection between B and A
@app.post("/connection_establishment")
async def connection_establishment(nodeA_msg : AuthStart):
    print(f"The node A's id is {nodeA_msg.nodeA_id} and B's id is {nodeB_url}")
