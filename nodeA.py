from fastapi import FastAPI
from pydantic import BaseModel
import httpx

app = FastAPI()

server_url = "http://127.0.0.1:8000"
nodeA_url = "http://127.0.0.1:8001"
nodeB_url = "http://127.0.0.1:8002"

@app.post("/connection_request")
async def connection_request():
    async with httpx.AsyncClient() as client:
        await client.post(f"{nodeB_url}/connection_establishment", json={"nodeA_id" : nodeA_url})
    return {"status" : "Sent data to Node B"}