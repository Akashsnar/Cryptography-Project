from fastapi import FastAPI
from pydantic import BaseModel
import httpx

app = FastAPI()

server_url = "http://127.0.0.1:8000"
nodeA_url = "http://127.0.0.1:8001"
nodeB_url = "http://127.0.0.1:8002"

def generate_random(seed, num_bits):

    p = 7
    q = 11
    n = p*q

    x_o = (seed*seed)%n
    res = ""
    prev = x_o
    for i in range(num_bits):
        curr = (prev*prev)%n
        y = curr%2
        res += str(y)
        prev = curr

    return int(res, 2)


NodeDetails = {
    nodeA_url : (nodeA_url, )
}

class SendAuthMsg(BaseModel):
    nodeA_id : str
    nodeB_id : str


@app.post("/send_auth_msg")
async def send_auth_msg(nodeB_msg : SendAuthMsg):
        