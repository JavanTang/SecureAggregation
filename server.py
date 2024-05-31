from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import json
import codecs
import pickle
import numpy as np
from typing import List


class secaggserver:
    def __init__(self, host: str, port: int, n: int, k: int):
        self.n = n
        self.k = k
        self.aggregate = np.zeros((10, 10))
        self.host = host
        self.port = port
        self.numkeys = 0
        self.responses = 0
        self.secretresp = 0
        self.othersecretresp = 0
        self.respset = set()
        self.resplist = []
        self.ready_client_ids = set()
        self.client_keys = dict()
        self.app = FastAPI()
        self.connections: List[WebSocket] = []

    def weights_encoding(self, x):
        return codecs.encode(pickle.dumps(x), "base64").decode()

    def weights_decoding(self, s):
        return pickle.loads(codecs.decode(s.encode(), "base64"))

    async def send_message(self, websocket: WebSocket, message: dict):
        await websocket.send_text(json.dumps(message))

    async def handle_wakeup(self, websocket: WebSocket):
        print("Received wakeup from", str(websocket.client))
        await self.send_message(
            websocket,
            {
                "event": "send_public_key",
                "message": "hey I'm server",
                "id": str(websocket.client),
            },
        )

    async def handle_connect(self, websocket: WebSocket):
        print(str(websocket.client), " Connected")
        self.ready_client_ids.add(str(websocket.client))
        self.connections.append(websocket)
        print("Connected devices:", self.ready_client_ids)

    async def handle_disconnect(self, websocket: WebSocket):
        print(str(websocket.client), " Disconnected")
        self.ready_client_ids.discard(str(websocket.client))
        self.connections.remove(websocket)
        print("Connected devices:", self.ready_client_ids)

    async def handle_pubkey(self, websocket: WebSocket, key: dict):
        print(str(websocket.client), "sent key:", key["key"])
        self.client_keys[str(websocket.client)] = key["key"]
        self.numkeys += 1
        self.respset.add(str(websocket.client))
        print("keys: ", self.client_keys)
        if self.numkeys == self.n:
            print("Starting public key transfer")
            key_json = json.dumps(self.client_keys)
            for conn in self.connections:
                await self.send_message(
                    conn, {"event": "public_keys", "data": key_json}
                )

    async def handle_weights(self, websocket: WebSocket, data: dict):
        print(str(websocket.client), "sent weights")
        if self.responses < self.k:
            self.aggregate += self.weights_decoding(data["weights"])
            await self.send_message(
                websocket, {"event": "send_secret", "msg": "Hey I'm server"}
            )
            print("MESSAGE SENT TO", str(websocket.client))
            self.responses += 1
            self.respset.remove(str(websocket.client))
            self.resplist.append(str(websocket.client))
        else:
            await self.send_message(
                websocket, {"event": "late", "msg": "Hey I'm server"}
            )
            self.responses += 1
        if self.responses == self.k:
            print("k WEIGHTS RECEIVED. BEGINNING AGGREGATION PROCESS.")
            absentkeyjson = json.dumps(list(self.respset))
            for client in self.resplist:
                for conn in self.connections:
                    if conn.client == client:
                        await self.send_message(
                            conn, {"event": "send_there_secret", "data": absentkeyjson}
                        )

    async def handle_secret(self, websocket: WebSocket, data: dict):
        print(str(websocket.client), "sent SECRET")
        self.aggregate += self.weights_decoding(data["secret"])
        self.secretresp += 1
        if self.secretresp == self.k and self.othersecretresp == self.k:
            print("FINAL WEIGHTS:", self.aggregate)
            return self.aggregate

    async def handle_secret_reveal(self, websocket: WebSocket, data: dict):
        print(str(websocket.client), "sent shared secrets")
        self.aggregate += self.weights_decoding(data["rvl_secret"])
        self.othersecretresp += 1
        if self.secretresp == self.k and self.othersecretresp == self.k:
            print("FINAL WEIGHTS:", self.aggregate)
            return self.aggregate

    async def websocket_endpoint(self, websocket: WebSocket):
        await websocket.accept()
        await self.handle_connect(websocket)
        try:
            while True:
                data = await websocket.receive_json()
                event = data.get("event")
                if event == "wakeup":
                    await self.handle_wakeup(websocket)
                elif event == "public_key":
                    await self.handle_pubkey(websocket, data)
                elif event == "weights":
                    await self.handle_weights(websocket, data)
                elif event == "secret":
                    await self.handle_secret(websocket, data)
                elif event == "rvl_secret":
                    await self.handle_secret_reveal(websocket, data)
        except WebSocketDisconnect:
            await self.handle_disconnect(websocket)

    def start(self):
        import uvicorn

        uvicorn.run(self.app, host=self.host, port=self.port)


if __name__ == "__main__":
    server = secaggserver("127.0.0.1", 2019, 3, 2)
    print("listening on 127.0.0.1:2019")
    server.app.websocket("/ws")(server.websocket_endpoint)
    server.start()
