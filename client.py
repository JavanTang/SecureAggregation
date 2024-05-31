import asyncio
import websockets
import json
import codecs
import pickle
import numpy as np
from random import randrange
from copy import deepcopy


class SecAggregator:
    def __init__(self, common_base, common_mod, dimensions, weights):
        self.secretkey = randrange(common_mod)
        self.base = common_base
        self.mod = common_mod
        self.pubkey = pow(self.base, self.secretkey, self.mod)
        self.sndkey = randrange(common_mod)
        self.dim = dimensions
        self.weights = weights
        self.keys = {}
        self.id = ""

    def public_key(self):
        return self.pubkey

    def set_weights(self, wghts, dims):
        self.weights = wghts
        self.dim = dims

    def configure(self, base, mod):
        self.base = base
        self.mod = mod
        self.pubkey = pow(self.base, self.secretkey, self.mod)

    def generate_weights(self, seed):
        np.random.seed(seed)
        return np.float32(np.random.rand(self.dim[0], self.dim[1]))

    def prepare_weights(self, shared_keys, myid):
        self.keys = shared_keys
        self.id = myid
        wghts = deepcopy(self.weights)
        for sid in shared_keys:
            if sid > myid:
                print("1", myid, sid, pow(shared_keys[sid], self.secretkey, self.mod))
                wghts += self.generate_weights(
                    pow(shared_keys[sid], self.secretkey, self.mod)
                )
            elif sid < myid:
                print("2", myid, sid, pow(shared_keys[sid], self.secretkey, self.mod))
                wghts -= self.generate_weights(
                    pow(shared_keys[sid], self.secretkey, self.mod)
                )
        wghts += self.generate_weights(self.sndkey)
        return wghts

    def reveal(self, keylist):
        wghts = np.zeros(self.dim)
        for each in keylist:
            print(each)
            if each < self.id:
                wghts -= self.generate_weights(
                    pow(self.keys[each], self.secretkey, self.mod)
                )
            elif each > self.id:
                wghts += self.generate_weights(
                    pow(self.keys[each], self.secretkey, self.mod)
                )
        return -1 * wghts

    def private_secret(self):
        return self.generate_weights(self.sndkey)


class SecAggClient:
    def __init__(self, server_uri):
        self.server_uri = server_uri
        self.aggregator = SecAggregator(
            3, 100103, (10, 10), np.float32(np.full((10, 10), 3, dtype=int))
        )
        self.id = ""
        self.keys = {}

    def configure(self, b, m):
        self.aggregator.configure(b, m)

    def set_weights(self, wghts, dims):
        self.aggregator.set_weights(wghts, dims)

    def weights_encoding(self, x):
        return codecs.encode(pickle.dumps(x), "base64").decode()

    def weights_decoding(self, s):
        return pickle.loads(codecs.decode(s.encode(), "base64"))

    async def on_connect(self, websocket):
        print("Connected to server")
        await websocket.send(json.dumps({"event": "wakeup"}))

    async def on_send_public_key(self, websocket, msg):
        print("Received send_public_key event")
        self.id = msg["id"]
        pubkey = {"key": self.aggregator.public_key()}
        await websocket.send(json.dumps({"event": "public_key", **pubkey}))
        print("Sent public key:", pubkey)

    async def on_public_keys(self, websocket, msg):
        print("Received public_keys event")
        keydict = json.loads(msg["data"])
        self.keys = keydict
        print("KEYS RECEIVED: ", self.keys)
        weight = self.aggregator.prepare_weights(self.keys, self.id)
        print("Prepared weights:", weight)
        weight = self.weights_encoding(weight)
        resp = {"weights": weight}
        await websocket.send(json.dumps({"event": "weights", **resp}))
        print("Sent weights")

    async def on_send_secret(self, websocket):
        print("Received send_secret event")
        secret = self.weights_encoding(-1 * self.aggregator.private_secret())
        resp = {"secret": secret}
        await websocket.send(json.dumps({"event": "secret", **resp}))
        print("Sent secret")

    async def on_send_there_secret(self, websocket, msg):
        print("Received send_there_secret event")
        keylist = json.loads(msg["data"])
        resp = {"rvl_secret": self.weights_encoding(self.aggregator.reveal(keylist))}
        await websocket.send(json.dumps({"event": "rvl_secret", **resp}))
        print("Sent reveal secret")

    async def on_disconnect(self):
        print("Disconnected from server")

    async def handle_message(self, websocket, message):
        msg = json.loads(message)
        event = msg.get("event")
        print("Received event:", event)
        if event == "send_public_key":
            await self.on_send_public_key(websocket, msg)
        elif event == "public_keys":
            await self.on_public_keys(websocket, msg)
        elif event == "send_secret":
            await self.on_send_secret(websocket)
        elif event == "send_there_secret":
            await self.on_send_there_secret(websocket, msg)

    async def start(self):
        async with websockets.connect(self.server_uri) as websocket:
            await self.on_connect(websocket)
            try:
                async for message in websocket:
                    await self.handle_message(websocket, message)
            except websockets.ConnectionClosed:
                await self.on_disconnect()


if __name__ == "__main__":
    client = SecAggClient("ws://127.0.0.1:2019/ws")
    client.set_weights(np.zeros((10, 10)), (10, 10))
    client.configure(2, 100255)
    asyncio.get_event_loop().run_until_complete(client.start())
    print("Ready")
