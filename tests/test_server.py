import asyncio

from tests.test_key import KEY
from encoding import encode_list, decode_list
from encryption import encrypt_bytes, decrypt_bytes
from errorcodes import *
from queue import Queue
import random

class AsyncServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 2525):
        """Initialize the asynchronous server."""
        self.host = host
        self.port = port
        self.request_queue = Queue()
        self.test_data = {
            tuple(random.randint(0,999) for _ in range(3)) for _ in range(100)
        }
        self.test_recv_data = set()
        for data in self.test_data:
            self.request_queue.put(data)

    def test_add_data(self, data):
        self.test_data.add(data)
        self.request_queue.put(data)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle communication with a single client asynchronously."""
        client_addr = writer.get_extra_info('peername')
        print(f"Connection established with {client_addr}")

        try:
            client_type = await reader.read(1024)
            client_type = client_type.decode()

            failure = False

            while True:
                if self.request_queue.empty() and not failure:
                    self.test_add_data(tuple(random.randint(0,999) for _ in range(3)))
                    continue
                # Send a list of integers to the client
                integers_to_send = integers_to_send if failure else self.request_queue.get(True)

                msg = encrypt_bytes(encode_list(integers_to_send), KEY)
                
                writer.write(format(len(msg), "06X").encode() + msg)
                await writer.drain()  # Ensure data is sent
                if failure:
                    print(f"\n X X X RETRYING {integers_to_send} -> {client_addr}")
                else:
                    print(f"\n [{client_type}] SENT -> {client_addr} <- {integers_to_send}")

                # Receive a list of integers from the client
                data = await reader.read(1024)
                if not data:
                    break  # Client disconnected

                if data not in [ERROR_CLIENT_BUSY, ERROR_TIMEOUT]:
                    received_integers = decode_list(decrypt_bytes(data, KEY))
                    print(f"\n [{client_type}] RECEIVED <- {client_addr} <- {received_integers}\n    MATCHES:{tuple(received_integers) == tuple(integers_to_send)}")
                    self.test_recv_data.add(tuple(received_integers))
                    failure = False
                else:
                    print(f"\n [{client_type}] FAILED from {client_addr}\n   REASON:{data}\n   SENT:{integers_to_send} ")
                    failure = True

        except asyncio.IncompleteReadError:
            print(f"\n INCOMPLETE -> {client_addr} <- CLOSED")

        except Exception as e:
            print(f"\n ERROR -> {client_addr}: {e}")

        finally:
            writer.close()
            await writer.wait_closed()
            print(f"\n CLOSED -> {client_addr}")

    async def start(self):
        """Start the asynchronous server."""
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        print(f"TEST SERVER LISTENING ON {self.host}:{self.port}")

        async with server:
            await server.serve_forever()  # Keep server running indefinitely

if __name__ == "__main__":
    async_server = AsyncServer()
    try:
        asyncio.run(async_server.start())
    except KeyboardInterrupt:
        print("UNPROCESSED DATA:")
        for data in (async_server.test_data - async_server.test_recv_data):
            print(data)