import argparse
import json
from pathlib import Path
import socket

import threading
from abc import ABC, abstractmethod

from encryption import decrypt_bytes, encrypt_bytes
from errorcodes import *

class Client(ABC):
    client_type:bytes = None

    def __init__(self, enc_key:bytes, host:str, port:int, time_out:int = 1):
        if not self.client_type:
            raise NotImplementedError("Client.client_type must be set to a unique byte string representing the kind of packets it handles")
        self.enc_key = enc_key
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(time_out)


    def connect(self):
        self.socket.connect((self.host, self.port))
        self.socket.sendall(self.client_type)

    
    def send(self, data:list[int|float]):
        data_bytes = json.dumps(data).encode()
        cypher_bytes = encrypt_bytes(data_bytes, self.enc_key)

        self.socket.sendall(cypher_bytes)

    def send_error(self, error:bytes):
        self.socket.sendall(error)

    def receive(self, packet_size:int = 1024):
        encrypted_incomming = b""
        raw_len_header = self.socket.recv(6)
        # this assertion raises "busy"
        assert len(raw_len_header) == 6, "Length header malformed."

        data_len = int(raw_len_header, 16)
        
        while data_len > 0:
            encrypted_incomming += self.socket.recv(packet_size if packet_size < data_len else data_len)
            data_len -= packet_size

        
        plain_text = decrypt_bytes(encrypted_incomming, self.enc_key)
        print(plain_text)
        decoded_result = json.loads(plain_text)

        print(decoded_result)

        return decoded_result
    
    def close(self):
        self.socket.close()

    def start_task(self):
        try:
            in_data = self.receive()
        except socket.timeout:
            # handle timeout so program doesnt crash
            return
        except AssertionError as e:
            # wait for packet
            return
        except Exception as e:
            # handle bad packets so program doesnt crash
            print(f"ERROR_INVALID_PACKET: {e}")
            self.send_error(ERROR_INVALID_PACKET)
            return
        
        
        out_data = self.handle_workload(in_data)
        
        self.send(out_data)
        # Un-busy the state once the task is completed

    @abstractmethod
    def handle_workload(self, incoming:list|dict|int|float|str|bool|None) -> list|dict:
        """
        Return value should be json serializeable
        """
        pass

    def main_loop(self):
        while True:
            # Only a single separate thread should ever run at once since its only for io parrallelism anyways
            self.start_task()

    def start(self):
        self.connect()
        self.main_loop()

def run_client(client_class:type[Client], key_path:Path|None = None):
    parser = argparse.ArgumentParser("Test Client")
    parser.add_argument("host", type=str, help="The server hostname/IP.")
    parser.add_argument("port", type=int, help="The server port.")
    parser.add_argument("--key", type=Path, help="The path to the encryption key.", default=key_path if key_path else Path("./key.key"))

    args = parser.parse_args()

    client = client_class(args.key.read_bytes(), args.host, args.port)
    client.start()