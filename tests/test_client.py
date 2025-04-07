from client import Client, run_client
from tests.test_key import KEY
import time
import argparse
from pathlib import Path

class TestClient(Client):
    client_type = b"PassThrough"
    def handle_workload(self, incoming:dict|list) -> tuple[list[int|float], bool]:
        print(f" -*->  {incoming}")
        print(f" <-*- {incoming}")
        return incoming
    
if __name__ == "__main__":
    run_client(TestClient)