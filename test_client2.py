from client import Client, run_client
from test_key import KEY
import time
import argparse
from pathlib import Path

class TestClient2(Client):
    client_type = b"Sum"
    def handle_workload(self, incoming:dict|list) -> tuple[list[int|float], bool]:
        return sum(incoming)
    
if __name__ == "__main__":
    run_client(TestClient2)