@echo off
start "Auth Client" cmd /k "conda activate base && python .\auth_client.py --key .\key.key --db_path ./auth.db 127.0.0.1 2525"
start "Passthrough Client" cmd /k "conda activate base && python .\test_client_passthrough.py --key .\key.key 127.0.0.1 2525"
start "Client 2" cmd /k "conda activate base && python .\test_client2.py --key .\key.key 127.0.0.1 2525"
