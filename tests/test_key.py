from pathlib import Path

KEY = b'N\x1a\xc3x\xac\x1e\x0f\xd9*\x17pm\xc8Q\xd6w\xeb\xe5\xfb,\xcf\x91`\x8cI\xa1^\x85\x05|k\x17'

if __name__ == "__main__":
    Path("./key.key").write_bytes(KEY)