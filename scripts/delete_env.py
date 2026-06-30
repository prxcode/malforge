import os
from pathlib import Path

def main():
    root_dir = Path(__file__).parent.parent
    for filename in [".env", ".env.example"]:
        filepath = root_dir / filename
        if filepath.exists():
            filepath.unlink()
            print(f"Deleted {filename}")

if __name__ == "__main__":
    main()
