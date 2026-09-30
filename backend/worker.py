import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.jobs import worker_loop
from app.service import init_database

if __name__ == "__main__":
    init_database()
    worker_loop()
