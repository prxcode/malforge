import sys
import traceback

try:
    from app.main import app
    print("SUCCESS")
except Exception as e:
    with open("crash_log.txt", "w") as f:
        traceback.print_exc(file=f)
