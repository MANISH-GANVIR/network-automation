# utils/spinner.py

import os
import sys
import time


def square_spinner(message, duration=2):
    # If running from Web/UI (FastAPI), disable spinner to avoid repeated output spam
    if os.environ.get("WEB_MODE") == "1":
        return

    frames = ["◰", "◳", "◲", "◱"]
    end_time = time.time() + duration
    i = 0

    while time.time() < end_time:
        sys.stdout.write(f"\r{message} [{frames[i % len(frames)]}]")
        sys.stdout.flush()
        time.sleep(0.25)
        i += 1

    sys.stdout.write(f"\r{message} ... ✔ Done!\n")
    sys.stdout.flush()