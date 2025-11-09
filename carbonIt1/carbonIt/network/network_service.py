import subprocess
import time
import os
import sys

PLATFORM = os.name 

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "Networking"))
DATA_DIR = os.path.join(BASE_DIR, "data","tor_necessities")
HS_DIR = os.path.join(BASE_DIR,"data","HiddenService")

if PLATFORM == "nt":
    TOR_EXE = os.path.join(BASE_DIR, "tor", "tor.exe")
else:
    TOR_EXE = os.path.join(BASE_DIR, "tor", "tor")

os.makedirs(HS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)


tor_process = subprocess.Popen(
    [
        TOR_EXE,
        "--DataDirectory", DATA_DIR,
        "--HiddenServiceDir", HS_DIR,
        "--HiddenServicePort", "5050 127.0.0.1:5050"
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

hostname_file = os.path.join(HS_DIR, "hostname")
timeout = 60  # in seconds btw
start_time = time.time()

while not os.path.isfile(hostname_file):
    if time.time() - start_time > timeout:
        tor_process.terminate()
        sys.exit(1)
    time.sleep(0.5)

with open(hostname_file, "r") as f:
    onion_address = f.read().strip()
    tor_process.terminate()