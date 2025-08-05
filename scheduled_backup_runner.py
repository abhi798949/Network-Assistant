# scheduled_backup_runner.py

import requests

# Update this to match your Flask server URL and port
FLASK_URL = "http://127.0.0.1:5000"

# Replace these with device labels shown in your Web UI (index.html)
devices = [
    "R1 (192.168.29.201)",
    "R2 (192.168.29.124)",
    "R3 (192.168.29.47)",
    "R4 (192.168.29.223)"
]

def run_backup():
    try:
        response = requests.post(FLASK_URL, json={"devices": devices})
        if response.status_code == 200:
            print("Backup completed successfully.")
            print(response.json())
        else:
            print(f"Backup failed. Status Code: {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"Backup script error: {e}")

if __name__ == "__main__":
    run_backup()
