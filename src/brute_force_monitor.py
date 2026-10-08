import matplotlib

matplotlib.use("TkAgg")

import re
import time
from pathlib import Path

import matplotlib.pyplot as plt
import requests


# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = "/var/log/secure"
VALID_USERS_FILE = BASE_DIR / "examples" / "company_users.example.txt"


# Load known users
with open(VALID_USERS_FILE, "r", encoding="utf-8") as file:
    valid_users = {
        line.strip()
        for line in file
        if line.strip()
    }


# Store monitoring results
attempts = {}
attempted_users = set()
matched_valid_users = set()


# Match failed SSH authentication attempts
PATTERN = re.compile(
    r"Failed password.*for (invalid user )?(\S+) "
    r"from (\d+\.\d+\.\d+\.\d+)"
)


def get_geo_info(ip):
    """Return approximate location and ISP information for an IP address."""
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,regionName,city,isp",
            timeout=5,
        )

        data = response.json()

        if data.get("status") == "success":
            location = (
                f"{data.get('city')}, "
                f"{data.get('regionName')}, "
                f"{data.get('country')}"
            )
            return location, data.get("isp", "Unknown")

        return "Unknown", "Unknown"

    except requests.RequestException:
        return "Error", "Error"


def show_pie_chart():
    """Display failed SSH attempts grouped by username."""
    user_counts = {}

    for (username, _ip), count in attempts.items():
        user_counts[username] = user_counts.get(username, 0) + count

    if not user_counts:
        return

    labels = list(user_counts.keys())
    sizes = list(user_counts.values())

    plt.clf()
    plt.pie(
        sizes,
        labels=labels,
        autopct="%1.1f%%",
        startangle=140,
    )
    plt.title("Failed SSH Login Attempts by Username")
    plt.pause(0.1)


def print_summary():
    """Print the current monitoring summary."""
    print("\n--- Monitoring Summary ---")
    print("Total unique usernames attempted:", len(attempted_users))
    print("Users matched with internal list:", len(matched_valid_users))
    print(
        "Matched valid usernames:",
        matched_valid_users if matched_valid_users else "None",
    )


def monitor_log_file():
    """Continuously monitor the SSH authentication log."""
    plt.ion()

    last_summary_time = time.monotonic()

    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as file:
        # Start monitoring new log entries only.
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
            else:
                match = PATTERN.search(line)

                if match:
                    username = match.group(2)
                    ip = match.group(3)

                    key = (username, ip)
                    attempts[key] = attempts.get(key, 0) + 1
                    attempted_users.add(username)

                    if username in valid_users:
                        matched_valid_users.add(username)

                    location, isp = get_geo_info(ip)

                    print(
                        f"{username}, {ip} → "
                        f"{attempts[key]} attempts → "
                        f"Location: {location} "
                        f"[ISP: {isp}]"
                    )

            # Display summary approximately every 10 seconds.
            if time.monotonic() - last_summary_time >= 10:
                print_summary()
                show_pie_chart()
                last_summary_time = time.monotonic()


if __name__ == "__main__":
    print("Monitoring SSH brute force attempts...")
    print(f"Monitoring log: {LOG_FILE}")
    print(f"Known users file: {VALID_USERS_FILE}")

    monitor_log_file()
