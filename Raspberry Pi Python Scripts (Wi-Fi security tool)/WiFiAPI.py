#!/usr/bin/env python3
from flask import Flask, request, jsonify, after_this_request
import subprocess, re, time, threading

app = Flask(__name__)

# Precompile a regex to strip ANSI escape sequences.
AnsiEscape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

@app.route('/configure_wifi', methods=['POST'])
def ConfigureWiFi():
    """
    Receives Wi-Fi credentials, connects wlan0 to the given SSID via nmcli,
    polls until an IP is assigned, then returns that IP and tears down the AP
    a few seconds after the HTTP response is sent.
    """
    data = request.get_json(force=True)
    ssid = data.get('ssid')
    password = data.get('password')
    if not ssid or not password:
        return jsonify({
            "status": "error",
            "message": "Both SSID and password are required."
        }), 400

    # Normalize SSID
    ssid = ssid.replace("’", "'").strip()

    # Save credentials (optional)
    config_path = "/home/ismail/wifi-security-tool/data/wifi_config.conf"
    try:
        with open(config_path, "w") as f:
            f.write(f"ssid={ssid}\npassword={password}\n")
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to save configuration: {e}"
        }), 500

    # Connect with nmcli
    try:
        result = subprocess.run(
            ["sudo", "nmcli", "dev", "wifi", "connect", ssid,
             "password", password, "ifname", "wlan0"],
            capture_output=True, text=True, check=True
        )
        nm_out = result.stdout
    except subprocess.CalledProcessError as e:
        out = AnsiEscape.sub('', e.stdout + e.stderr)
        return jsonify({
            "status": "error",
            "message": f"Failed to connect wlan0 to '{ssid}':\n{out}"
        }), 500

    # Poll for IP (up to 30s)
    wlan0_ip = ""
    timeout, interval = 30, 2
    for _ in range(timeout // interval):
        ip_r = subprocess.run(
            ["nmcli", "-g", "IP4.ADDRESS", "dev", "show", "wlan0"],
            capture_output=True, text=True
        )
        wlan0_ip = ip_r.stdout.strip()
        if wlan0_ip:
            break
        time.sleep(interval)

    if not wlan0_ip:
        return jsonify({
            "status": "error",
            "message": "wlan0 did not receive an IP within the timeout period."
        }), 500

    # Schedule AP teardown after the response goes out
    @after_this_request
    def schedule_teardown(response):
        def _delayed_stop():
            time.sleep(5)  # give client time to finish the HTTP call
            subprocess.run(
                ["sudo", "systemctl", "stop", "virtual-ap.service"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        threading.Thread(target=_delayed_stop, daemon=True).start()
        return response

    # Return success with the new IP
    return jsonify({
        "status": "success",
        "message": f"Connected wlan0 to '{ssid}'.",
        "wlan0_ip": wlan0_ip
    }), 200

if __name__ == "__main__":
    app.run(
        host="0.0.0.0", port=5000,
        ssl_context=(
            '/home/ismail/wifi-security-tool/data/cert.pem',
            '/home/ismail/wifi-security-tool/data/key.pem'
        )
    )
