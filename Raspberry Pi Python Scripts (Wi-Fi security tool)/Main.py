#!/usr/bin/env python3
"""
Main control script for the Wi‑Fi Security Assessment Tool.

This central programme performs the following functions:
  - Connects to the MQTT broker once at startup.
  - Starts the Wi‑Fi configuration REST API (from WiFiAPI) so that the phone app can send Wi‑Fi credentials.
  - Launches continuous monitoring modules (Rogue AP detection and De‑auth attack detection) on dedicated interfaces.
  - Relies on the global MQTT helper (mqtt_helper) to manage all MQTT messaging, including on‑demand assessment commands.

When a phone app command (e.g. "run_assessment" for protocol or password assessments) is received via MQTT,
the MQTT helper spawns the corresponding assessment module in a new thread.
"""

import threading
import time

# Import the Flask app from WiFiAPI.
from WiFiAPI import app as WiFiAPIApp

# Import the continuous detection modules.
import RogueAPDetection
import DeauthDetection

# Import the global MQTT helper instance.
from MQTTHelper import mqtt_helper

def RunWiFiAPI():
    """
    Run the Wi‑Fi configuration REST API.
    
    The REST API listens on all interfaces (0.0.0.0) over HTTPS, using a self‑signed certificate and key.
    The phone app sends Wi‑Fi credentials to this API, and the Pi uses nmcli to connect its built‑in Wi‑Fi (wlan0)
    to the selected network.
    """
    WiFiAPIApp.run(
        host="0.0.0.0",
        port=5000,
        ssl_context=(
            '/home/ismail/wifi-security-tool/data/cert.pem',
            '/home/ismail/wifi-security-tool/data/key.pem'
        )
    )

def RunRogueAPDetection():
    """
    Start the Rogue AP detection module.
    
    This module continuously sniffs for beacon frames on the monitor interface (wlan1) and publishes MQTT alerts
    for any detected rogue access points.
    """
    RogueAPDetection.Main()

def RunDeauthDetection():
    """
    Start the De‑auth attack detection module.
    
    This module continuously monitors for de‑authentication frames and publishes MQTT alerts when the threshold is exceeded.
    """
    DeauthDetection.Main()

def Main():
    # Connect to the MQTT broker once, centrally.
    mqtt_helper.connect()
    
    # Create threads for each of the core services.
    WiFiAPIThread = threading.Thread(target=RunWiFiAPI, name="WiFiAPIThread")
    RogueAPDetectionThread = threading.Thread(target=RunRogueAPDetection, name="RogueAPDetectionThread")
    DeauthDetectionThread = threading.Thread(target=RunDeauthDetection, name="DeauthDetectionThread")
    
    # Start all threads.
    WiFiAPIThread.start()
    RogueAPDetectionThread.start()
    DeauthDetectionThread.start()
    
    print("[Main] All core services have started. The system is operational.")
    
    try:
        # Keep the main thread alive by joining the worker threads.
        WiFiAPIThread.join()
        RogueAPDetectionThread.join()
        DeauthDetectionThread.join()
    except KeyboardInterrupt:
        print("Received KeyboardInterrupt, shutting down...")
    finally:
        mqtt_helper.disconnect()

if __name__ == "__main__":
    Main()
