#!/usr/bin/env python3
import re
import os
import sys
import json
import time
from MQTTHelper import mqtt_helper  # Import the global instance

def AssessComplexity(PSK):
    Score = 0
    Recommendations = []
    
    # Check length.
    if len(PSK) >= 16:
        Score += 2
    elif len(PSK) >= 12:
        Score += 1
    else:
        Recommendations.append("Increase password length (at least 12–16 characters).")
    
    # Check for lowercase letters.
    if re.search(r"[a-z]", PSK):
        Score += 1
    else:
        Recommendations.append("Include lowercase letters.")
    
    # Check for uppercase letters.
    if re.search(r"[A-Z]", PSK):
        Score += 1
    else:
        Recommendations.append("Include uppercase letters.")
    
    # Check for digits.
    if re.search(r"\d", PSK):
        Score += 1
    else:
        Recommendations.append("Include numbers.")
    
    # Check for special characters.
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", PSK):
        Score += 1
    else:
        Recommendations.append("Include special characters (e.g., !@#$%^&*).")
    
    if Score >= 6:
        Strength = "Strong"
    elif Score >= 4:
        Strength = "Moderate"
    else:
        Strength = "Weak"
    
    return Strength, Recommendations

def ReadWiFiConfig(ConfigFile="/home/ismail/wifi-security-tool/data/wifi_config.conf"):
    """
    Read the Wi-Fi configuration file for the SSID and password.
    Expects lines of the form:
      ssid=<SSID>
      password=<PASSWORD>
    """
    if not os.path.exists(ConfigFile):
        print(f"Error: Configuration file {ConfigFile} not found.")
        sys.exit(1)
    
    SSID = None
    PSK = None
    with open(ConfigFile, "r") as F:
        for Line in F:
            Line = Line.strip()
            if Line.startswith("ssid="):
                SSID = Line.split("=", 1)[1]
            elif Line.startswith("password="):
                PSK = Line.split("=", 1)[1]
    
    if not SSID or not PSK:
        print("Error: Could not find both SSID and password in configuration file.")
        sys.exit(1)
    
    return SSID, PSK

def Main():
    # Read Wi-Fi configuration (SSID and password).
    SSID, PSK = ReadWiFiConfig()
    # Assess password complexity.
    Strength, Recommendations = AssessComplexity(PSK)
    
    # Construct the result as a dictionary.
    Result = {
        "ssid": SSID,
        "strength": Strength,
        "recommendations": Recommendations,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    
    # Print the result locally.
    print(f"{SSID}: {Strength} password detected.")
    if Recommendations:
        print("Recommendations:")
        for Rec in Recommendations:
            print(f" - {Rec}")
    
    # Publish the result to the 'alerts/password_assessment' topic using the global MQTT helper.
    Payload = json.dumps(Result)
    mqtt_helper.publish("alerts/password_assessment", Payload)
    print("Published password assessment via MQTT:", Payload)
    
    # Allow a short delay for the MQTT message to be sent.
    time.sleep(2)

if __name__ == "__main__":
    Main()
