#!/usr/bin/env python3
import subprocess, csv, os, sys, time, re, json
from MQTTHelper import mqtt_helper  # Import the global instance

# Precompile a regex to match a MAC address.
MacRegex = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

def NormaliseSSID(SSID):
    """
    Replace curly apostrophes with straight ones and strip extra whitespace.
    """
    return SSID.replace("’", "'").strip()

def ParseCSV(CSVFilename):
    """
    Parse the given CSV file and return a dictionary of networks.
    Each network key is the ESSID, with a value dictionary containing Privacy, Cipher, and Authentication.
    """
    Networks = {}
    with open(CSVFilename, newline='', encoding='utf-8', errors='ignore') as CSVFile:
        Reader = csv.reader(CSVFile)
        for Row in Reader:
            # Skip rows that don't have the expected columns.
            if not Row or len(Row) < 14:
                continue
            FirstCol = Row[0].strip()
            if not MacRegex.match(FirstCol):
                continue
            BSSID = FirstCol
            Channel = Row[3].strip()
            Privacy = Row[5].strip()
            Cipher = Row[6].strip()
            Auth = Row[7].strip()
            ESSID = Row[13].strip()
            # Use the ESSID as key; if multiple rows share the same ESSID, keep the first.
            if ESSID and ESSID not in Networks:
                Networks[ESSID] = {
                    "Privacy": Privacy,
                    "Cipher": Cipher,
                    "Authentication": Auth
                }
    return Networks

def ClassifyNetwork(Privacy, Cipher, Auth):
    """
    Classify the network based on its encryption settings.
    Flags as insecure if the network is Open, uses WEP, or uses WPA with TKIP.
    """
    P = Privacy.upper()
    C = Cipher.upper()
    A = Auth.upper()
    if P == "OPN":
        return "Insecure, open (no encryption)"
    elif P == "WEP":
        return "Insecure, uses WEP"
    elif P.startswith("WPA"):
        if "TKIP" in C:
            return "Insecure, uses WPA with TKIP"
        else:
            return "Secure (WPA2/WPA3)"
    else:
        return "Unknown encryption"

def RunAirodump(Interface, Timeout):
    """
    Run airodump-ng on the specified interface for a given timeout period.
    Deletes any previous CSV capture files before starting.
    """
    CapturePrefix = "capture"
    # Delete any previous CSV capture files.
    for Filename in os.listdir("."):
        if Filename.startswith(CapturePrefix) and Filename.endswith(".csv"):
            os.remove(Filename)
    print(f"[*] Running airodump-ng on channel 6 for {Timeout} seconds...")
    try:
        subprocess.run([
            "sudo", "airodump-ng", "-w", CapturePrefix, "--output-format", "csv",
            "-c", "6", Interface
        ], timeout=Timeout+5)
    except subprocess.TimeoutExpired:
        print("[*] Airodump-ng capture complete.")

def GetProtocolAssessment(Networks):
    """
    Generate a protocol assessment summary for the given networks.
    For each network, classify its encryption based on Privacy, Cipher, and Authentication.
    """
    Summary = {}
    for ESSID, Info in Networks.items():
        ESSIDClean = " ".join(ESSID.split())  # Collapse extra whitespace.
        Privacy = Info.get("Privacy", "").strip()
        Cipher = Info.get("Cipher", "").strip()
        Auth = Info.get("Authentication", "").strip()
        Assessment = ClassifyNetwork(Privacy, Cipher, Auth)
        Summary[ESSIDClean] = Assessment
    return Summary

def Main():
    Interface = sys.argv[1] if len(sys.argv) > 1 else "wlan1"
    Timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 180

    # Run airodump-ng to capture networks.
    RunAirodump(Interface, Timeout)
    
    CSVFile = "capture-01.csv"
    Networks = ParseCSV(CSVFile)
    if Networks:
        Summary = GetProtocolAssessment(Networks)
        print("\n--- Protocol Assessment Summary ---")
        for ESSID, Assessment in Summary.items():
            print(f"{ESSID}: {Assessment}")
        print("------------------------------------")
        
        # Publish the summary via MQTT using the global instance.
        Payload = json.dumps(Summary)
        mqtt_helper.publish("alerts/protocol_assessment", Payload, QoS=1)
        print("Published protocol assessment via MQTT:", Payload)
    else:
        print("[ERROR] No networks found in the CSV output.")
    
    # Clean up: delete the CSV file.
    if os.path.exists(CSVFile):
        os.remove(CSVFile)
        print(f"[*] Deleted CSV file: {CSVFile}")
    
    # Allow time for the MQTT message to be sent.
    time.sleep(2)

if __name__ == "__main__":
    Main()
