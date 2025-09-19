#!/usr/bin/env python3
import sys, time, json
from collections import Counter
from scapy.all import sniff, Dot11Deauth
from MQTTHelper import mqtt_helper, BLOCKED_BSSIDS  # Import the global instance and blocked dict

# Dictionary to store records of de-auth frames for each destination MAC.
# Key: Destination MAC; Value: list of tuples (Timestamp, Attacker MAC)
DeauthRecords = {}

# Dictionary to store the maximum count of de-auth frames observed per destination.
MaxDeauthCounts = {}

# Threshold settings: 10 frames within 5 seconds.
Threshold = 15        # Number of de-auth frames required.
TimeWindow = 5        # Time window in seconds.

# Dictionary to store the last alert time per destination (to update alerts at most once per second).
LastAlertTime = {}

def PublishDeauthAlert(Destination, Count, AttackerMAC, MaxCount):
    """Publish a de-auth alert message over MQTT as a JSON payload."""
    AlertData = {
        "alert_type": "deauth_attack",
        "destination": Destination,
        "frame_count": Count,
        "max_frame_count": MaxCount,
        "most_frequent_attacker": AttackerMAC,
        "spoofed": True,  # Indicates that the attacker MAC is likely spoofed.
        "time_window": TimeWindow,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    mqtt_helper.publish("alerts/deauth", AlertData)
    print("Published de-auth MQTT alert:", json.dumps(AlertData))

def DetectDeauth(Pkt):
    """Process de-authentication frames to count frames per destination and publish MQTT alerts when threshold is reached."""
    if Pkt.haslayer(Dot11Deauth):
        CurrentTime = time.time()
        Destination = Pkt.addr1  # The victim's MAC address.
        Attacker = Pkt.addr2     # The sender's (attacker's) MAC address.
        
        # Ignore frames from an attacker that was blocked less than 30 seconds ago.
        if Attacker in BLOCKED_BSSIDS and (CurrentTime - BLOCKED_BSSIDS[Attacker] < 30):
            return
        
        # Initialise record list for this victim if not present.
        if Destination not in DeauthRecords:
            DeauthRecords[Destination] = []
        DeauthRecords[Destination].append((CurrentTime, Attacker))
        
        # Remove records older than TimeWindow seconds.
        DeauthRecords[Destination] = [(T, A) for (T, A) in DeauthRecords[Destination] if CurrentTime - T <= TimeWindow]
        Count = len(DeauthRecords[Destination])
        
        # Update maximum count for this destination.
        if Destination not in MaxDeauthCounts or Count > MaxDeauthCounts[Destination]:
            MaxDeauthCounts[Destination] = Count
        
        # If the count meets or exceeds the threshold, publish an alert (once per second per victim).
        if Count >= Threshold:
            AttackerList = [A for (T, A) in DeauthRecords[Destination]]
            MostCommon = Counter(AttackerList).most_common(1)
            AttackerMAC = MostCommon[0][0] if MostCommon else "Unknown"
            if Destination not in LastAlertTime or (CurrentTime - LastAlertTime[Destination]) >= 1:
                PublishDeauthAlert(Destination, Count, AttackerMAC, MaxDeauthCounts[Destination])
                LastAlertTime[Destination] = CurrentTime
        else:
            # Clear stored alert time if count drops below threshold.
            if Destination in LastAlertTime:
                del LastAlertTime[Destination]

def StartSniffing(Interface="wlan1"):
    print(f"[*] Starting de-auth attack detection on interface: {Interface}")
    try:
        # Run sniffing continuously (no timeout).
        sniff(iface=Interface, prn=DetectDeauth, store=0)
    except KeyboardInterrupt:
        print("De-auth sniffing interrupted by user, stopping...")
    except Exception as E:
        print(f"Error while sniffing: {E}")
        sys.exit(1)

def Main():
    Interface = sys.argv[1] if len(sys.argv) > 1 else "wlan1"
    # Do not manage MQTT connection here; connection management is handled centrally.
    StartSniffing(Interface=Interface)

if __name__ == "__main__":
    Main()
