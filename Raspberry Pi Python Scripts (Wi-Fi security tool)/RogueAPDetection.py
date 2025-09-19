#!/usr/bin/env python3
import sys, json
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt
from MQTTHelper import mqtt_helper  # Use the global instance

# Initialise trusted networks as empty dictionaries.
# Personal trusted networks will store full BSSID lists.
PersonalTrusted = {}
# Public trusted networks will store only the BSSID prefix (first three octets).
PublicTrusted = {}

# Global sets for tracking alerts and unrecognised SSIDs.
AlertedRogues = set()      # Stores tuples (SSID, rogue BSSID) that have already been alerted.
UnrecognisedSSIDs = set()  # Stores SSIDs that are not in either trusted dictionary.

def NormaliseSSID(SSID):
    """
    Replace curly apostrophes with straight ones, remove null characters,
    and strip extra whitespace.
    """
    return SSID.replace("’", "'").replace("\u0000", "").strip()

def GetPrefix(BSSID):
    """Return the first three octets (prefix) of the BSSID in lowercase."""
    parts = BSSID.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3]).lower()
    return BSSID.lower()

def PublishAlert(AlertData):
    """Publish AlertData (as JSON) to the MQTT 'alerts/rogue_ap' topic using the centralised helper."""
    mqtt_helper.publish("alerts/rogue_ap", AlertData)
    print("Published MQTT alert:", json.dumps(AlertData))

def UpdateTrustedCallback(Data):
    """
    Callback for the 'commands/update_trusted' topic.
    Expected payload format (JSON):
      {
         "personal": {
             "SSID1": ["full_bssid1", "full_bssid2"],
             "SSID2": ["full_bssid3"]
         },
         "public": {
             "SSID3": ["full_bssid4", "full_bssid5"],
             "SSID4": ["full_bssid6"]
         }
      }
    For public networks, this function converts each provided BSSID to its prefix.
    """
    global PersonalTrusted, PublicTrusted
    if "personal" in Data:
        # Store full BSSIDs (normalised to lowercase).
        PersonalTrusted = { k: [x.lower() for x in v] for k, v in Data["personal"].items() }
        print("Updated personal trusted networks:", PersonalTrusted)
    if "public" in Data:
        # For public networks, store only the BSSID prefix.
        PublicTrusted = { k: [GetPrefix(x) for x in v] for k, v in Data["public"].items() }
        print("Updated public trusted networks:", PublicTrusted)

# Subscribe to the update trusted command.
mqtt_helper.subscribe("commands/update_trusted", UpdateTrustedCallback)

def DetectRogue(Pkt):
    """Process beacon frames to detect rogue APs and publish MQTT alerts."""
    if Pkt.haslayer(Dot11Beacon):
        try:
            SSIDRaw = Pkt[Dot11Elt].info.decode(errors='ignore')
            SSID = NormaliseSSID(SSIDRaw)
        except Exception:
            SSID = "<unknown>"
        BSSID = Pkt[Dot11].addr2.lower()

        # Check against personal trusted networks (full BSSID match).
        if SSID in PersonalTrusted:
            AllowedBSSIDs = PersonalTrusted[SSID]
            if BSSID not in AllowedBSSIDs:
                if (SSID, BSSID) not in AlertedRogues:
                    AlertData = {
                        "alert_type": "rogue_ap",
                        "network_type": "personal",
                        "ssid": SSID,
                        "detected_bssid": BSSID,
                        "expected": AllowedBSSIDs
                    }
                    PublishAlert(AlertData)
                    AlertedRogues.add((SSID, BSSID))
        # Check against public trusted networks (prefix match).
        elif SSID in PublicTrusted:
            AllowedPrefixes = PublicTrusted[SSID]
            DetectedPrefix = GetPrefix(BSSID)
            if DetectedPrefix not in AllowedPrefixes:
                if (SSID, BSSID) not in AlertedRogues:
                    AlertData = {
                        "alert_type": "rogue_ap",
                        "network_type": "public",
                        "ssid": SSID,
                        "detected_bssid": BSSID,
                        "detected_prefix": DetectedPrefix,
                        "expected_prefixes": AllowedPrefixes
                    }
                    PublishAlert(AlertData)
                    AlertedRogues.add((SSID, BSSID))
        else:
            # Normalise the SSID and add to unrecognised set if it's not empty.
            CleanSSID = NormaliseSSID(SSID)
            if CleanSSID:
                UnrecognisedSSIDs.add(CleanSSID)

def StartSniffing(Interface="wlan1"):
    print(f"[*] Starting rogue AP detection on interface: {Interface}")
    try:
        # Run sniffing continuously.
        sniff(iface=Interface, prn=DetectRogue, store=0)
    except KeyboardInterrupt:
        print("Sniffing interrupted by user, stopping...")
    except Exception as E:
        print(f"Error while sniffing: {E}")
        sys.exit(1)
    # After sniffing ends, publish any unrecognised SSIDs.
    if UnrecognisedSSIDs:
        AlertData = {
            "alert_type": "unrecognised_aps",
            "ssids": list(UnrecognisedSSIDs)
        }
        PublishAlert(AlertData)
        print(f"[UNRECOGNISED APS] The following SSIDs were detected and are not in the trusted lists: {', '.join(UnrecognisedSSIDs)}")

def Main():
    Interface = sys.argv[1] if len(sys.argv) > 1 else "wlan1"
    # Do not call mqtt_helper.connect() or disconnect() here; these are managed centrally.
    StartSniffing(Interface=Interface)

if __name__ == "__main__":
    Main()
