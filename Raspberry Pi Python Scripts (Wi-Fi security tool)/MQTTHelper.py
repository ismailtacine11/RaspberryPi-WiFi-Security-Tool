#!/usr/bin/env python3
import paho.mqtt.client as mqtt
import json
import sys
import threading
import time  # Added import for time
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

# Global dictionary to record blocked BSSIDs with timestamps.
BLOCKED_BSSIDS = {}

# Broker settings – adjust MQTT_BROKER if needed (e.g., use your Pi's static IP for external devices)
MQTT_BROKER = "localhost"  # For the Pi; external clients should use the Pi's static IP.
MQTT_PORT = 1883

# Topic hierarchy for alerts and commands.
ALERT_TOPICS = {
    "rogue_ap": "alerts/rogue_ap",
    "deauth": "alerts/deauth",
    "protocol_assessment": "alerts/protocol_assessment",
    "password_assessment": "alerts/password_assessment"
}
COMMAND_TOPICS = {
    "update_trusted": "commands/update_trusted",
    "block": "commands/block",
    "run_assessment": "commands/run_assessment"
}

class MQTTHelper:
    def __init__(self, Broker=MQTT_BROKER, Port=MQTT_PORT):
        self.Broker = Broker
        self.Port = Port
        self.Client = mqtt.Client()
        self.Client.on_connect = self.OnConnect
        self.Client.on_message = self.OnMessage
        # Dictionary to hold callbacks for specific topics.
        self.Callbacks = {}
        # Subscribe to block command and on-demand assessment commands.
        self.subscribe(COMMAND_TOPICS["block"], self.BlockCallback)
        self.subscribe(COMMAND_TOPICS["run_assessment"], self.RunAssessmentCallback)
        # Optionally, other command subscriptions (e.g., update_trusted) can be added here.

    def connect(self):
        try:
            self.Client.connect(self.Broker, self.Port, 60)
            self.Client.loop_start()
            print(f"[MQTTHelper] Connected to MQTT broker at {self.Broker}:{self.Port}")
        except Exception as E:
            print("[MQTTHelper] Failed to connect to MQTT broker:", E)
            sys.exit(1)

    def OnConnect(self, Client, Userdata, Flags, RC):
        print("[MQTTHelper] MQTT OnConnect callback, result code:", RC)
        # Subscribe to any topics with registered callbacks, avoiding duplicate subscriptions.
        for Topic in self.Callbacks:
            if not hasattr(self, 'SubscribedTopics'):
                self.SubscribedTopics = set()
            if Topic not in self.SubscribedTopics:
                self.Client.subscribe(Topic)
                self.SubscribedTopics.add(Topic)
                print(f"[MQTTHelper] Subscribed to topic: {Topic}")

    def OnMessage(self, Client, Userdata, Msg):
        Payload = Msg.payload.decode()
        print(f"[MQTTHelper] Received message on topic {Msg.topic}: {Payload}")
        if Msg.topic in self.Callbacks:
            try:
                Data = json.loads(Payload)
            except json.JSONDecodeError:
                Data = Payload
            self.Callbacks[Msg.topic](Data)

    def subscribe(self, Topic, Callback):
        """
        Subscribe to a topic and register a callback to be executed when a message is received.
        """
        self.Client.subscribe(Topic)
        self.Callbacks[Topic] = Callback
        print(f"[MQTTHelper] Subscribed to topic: {Topic}")

    def publish(self, Topic, Payload, QoS=1):
        """
        Publish a payload to a topic. If the payload is a dictionary, it is converted to JSON.
        """
        if isinstance(Payload, dict):
            Payload = json.dumps(Payload)
        self.Client.publish(Topic, Payload, qos=QoS)
        print(f"[MQTTHelper] Published to {Topic}: {Payload}")

    def disconnect(self):
        self.Client.loop_stop()
        self.Client.disconnect()
        print("[MQTTHelper] Disconnected from MQTT broker.")

    # ---------------- Block Rogue AP Functionality ---------------- #
    def BlockRogueAP(self, RogueBSSID, Iface="wlan1", Count=10):
        """
        Sends deauthentication frames to block a rogue AP.
        
        Parameters:
          RogueBSSID: The BSSID of the rogue access point (string).
          Iface: The monitor-mode interface to use (default "wlan1").
          Count: The number of deauth frames to send (default 10).
        """
        # Construct the deauth frame; broadcast the deauth to all clients.
        Pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff",
                                  addr2=RogueBSSID,
                                  addr3=RogueBSSID) / Dot11Deauth(reason=7)
        sendp(Pkt, iface=Iface, count=Count, inter=0.1)
        print(f"[MQTTHelper] Sent {Count} deauth frames to block rogue AP {RogueBSSID} on interface {Iface}")
        # Record that this rogue BSSID was blocked just now.
        global BLOCKED_BSSIDS
        BLOCKED_BSSIDS[RogueBSSID] = time.time()

    def BlockCallback(self, Data):
        """
        Callback for the 'commands/block' topic. Expects Data to be a JSON object with at least:
          - "target_bssid": the rogue AP's BSSID.
          Optionally:
          - "interface": monitor-mode interface to use.
          - "count": number of deauth frames to send.
        """
        TargetBSSID = Data.get("target_bssid")
        Iface = Data.get("interface", "wlan1")
        Count = Data.get("count", 10)
        if TargetBSSID:
            print(f"[MQTTHelper] Block command received for BSSID: {TargetBSSID} (Iface: {Iface}, Count: {Count})")
            self.BlockRogueAP(TargetBSSID, Iface, Count)
        else:
            print("[MQTTHelper] Block command received but no 'target_bssid' provided.")

    # ---------------- On-Demand Assessment Functionality ---------------- #
    def RunAssessmentCallback(self, Data):
        """
        Callback for the 'commands/run_assessment' topic.
        Expects Data to be a JSON object with an 'assessment_type' key,
        where the value is either "protocol" or "password".
        """
        assessment_type = Data.get("assessment_type", "").lower()
        if assessment_type == "protocol":
            print("[MQTTHelper] Run assessment command received: Protocol")
            # Launch the protocol assessment in a separate thread.
            try:
                from ProtocolAssessment import Main as ProtocolAssessmentMain
                threading.Thread(target=ProtocolAssessmentMain, name="ProtocolAssessmentThread").start()
            except Exception as e:
                print(f"[MQTTHelper] Error starting Protocol Assessment: {e}")
        elif assessment_type == "password":
            print("[MQTTHelper] Run assessment command received: Password")
            # Launch the password assessment in a separate thread.
            try:
                from PasswordAssessment import Main as PasswordAssessmentMain
                threading.Thread(target=PasswordAssessmentMain, name="PasswordAssessmentThread").start()
            except Exception as e:
                print(f"[MQTTHelper] Error starting Password Assessment: {e}")
        else:
            print("[MQTTHelper] Unknown assessment type received:", assessment_type)

# Global instance for use in other modules.
mqtt_helper = MQTTHelper()

if __name__ == "__main__":
    print("[MQTTHelper] This module is intended to be imported, not run directly.")
