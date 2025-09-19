# RaspberryPi-WiFi-Security-Tool 
This project is a proof-of-concept Wi-Fi security system developed on a Raspberry Pi 5. It is designed to detect common wireless threats, assess network security, and provide real-time alerts. A lightweight Windows GUI was also built for user interaction.  

The system is modular, built in Python with an **object-oriented design** to ensure clarity, reusability, and extensibility.  

## Key Features  
- **Rogue Access Point Detection** – identifies fake Wi-Fi networks impersonating trusted ones.  
- **Deauthentication Attack Detection** – monitors and detects deauth flooding attempts.  
- **Password Assessment** – evaluates Wi-Fi password strength.  
- **Protocol Assessment** – checks for outdated or insecure encryption standards.  
- **Real-time Alerts via MQTT** – modules communicate using MQTT messaging.  
- **Windows GUI** – provides a user-friendly interface for non-technical users.  

## Structure  
- **PEM Key Files** – used for HTTPS communication.  
- **Raspberry Pi Config Files** – configuration for automatic startup and network settings.  
- **Raspberry Pi Python Scripts** – core detection, assessment, and communication logic.  
- **Raspberry Pi Shell Scripts** – helper scripts for system operations.  
- **Raspberry Pi System Services** – systemd services for auto-start and reliability.  
- **Windows GUI Script** – desktop interface for monitoring alerts.  

## Object-Oriented Design Examples  

The project strongly applies OOP principles to encapsulate functionality into clear, modular classes.  

### `MQTTHelper.py`  

Encapsulates all MQTT communication, including connecting, publishing alerts, and handling subscribed commands.  

```python
class MQTTHelper:
    def __init__(self, Broker=MQTT_BROKER, Port=MQTT_PORT):
        self.Broker = Broker
        self.Port = Port
        self.Client = mqtt.Client()
        self.Client.on_connect = self.OnConnect
        self.Client.on_message = self.OnMessage
        self.Callbacks = {}
        self.subscribe(COMMAND_TOPICS["block"], self.BlockCallback)
        self.subscribe(COMMAND_TOPICS["run_assessment"], self.RunAssessmentCallback)

    def connect(self):
        try:
            self.Client.connect(self.Broker, self.Port, 60)
            self.Client.loop_start()
            print(f"[MQTTHelper] Connected to MQTT broker at {self.Broker}:{self.Port}")
        except Exception as E:
            print("[MQTTHelper] Failed to connect to MQTT broker:", E)
            sys.exit(1)

    def publish(self, Topic, Payload, QoS=1):
        if isinstance(Payload, dict):
            Payload = json.dumps(Payload)
        self.Client.publish(Topic, Payload, qos=QoS)
        print(f"[MQTTHelper] Published to {Topic}: {Payload}")
```
This demonstrates encapsulation (broker/port/client inside the class), abstraction (publish via one method), and extensibility (callbacks for different commands).

### `RogueAPDetection.py`

Encapsulates logic for identifying rogue access points and publishing alerts.

```python
def DetectRogue(Pkt):
    if Pkt.haslayer(Dot11Beacon):
        try:
            SSIDRaw = Pkt[Dot11Elt].info.decode(errors='ignore')
            SSID = NormaliseSSID(SSIDRaw)
        except Exception:
            SSID = "<unknown>"
        BSSID = Pkt[Dot11].addr2.lower()

        if SSID in PersonalTrusted:
            AllowedBSSIDs = PersonalTrusted[SSID]
            if BSSID not in AllowedBSSIDs:
                AlertData = {
                    "alert_type": "rogue_ap",
                    "network_type": "personal",
                    "ssid": SSID,
                    "detected_bssid": BSSID,
                    "expected": AllowedBSSIDs
                }
                PublishAlert(AlertData)
```

This shows modularity (separating scanning, detection, and alerting), integration of OOP components (publishing via MQTTHelper), and domain-specific problem solving.
