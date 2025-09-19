#!/usr/bin/env python3
"""
WiFiSecurityApp.py - A KivyMD app for interacting with the Pi's Wi‑Fi Security Assessment Tool.

Workflow:
  1. The app starts on the Wi‑Fi Configuration screen where it scans for available Wi‑Fi networks (using netsh on Windows).
     The user selects a network and enters its password; these credentials are sent via a REST API to the Pi.
  2. On successful configuration, the app transitions to the Main screen.
  3. The Main screen auto‑refreshes to display notifications as clickable bars (using an MDList). Each notification shows a brief
     summary (e.g. "Protocol assessment completed" or "Warning: Rogue AP detected!"). When tapped, the app opens a
     Notification Detail screen showing full details.
  4. In the Notification Detail screen, if the alert is a Rogue AP alert, a disclaimer is displayed above a "Block Rogue AP" button.
     The block command now uses the detected BSSID extracted from the alert.
  5. The Update Trusted Networks screen lists available networks and allows the user to mark each as Personal or Public.
  6. Once Wi‑Fi credentials are sent, the Pi connects wlan0 to the external network and returns its new IP address.
     This new IP is used for subsequent MQTT communication.
  
Usage:
  python WiFiSecurityApp.py
"""

import json, threading, subprocess, requests, time, re
from kivy.lang import Builder
from kivy.clock import Clock
from kivy.properties import StringProperty, ListProperty
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.spinner import Spinner
import paho.mqtt.client as mqtt
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.selectioncontrol import MDCheckbox
from kivymd.uix.list import OneLineListItem, MDList

# ---------------- Configuration Constants ----------------
MQTT_BROKER = "192.168.4.1" # Default broker IP; will be updated after Wi‑Fi configuration.
MQTT_PORT = 1883
REST_API_URL = "https://192.168.4.1:5000/configure_wifi"  # Replace with the Pi's IP address in the REST API URL (HTTPS)

MQTT_ALERT_TOPIC = "alerts/#"
MQTT_CMD_RUN_ASSESSMENT = "commands/run_assessment"
MQTT_CMD_UPDATE_TRUSTED = "commands/update_trusted"
MQTT_CMD_BLOCK = "commands/block"

# ---------------- MQTT Client Class ----------------
class MQTTClient:
    """
    MQTTClient manages the MQTT connection. It subscribes to the alert topic and stores notifications.
    Each notification is stored as a dictionary with "summary" and "details" keys.
    """
    def __init__(self):
        self.client = mqtt.Client()
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.notifications = []

    def on_connect(self, client, userdata, flags, rc):
        print("Connected to MQTT broker with result code:", rc)
        self.client.subscribe(MQTT_ALERT_TOPIC)
        print("Subscribed to topic:", MQTT_ALERT_TOPIC)

    def on_message(self, client, userdata, msg):
        try:
            data = json.loads(msg.payload.decode())
            if msg.topic.startswith("alerts/protocol_assessment"):
                details = "Protocol Assessment Summary:\n"
                for ssid, classification in data.items():
                    details += f" • {ssid}: {classification}\n"
                summary = "Protocol assessment completed!"
            elif msg.topic.startswith("alerts/rogue_ap"):
                details = (
                    f"Rogue AP Alert:\n"
                    f" • Network: {data.get('ssid', 'Unknown')}\n"
                    f" • Detected BSSID: {data.get('detected_bssid', 'N/A')}\n"
                    f" • Expected: {', '.join(data.get('expected', []))}\n"
                )
                summary = "Warning: Rogue AP detected!"
            elif msg.topic.startswith("alerts/deauth"):
                details = (
                    f"De-auth Attack Alert:\n"
                    f" • Destination: {data.get('destination', 'Unknown')}\n"
                    f" • Frame Count: {data.get('frame_count', 'N/A')}\n"
                    f" • Attacker: {data.get('most_frequent_attacker', 'Unknown')}\n"
                    f" • Time Window: {data.get('time_window', 'N/A')}s\n"
                    f" • Timestamp: {data.get('timestamp', 'N/A')}\n"
                )
                summary = "De-auth attack detected!"
            elif msg.topic.startswith("alerts/password_assessment"):
                details = (
                    f"Password Assessment for {data.get('ssid', 'Unknown')}:\n"
                    f" • Strength: {data.get('strength', 'Unknown')}\n"
                )
                recs = data.get("recommendations", [])
                if recs:
                    details += " • Recommendations:\n"
                    for rec in recs:
                        details += f"    - {rec}\n"
                details += f" • Timestamp: {data.get('timestamp', 'N/A')}\n"
                summary = "Password assessment completed!"
            else:
                details = f"{msg.topic}: {data}"
                summary = "New alert received."
        except Exception:
            details = f"{msg.topic}: {msg.payload.decode()}"
            summary = "New alert received."
        print("MQTT Alert Received:", details)
        shortSummary = summary if len(summary) <= 60 else summary[:60] + "..."
        self.notifications.append({"summary": shortSummary, "details": details})

    def start(self):
        self.client.connect(MQTT_BROKER, MQTT_PORT, 60)
        self.client.loop_start()

    def publish(self, topic, payload):
        self.client.publish(topic, payload)

# Create a global MQTT client instance.
mqttClient = MQTTClient()

# ---------------- Helper Function: ExtractBssid ----------------
def ExtractBssid(details):
    """
    Extracts the detected BSSID from a details string.
    Expects a line containing "Detected BSSID:" followed by a MAC address.
    Returns the MAC address if found; otherwise, returns None.
    """
    match = re.search(r"Detected BSSID:\s*([0-9A-Fa-f:]{17})", details, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

# ---------------- Trusted Network Entry Widget ----------------
class TrustedNetworkEntry(MDBoxLayout):
    """
    A widget for a trusted network entry.
    Displays the SSID and its BSSIDs, along with a checkbox and a spinner
    for selecting whether the network is Personal or Public.
    """
    def __init__(self, ssid, bssids, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'horizontal'
        self.size_hint_y = None
        self.height = "48dp"
        self.padding = "8dp"
        self.spacing = "8dp"
        self.checkbox = MDCheckbox()
        self.add_widget(self.checkbox)
        self.label = MDLabel(text=f"{ssid}\nBSSIDs: {', '.join(bssids)}",
                              halign='left', size_hint_x=0.6, font_name="Roboto")
        self.add_widget(self.label)
        self.spinner = Spinner(text="Select Type", values=["Personal", "Public"],
                                size_hint=(None, None), size=("120dp", "48dp"))
        self.add_widget(self.spinner)
        self.Ssid = ssid
        self.Bssids = bssids

# ---------------- Wi‑Fi Scanner Helper (Windows) ----------------
def GetAvailableNetworks():
    """
    Uses 'netsh wlan show networks mode=bssid' on Windows to list available Wi‑Fi networks.
    Returns a list of dictionaries with keys 'ssid' and 'bssids'.
    """
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            universal_newlines=True,
            timeout=30
        )
    except Exception as e:
        print("Error scanning networks:", e)
        return []
    
    networks = []
    currentSsid = None
    currentBssids = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SSID "):
            if currentSsid is not None:
                networks.append({"ssid": currentSsid, "bssids": currentBssids})
                currentBssids = []
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                currentSsid = parts[1].strip()
            else:
                currentSsid = "Unknown"
        elif line.startswith("BSSID "):
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                bssid = parts[1].strip()
                currentBssids.append(bssid)
    if currentSsid is not None:
        networks.append({"ssid": currentSsid, "bssids": currentBssids})
    return networks

# ---------------- KV Layout ----------------
kv = '''
ScreenManager:
    WiFiConfigScreen:
    MainScreen:
    UpdateTrustedScreen:
    NotificationDetailScreen:

<WiFiConfigScreen>:
    name: "wifi_config"
    MDBoxLayout:
        orientation: "vertical"
        padding: "16dp"
        spacing: "16dp"
        MDLabel:
            text: "Wi‑Fi Configuration"
            halign: "center"
            font_style: "H5"
        Spinner:
            id: network_spinner
            text: "Select Network"
            values: root.available_networks
            size_hint_y: None
            height: "48dp"
        MDTextField:
            id: password_input
            hint_text: "Enter Password"
            password: True
            size_hint_y: None
            height: "48dp"
        MDRaisedButton:
            text: "Configure Wi‑Fi"
            on_release: root.configure_wifi()
        MDLabel:
            id: wifi_status
            text: root.status_message
            halign: "center"
            theme_text_color: "Error"

<MainScreen>:
    name: "main"
    MDBoxLayout:
        orientation: "vertical"
        padding: "16dp"
        spacing: "16dp"
        MDLabel:
            text: "Main Screen - Notifications"
            halign: "center"
            font_style: "H5"
            size_hint_y: None
            height: "48dp"
        MDLabel:
            id: assessment_progress
            text: ""
            halign: "center"
            font_style: "Subtitle1"
            size_hint_y: None
            height: "32dp"
        ScrollView:
            MDList:
                id: notification_list
        MDBoxLayout:
            orientation: "horizontal"
            spacing: "8dp"
            size_hint_y: None
            height: "48dp"
            MDRaisedButton:
                text: "Trigger Password Assessment"
                on_release: root.trigger_assessment("password")
                size_hint_x: 0.5
            MDRaisedButton:
                text: "Trigger Protocol Assessment"
                on_release: root.trigger_assessment("protocol")
                size_hint_x: 0.5
        MDBoxLayout:
            orientation: "horizontal"
            spacing: "8dp"
            size_hint_y: None
            height: "48dp"
            MDRaisedButton:
                text: "Update Trusted Networks"
                on_release: root.go_to_screen("update_trusted")
                size_hint_x: 0.5
            MDRaisedButton:
                id: block_button
                text: "Block Rogue AP"
                on_release: root.block_rogue_ap()
                size_hint_x: 0.5
                opacity: 0
                disabled: True

<UpdateTrustedScreen>:
    name: "update_trusted"
    MDBoxLayout:
        orientation: "vertical"
        padding: "16dp"
        spacing: "16dp"
        MDLabel:
            text: "Update Trusted Networks"
            halign: "center"
            font_style: "H5"
        ScrollView:
            MDBoxLayout:
                id: networks_grid
                orientation: "vertical"
                size_hint_y: None
                height: self.minimum_height
                spacing: "8dp"
        MDRaisedButton:
            text: "Submit Trusted Networks"
            on_release: root.submit_trusted()
        MDRaisedButton:
            text: "Back"
            on_release: root.go_back()

<NotificationDetailScreen>:
    name: "notification_detail"
    MDBoxLayout:
        orientation: "vertical"
        padding: "16dp"
        spacing: "16dp"
        MDLabel:
            id: notification_detail_label
            text: root.detail_text
            halign: "left"
            font_style: "Body1"
            markup: True
        MDLabel:
            id: disclaimer_label
            text: ""
            halign: "center"
            font_style: "Subtitle1"
            theme_text_color: "Secondary"
            opacity: 0
            size_hint_y: None
            height: "48dp"
            markup: True
        MDRaisedButton:
            id: detail_block_button
            text: "Block Rogue AP"
            on_release: root.block_rogue_ap()
            opacity: 0
            disabled: True
            size_hint_y: None
            height: "48dp"
        MDRaisedButton:
            text: "Back"
            on_release: root.go_back()
'''

# ---------------- Screen Classes ----------------
class WiFiConfigScreen(Screen):
    """Screen to configure Wi‑Fi: scans available networks and sends credentials to the Pi via REST API."""
    available_networks = ListProperty([])
    status_message = StringProperty("")

    def on_enter(self):
        nets = GetAvailableNetworks()
        ssidDict = {}
        for net in nets:
            ssid = net["ssid"]
            bssids = net["bssids"]
            if ssid in ssidDict:
                ssidDict[ssid] = list(set(ssidDict[ssid] + bssids))
            else:
                ssidDict[ssid] = bssids
        self.networks_info = ssidDict
        self.available_networks = list(ssidDict.keys())
        self.status_message = "Networks updated."

    def configure_wifi(self):
        network = self.ids.network_spinner.text
        password = self.ids.password_input.text.strip()
        if network == "Select Network" or not password:
            self.status_message = "Please select a network and enter a password."
            return
        payload = {"ssid": network, "password": password}
        try:
            response = requests.post(REST_API_URL, json=payload, verify=False, timeout=90)
            data = response.json()
            self.status_message = "Success: " + data.get("message", "Wi‑Fi configured.")
            
            # Extract the new IP address from the response
            if data.get("wlan0_ip"):
                # Remove the subnet mask if present (e.g., "192.168.1.100/24")
                new_ip = data["wlan0_ip"].split("/")[0]
                print("Received new wlan0 IP:", new_ip)
                
                # Update the MQTT broker address in memory (but don't reconnect yet)
                global MQTT_BROKER
                MQTT_BROKER = new_ip
                
                # Wait 5 seconds before switching networks (stability period)
                print("Waiting 5 seconds before switching networks...")
                time.sleep(5)
                
                try:
                    # Switch Windows to the target Wi-Fi network
                    print(f"Connecting Windows to network: {network}")
                    subprocess.run(
                        ["netsh", "wlan", "connect", f"name={network}", f"ssid={network}"],
                        check=True
                    )
                    
                    # Wait 10 seconds for network association and IP assignment
                    print("Waiting 10 seconds for network connection...")
                    time.sleep(10)
                    
                    # Now reconnect MQTT to the new broker address
                    print("Reconnecting MQTT to new broker...")
                    mqttClient.client.disconnect()
                    time.sleep(1)  # Brief pause for clean disconnect
                    mqttClient.client.connect(MQTT_BROKER, MQTT_PORT, 60)
                    mqttClient.client.loop_start()
                    print("MQTT broker updated to", MQTT_BROKER)
                    
                except Exception as e:
                    print(f"Error during network transition: {e}")
                    self.status_message = f"Network switch error: {str(e)}"
                    return
                
            self.manager.current = "main"
        except Exception as e:
            self.status_message = f"Error: {str(e)}"

class MainScreen(Screen):
    """Main screen that displays notifications and offers controls for assessments and updating trusted networks."""
    alerts_text = StringProperty("")

    def on_enter(self):
        # Auto-refresh notifications every 2 seconds.
        Clock.schedule_interval(self.refresh_notifications, 2)
        # Also check for rogue AP alerts to enable the block button.
        Clock.schedule_interval(self.check_rogue_ap, 2)

    def refresh_notifications(self, dt):
        notificationList = self.ids.notification_list
        if mqttClient.notifications:
            for note in mqttClient.notifications:
                # Create a clickable list item for each notification.
                item = OneLineListItem(
                    text=note["summary"],
                    on_release=lambda inst, details=note["details"]: self.open_notification_detail(details)
                )
                notificationList.add_widget(item)
            mqttClient.notifications = []

    def open_notification_detail(self, details):
        notifScreen = self.manager.get_screen("notification_detail")
        notifScreen.detail_text = details
        # If details contain a rogue AP alert, show disclaimer and enable the block button.
        if "Rogue AP Alert" in details or "rogue_ap" in details.lower():
            notifScreen.ids.disclaimer_label.markup = True
            notifScreen.ids.disclaimer_label.text = (
                "[color=#ff0000]Disclaimer:[/color] Blocking a rogue AP may disconnect legitimate clients. "
                "Proceed only if you are sure."
            )
            notifScreen.ids.disclaimer_label.opacity = 1
            notifScreen.ids.detail_block_button.opacity = 1
            notifScreen.ids.detail_block_button.disabled = False
        else:
            notifScreen.ids.disclaimer_label.text = ""
            notifScreen.ids.disclaimer_label.opacity = 0
            notifScreen.ids.detail_block_button.opacity = 0
            notifScreen.ids.detail_block_button.disabled = True
        self.manager.current = "notification_detail"

    def check_rogue_ap(self, dt):
        # Check displayed notifications for any mention of a Rogue AP.
        if "Rogue AP" in self.alerts_text:
            self.ids.block_button.opacity = 1
            self.ids.block_button.disabled = False
        else:
            self.ids.block_button.opacity = 0
            self.ids.block_button.disabled = True

    def trigger_assessment(self, assessmentType):
        if assessmentType == "protocol":
            self.start_protocol_countdown(180)  # 3-minute countdown for protocol assessment.
        payload = json.dumps({"assessment_type": assessmentType})
        mqttClient.publish(MQTT_CMD_RUN_ASSESSMENT, payload)
        print(f"Triggered {assessmentType} assessment.")

    def start_protocol_countdown(self, seconds):
        self.ids.assessment_progress.text = f"Protocol assessment in progress: {seconds//60:02d}:{seconds%60:02d} remaining"
        def update(dt):
            nonlocal seconds
            seconds -= 1
            if seconds >= 0:
                self.ids.assessment_progress.text = f"Protocol assessment in progress: {seconds//60:02d}:{seconds%60:02d} remaining"
            else:
                self.ids.assessment_progress.text = ""
                return False
        Clock.schedule_interval(update, 1)

    def block_rogue_ap(self):
        # Extract the detected BSSID from the current notification detail using the helper function.
        currentScreen = self.manager.get_screen("notification_detail")
        targetBssid = ExtractBssid(currentScreen.detail_text)
        if not targetBssid:
            targetBssid = "00:11:22:33:44:55"  # Fallback value if extraction fails.
        payload = json.dumps({"target_bssid": targetBssid, "interface": "wlan1", "count": 10})
        mqttClient.publish(MQTT_CMD_BLOCK, payload)
        self.alerts_text += f"\nBlock command sent for rogue AP {targetBssid}.\n"

    def go_to_screen(self, screenName):
        self.manager.current = screenName

class UpdateTrustedScreen(Screen):
    """Screen to update trusted networks; displays available networks and allows selection of network type."""
    def on_enter(self):
        nets = GetAvailableNetworks()
        ssidDict = {}
        for net in nets:
            ssid = net["ssid"]
            bssids = net["bssids"]
            if ssid in ssidDict:
                ssidDict[ssid] = list(set(ssidDict[ssid] + bssids))
            else:
                ssidDict[ssid] = bssids
        grid = self.ids.networks_grid
        grid.clear_widgets()
        for ssid, bssids in ssidDict.items():
            entry = TrustedNetworkEntry(ssid, bssids)
            grid.add_widget(entry)

    def submit_trusted(self):
        trustedPersonal = {}
        trustedPublic = {}
        for child in self.ids.networks_grid.children:
            if hasattr(child, 'checkbox') and child.checkbox.active:
                netType = child.spinner.text.lower()
                if netType == "personal":
                    trustedPersonal[child.Ssid] = child.Bssids
                elif netType == "public":
                    trustedPublic[child.Ssid] = child.Bssids
        payload = json.dumps({"personal": trustedPersonal, "public": trustedPublic})
        mqttClient.publish(MQTT_CMD_UPDATE_TRUSTED, payload)
        self.manager.current = "main"

    def go_back(self):
        self.manager.current = "main"

class NotificationDetailScreen(Screen):
    """Screen to display detailed notification information with an option to block a rogue AP if applicable."""
    detail_text = StringProperty("")

    def block_rogue_ap(self):
        targetBssid = ExtractBssid(self.detail_text)
        if not targetBssid:
            targetBssid = "00:11:22:33:44:55"  # Fallback value
        payload = json.dumps({"target_bssid": targetBssid, "interface": "wlan1", "count": 10})
        mqttClient.publish(MQTT_CMD_BLOCK, payload)
        self.detail_text += f"\nBlock command sent for rogue AP {targetBssid}."

    def go_back(self):
        self.manager.current = "main"

class WiFiSecurityScreenManager(ScreenManager):
    """Custom ScreenManager for the WiFiSecurityApp."""
    pass

class WiFiSecurityApp(MDApp):
    """Main application class for WiFiSecurityApp."""
    def build(self):
        self.theme_cls.primary_palette = "BlueGray"
        self.theme_cls.primary_hue = "800"
        self.theme_cls.theme_style = "Light"
        if hasattr(self.theme_cls, "font_styles"):
            self.theme_cls.font_styles["H5"] = ["Roboto", 48, False, 0.15]
        return Builder.load_string(kv)

# ---------------- Main Execution ----------------
if __name__ == '__main__':
    threading.Thread(target=mqttClient.start, daemon=True).start()
    WiFiSecurityApp().run()
