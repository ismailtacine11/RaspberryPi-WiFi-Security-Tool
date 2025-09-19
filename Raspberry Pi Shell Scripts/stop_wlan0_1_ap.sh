#!/bin/bash
# /usr/local/bin/stop_wlan0_1_ap.sh
LOGFILE="/var/log/virtual-ap-stop.log"
exec >> "$LOGFILE" 2>&1
echo "=== Stopping Virtual AP at $(date) ==="

echo "Stopping dnsmasq..."
/bin/systemctl stop dnsmasq

echo "Stopping hostapd..."
/bin/systemctl stop hostapd

echo "Bringing down wlan0_1..."
/sbin/ip link set wlan0_1 down

echo "Deleting wlan0_1..."
/usr/sbin/iw dev wlan0_1 del

echo "AP stopped."
