#!/bin/bash
# /usr/local/bin/set_wlan0_1_ap.sh
LOGFILE="/var/log/virtual-ap-setup.log"
exec >> "$LOGFILE" 2>&1
echo "=== Starting Virtual AP Setup at $(date) ==="
sleep 30

# Remove stale interface
if /usr/sbin/iw dev | grep -q wlan0_1; then
  echo "Deleting existing wlan0_1..."
  /usr/sbin/iw dev wlan0_1 del || { echo "Cannot delete wlan0_1"; exit 1; }
fi

echo "Creating wlan0_1 on wlan0..."
/usr/sbin/iw dev wlan0 interface add wlan0_1 type __ap || { echo "Cannot add wlan0_1"; exit 1; }

echo "Bringing up wlan0_1..."
/sbin/ip link set wlan0_1 up || { echo "Cannot bring up wlan0_1"; exit 1; }

echo "Pre-hostapd IP assign..."
/sbin/ip addr flush dev wlan0_1
/sbin/ip addr add 192.168.4.1/24 dev wlan0_1

echo "Starting hostapd..."
/usr/sbin/hostapd -B /etc/hostapd/hostapd_wlan0_1.conf || { echo "hostapd failed"; exit 1; }

sleep 10
echo "Re-assigning IP after hostapd..."
/sbin/ip addr flush dev wlan0_1
for i in {1..5}; do
  /sbin/ip addr add 192.168.4.1/24 dev wlan0_1 && break
  sleep 2
done

echo "Starting dnsmasq..."
/bin/systemctl start dnsmasq || { echo "dnsmasq failed"; exit 1; }

echo "AP up on wlan0_1 at 192.168.4.1"  
