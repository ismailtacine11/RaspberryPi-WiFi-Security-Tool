#!/bin/bash
# set_wlan1_monitor.sh
# This script disables interfering services, sets wlan1 to monitor mode,
# and then restarts the interfering services.
#
# Note: Restarting the services may cause wlan1 to be re-managed on some systems.
# In that case, consider configuring NetworkManager to ignore wlan1.

echo "Disabling interfering services..."
# Kill processes that might interfere with monitor mode
sudo airmon-ng check kill

echo "Setting wlan1 to monitor mode..."
sudo airmon-ng start wlan1

# Optional: Wait a moment for monitor mode to take effect
sleep 2

echo "Restarting interfering services..."
# Restart network management for managed interfaces (e.g., wlan0)
sudo systemctl restart NetworkManager
sudo systemctl restart wpa_supplicant

echo "Done. Please verify monitor mode on wlan1 with: iwconfig wlan1"

