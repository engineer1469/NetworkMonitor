import subprocess
import platform
from datetime import datetime
from logging import getLogger, INFO, FileHandler, Formatter
import time
import os
import json
import smtplib
from email.mime.text import MIMEText

# Configure logging
logger = getLogger(__name__)
logger.setLevel(INFO)  # Set logging level to INFO

def configure_logging(log_dir):
    """Configure logging with file rotation."""
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    log_file = os.path.join(log_dir, f"network_activity_{datetime.now().strftime('%Y-%m-%d')}.log")
    handler = FileHandler(log_file)
    handler.setFormatter(Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)

def get_current_ssid():
    """Retrieve the current WiFi SSID across different platforms."""
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(["netsh", "wlan", "show", "interfaces"]).decode("utf-8")
            for line in output.splitlines():
                logger.debug(f"Line from netsh output: {line}")
                if "State" in line and "disconnected" in line:
                    logger.warning("Wi-Fi is disconnected")
                    return "UNKNOWN_SSID"
                if "SSID" in line:
                    return line.split(":")[1].strip()
        elif platform.system() == "Darwin":
            output = subprocess.check_output(["/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport", "-I"]).decode("utf-8")
            for line in output.splitlines():
                logger.debug(f"Line from airport output: {line}")
                if " SSID:" in line:
                    return line.split(":")[1].strip()
        elif platform.system() == "Linux":
            output = subprocess.check_output(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"]).decode("utf-8")
            for line in output.splitlines():
                logger.debug(f"Line from nmcli output: {line}")
                if line.startswith("yes:"):
                    return line.split(":")[1]
    except Exception as e:
        logger.warning(f"Failed to get SSID: {e}", exc_info=True)
    return "UNKNOWN_SSID"

def get_subnet():
    """Detect the subnet based on the default gateway, prioritizing IPv4."""
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(["ipconfig"]).decode()
            ipv4_address = None
            for line in output.splitlines():
                logger.debug(f"Line from ipconfig output: {line}")
                if "IPv4 Address" in line or "IPv4-adres" in line:
                    ipv4_address = line.split(':')[-1].strip()
                if "Default Gateway" in line and '.' in line.split(':')[-1].strip():
                    gateway_ip = line.split(':')[-1].strip()
                    if ipv4_address:
                        return '.'.join(ipv4_address.split('.')[:-1]) + '.'
                elif "Default Gateway" in line:
                    gateway_ip = line.split(':')[-1].strip()
                    if not ipv4_address:
                        return gateway_ip  # Handle IPv6 gateway
        elif platform.system() in ["Darwin", "Linux"]:
            output = subprocess.check_output(["ip", "route"]).decode()
            for line in output.splitlines():
                logger.debug(f"Line from ip route output: {line}")
                if "default via" in line and '.' in line.split()[2]:
                    gateway_ip = line.split()[2]
                    return '.'.join(gateway_ip.split('.')[:-1]) + '.'
                elif "default via" in line:
                    gateway_ip = line.split()[2]
                    return gateway_ip  # Handle IPv6 gateway
    except Exception as e:
        logger.warning(f"Failed to get subnet: {e}", exc_info=True)
    return "UNKNOWN_SUBNET"

def scan_network(subnet):
    """Use nmap to scan the network and retrieve MAC addresses, manufacturers, and hostnames."""
    devices = {}
    try:
        output = subprocess.check_output(["nmap", "-sn", f"{subnet}0/24"]).decode()
        current_ip = None
        for line in output.splitlines():
            logger.debug(f"Line from nmap output: {line}")
            if "Nmap scan report for" in line:
                parts = line.split()
                current_ip = parts[-1].strip('()')
                hostname = parts[4] if '(' in line else parts[-1]
            if "MAC Address" in line:
                mac_address = line.split()[2]
                manufacturer = ' '.join(line.split()[3:]).strip('()')
                devices[mac_address] = {"ip": current_ip, "manufacturer": manufacturer, "hostname": hostname}
    except Exception as e:
        logger.warning(f"Failed to scan network: {e}", exc_info=True)
    return devices

def load_nicknames(nicknames_file):
    """Load nicknames from a JSON file."""
    if os.path.exists(nicknames_file):
        with open(nicknames_file, 'r') as file:
            return json.load(file)
    return {}

def get_device_name(mac, nicknames, info):
    """Get device name from nicknames or manufacturer and hostname."""
    if mac in nicknames:
        return nicknames[mac]
    # Enhance identification for iPhones
    if "iPhone" in info['hostname'] and "Apple" in info['manufacturer']:
        return f"{info['hostname']} ({mac}) from Apple"
    return f"{info['hostname']} ({mac}) from {info['manufacturer']}"

def compare_scans(current_devices, previous_devices, ssid, nicknames):
    """Compare current and previous scans, log changes, and update previous devices."""
    for mac, info in current_devices.items():
        device_name = get_device_name(mac, nicknames, info)
        if mac not in previous_devices:
            logger.info(f"New device {device_name} with IP {info['ip']} has joined the network {ssid}")
        elif info['ip'] != previous_devices[mac]['ip']:
            logger.info(f"Device {device_name} changed IP from {previous_devices[mac]['ip']} to {info['ip']} on network {ssid}")
    for mac in list(previous_devices.keys()):
        if mac not in current_devices:
            device_name = get_device_name(mac, nicknames, previous_devices[mac])
            logger.info(f"Device {device_name} has left the network {ssid}")
            del previous_devices[mac]
    return current_devices

def send_notification(subject, message, to_email):
    """Send an email notification."""
    from_email = "your_email@example.com"
    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    try:
        with smtplib.SMTP("smtp.example.com", 587) as server:
            server.starttls()
            server.login(from_email, "your_password")
            server.sendmail(from_email, [to_email], msg.as_string())
    except Exception as e:
        logger.warning(f"Failed to send email: {e}", exc_info=True)

def load_previous_devices(log_dir):
    """Load previous devices from a JSON file."""
    previous_devices_file = os.path.join(log_dir, "previous_devices.json")
    if os.path.exists(previous_devices_file):
        with open(previous_devices_file, 'r') as file:
            return json.load(file)
    return {}

def save_previous_devices(previous_devices, log_dir):
    """Save previous devices to a JSON file."""
    previous_devices_file = os.path.join(log_dir, "previous_devices.json")
    with open(previous_devices_file, 'w') as file:
        json.dump(previous_devices, file)

def run_scan(scan_interval, log_dir, nicknames_file, notification_email=None):
    """Orchestrate network scans, comparisons, and logging."""
    previous_devices = load_previous_devices(log_dir)
    nicknames = load_nicknames(nicknames_file)
    configure_logging(log_dir)

    while True:
        current_subnet = get_subnet()
        current_ssid = get_current_ssid()

        if current_subnet == "UNKNOWN_SUBNET" or current_ssid == "UNKNOWN_SSID":
            logger.warning("Unable to scan network due to unknown SSID or subnet.")
            time.sleep(scan_interval * 60)
            continue

        # Printing the current SSID and subnet being scanned
        print(f"Current SSID: {current_ssid}", flush=True)
        print(f"Scanning on subnet: {current_subnet}", flush=True)

        current_devices = scan_network(current_subnet)
        
        # Printing the network scan results
        print("Network scan results:", current_devices, flush=True)

        previous_devices = compare_scans(current_devices, previous_devices, current_ssid, nicknames)
        
        # Printing the state of previous devices
        print("Previous devices state:", previous_devices, flush=True)

        save_previous_devices(previous_devices, log_dir)

        time.sleep(scan_interval * 60)

if __name__ == "__main__":
    run_scan(0.2, log_dir="logs", nicknames_file="nicknames.json", notification_email="your_notification_email@example.com")
