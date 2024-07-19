# Network Scanner

## Introduction

Network Scanner is a Python-based tool designed to monitor and log network activity. It provides real-time insights into devices joining or leaving your network, IP changes, and can send notifications for significant events. This tool is perfect for network administrators, security enthusiasts, or anyone interested in keeping track of their home or office network activity.

## Installation

To install and run the Network Scanner, follow these steps:

1. Clone the repository:
   ```
   git clone https://github.com/engineer1469/NetworkMonitor.git
   cd NetworkMonitor
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Ensure you have `nmap` installed on your system. Installation varies by operating system:
   - On Ubuntu/Debian: `sudo apt-get install nmap`
   - On macOS with Homebrew: `brew install nmap`
   - On Windows, download from [nmap.org](https://nmap.org/download.html)

4. Set up your email configuration in the script for notifications (optional).

5. Create a `nicknames.json` file in the root directory to assign friendly names to MAC addresses (optional).

## Features

- Cross-platform support (Windows, macOS, Linux)
- Automatic network subnet detection
- Wi-Fi SSID tracking
- Device tracking by MAC address
- Manufacturer and hostname identification
- IP change detection
- Customizable scan intervals
- Logging with daily rotation
- Email notifications for network changes (optional)
- Nickname support for easy device identification

## Tasks List
- [x] Add automatic subnet detection
- [x] Implement device tracking and change detection
- [x] Add manufacturer and hostname identification
- [x] Implement nickname support
- [ ] Add better fingerprinting of devices(like iPhones)
- [ ] Add a graphical user interface
- [ ] Implement network traffic analysis
- [ ] Add support for custom alerting rules
- [ ] Implement data visualization for network activity


## Usage

Run the script with Python:

```
python network_scanner.py
```

The script will start scanning the network at the specified interval and log any changes it detects.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
