# NetWeaver

A Python-based network packet capture and analysis tool. This project provides real-time packet capture, analysis, and visualization capabilities with an intuitive graphical interface.

## Features
- Real-time network packet capture and analysis
- Support for multiple protocols (TCP, UDP, DNS, ARP)
- Thread-based capture handling for smooth performance
- Packet logging and analysis tools
- User-friendly graphical interface

## Prerequisites
- Python 3.x
- Required Python packages:
  - tkinter (usually comes with Python)
  - scapy
  - pandas
  - threading

## Installation

1. Clone the repository:
```bash
git clone https://github.com/joyceanderson/NetWeaver.git
```

2. Navigate to the project directory:
```bash
cd NetWeaver
```

3. Install required packages:
```bash
pip install scapy pandas
```

## Usage Guide

### Starting the Application
1. Run the main application:
```bash
python main.py
```

### Capturing Packets
1. **Select Network Interface**
   - Choose your network interface from the dropdown menu
   - Common options include 'eth0' for Ethernet or 'wlan0' for WiFi

2. **Start Capture**
   - Click the "Start" button to begin capturing packets
   - The capture will run in a separate thread to maintain UI responsiveness

3. **Stop Capture**
   - Click the "Stop" button to halt packet capture
   - Captured packets will remain in the display for analysis

### Analyzing Packets
1. **Protocol Tabs**
   - Switch between different protocol tabs (TCP, UDP, DNS, ARP) to view specific packet types
   - Each tab provides protocol-specific information and analysis

2. **Packet Details**
   - Click on any packet in the list to view its detailed information
   - Information includes source/destination addresses, ports, payload, and protocol-specific fields

3. **Filtering**
   - Use the filter options to narrow down packet display
   - Filter by protocol, address, port, or other criteria

### Saving and Loading
1. **Save Capture**
   - Click the "Save" button to store captured packets
   - Choose a location and filename for your capture file

2. **Load Previous Capture**
   - Use the "Load" button to open previously saved captures
   - Analyze historical capture data

## Troubleshooting

### Common Issues
1. **Permission Denied**
   - Run the application with sudo/administrator privileges for packet capture
   ```bash
   sudo python main.py
   ```

2. **No Packets Appearing**
   - Verify your network interface selection
   - Check if your system's firewall is blocking packet capture
   - Ensure you have the necessary permissions

3. **Interface Not Found**
   - Make sure you're using the correct interface name for your system
   - Some systems may use different naming conventions (e.g., 'en0' on macOS)

### Need Help?
If you encounter any issues or need assistance:
1. Check the existing [GitHub Issues](https://github.com/joyceanderson/NetWeaver/issues)
2. Create a new issue with detailed information about your problem

## Contributing
Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests.

## License
This project is open source and available under the MIT License.
