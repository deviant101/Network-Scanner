# Network Scanner

## Overview

The Network Scanner is a Python-based network reconnaissance tool that implements various scanning techniques for network discovery and analysis. This tool uses the Scapy library to perform different types of network probes and scans. The application also includes a graphical user interface (GUI) built with Tkinter.

## Prerequisites

- Python 3.x
- Scapy library
- Tkinter library (usually included with Python)
- Root/Administrator privileges
- Linux/Unix system (recommended)

## Features

- **Host Discovery**
  - ICMP Ping
  - TCP ACK Ping
  - SCTP Init Ping
  - ICMP Timestamp Ping
  - ICMP Address Mask Ping
  - ARP Ping
  - Find MAC Address

- **OS Discovery**
  - OS Detection (based on TTL)

- **Port Scanning**
  - TCP Connect Scan
  - UDP Scan
  - TCP Null Scan
  - TCP FIN Scan
  - Xmas Scan
  - TCP ACK Scan
  - TCP Window Scan
  - TCP Maimon Scan
  - IP Protocol Scan

## Installation

1. **Clone the repository:**

   ```sh
   git clone https://github.com/deviant101/Network-Scanner.git
   cd Network-Scanner
   ```

2. **Create a virtual environment:**

   ```sh
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install the required libraries:**

   ```sh
   pip install -r requirements.txt
   ```

   If you don't have a `requirements.txt` file, create one with the following content:

   ```text
   scapy
   ```

   Tkinter is usually included with Python, but if it's not installed, you can install it using your package manager. For example, on Ubuntu, you can run:

   ```sh
   sudo apt install python3-tk
   ```

## Usage

1. **Run the GUI application:**

   ```sh
   sudo python3 network_scanner_gui.py
   ```

   Note: Running the application with `sudo` is necessary to perform raw socket operations required by Scapy.

2. **Using the GUI:**

   - **Host:** Enter the target host IP address.
   - **Port (optional):** Enter the port number if performing port scanning.
   - **Scan Category:** Select the scan category (Host Discovery, OS Discovery, Port Scanning).
   - **Scan Methods:** Select the specific scan method based on the chosen category.
   - **Scan Button:** Click the "Scan" button to perform the selected scan.

## Project Structure

## Project Structure

```
network_scanner/
├── network_scanner.py          # Contains the implementation of various network scanning functions using Scapy.
├── network_scanner_gui.py      # Contains the implementation of the GUI using Tkinter.
├── README.md                   # Project documentation.
├── requirements.txt            # List of dependencies.
└── LICENSE                     # License information.
```


## Functions

### network_scanner.py

- `icmp_ping(host: str) -> Optional[IP]`: Send ICMP echo request to host.
- `tcp_ack_ping(host, port=80)`: Send TCP ACK packet to host.
- `sctp_init_ping(host, port=80)`: Send SCTP INIT packet to host.
- `icmp_timestamp_ping(host)`: Send ICMP timestamp request to host.
- `icmp_address_mask_ping(host)`: Send ICMP address mask request to host.
- `arp_ping(host)`: Send ARP request to host.
- `get_mac_address(host)`: Get MAC address of the host.
- `os_detection(host)`: Detect OS based on TTL value.
- `tcp_connect_scan(host, port)`: Perform TCP connect scan on the specified port.
- `udp_scan(host, port)`: Perform UDP scan on the specified port.
- `tcp_null_scan(host, port)`: Perform TCP null scan on the specified port.
- `tcp_fin_scan(host, port)`: Perform TCP FIN scan on the specified port.
- `xmas_scan(host, port)`: Perform Xmas scan on the specified port.
- `tcp_ack_scan(host, port)`: Perform TCP ACK scan on the specified port.
- `tcp_window_scan(host, port)`: Perform TCP window scan on the specified port.
- `tcp_maimon_scan(host, port)`: Perform TCP Maimon scan on the specified port.
- `ip_protocol_scan(host)`: Perform IP protocol scan on the host.

### network_scanner_gui.py

- `perform_scan(scan_type, host, port=None)`: Perform the selected scan based on the scan type, host, and port.
- `create_gui()`: Create and run the GUI application.

## Security Considerations
- Legal Implications: Only scan networks you have permission to test
- Network Impact: Scanning can generate significant traffic
- Detection Risk: Some scanning methods may trigger IDS/IPS systems

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Scapy](https://scapy.net/) - The Python library used for network packet manipulation.
- [Tkinter](https://docs.python.org/3/library/tkinter.html) - The standard GUI toolkit for Python.