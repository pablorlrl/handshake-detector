# Handshake Detector

Handshake Detector is a network monitoring and analysis tool designed to track network connectivity, analyze traffic patterns, and generate visual reports. It helps you understand what your computer is connecting to and identifies potential connectivity issues like latency spikes, IP changes, or packet loss.

## Features

- **Real-time Monitoring**: Tracks public IP, latency, and TTL (Time To Live) to a target server (default: 1.1.1.1).
- **Traffic Analysis**:
    - **Simple Mode (Netstat)**: Snapshots active connections and maps them to processes.
    - **Advanced Mode (Scapy)**: Captures packets to measure traffic volume per destination (requires Admin privileges).
- **Visual Reporting**: Generates detailed PNG reports with latency timelines, histograms, and traffic statistics.
- **GUI Control**: Easy-to-use interface built with Tkinter.

## Prerequisites

- **Python 3.x**
- **Windows** (Primary support, though core logic may work on Linux/macOS with adjustments)

## Installation

1.  Clone the repository or download the source code.
2.  Install the required dependencies using `pip`:

    ```bash
    pip install -r requirements.txt
    ```

    *Note: `scapy` is required for advanced traffic analysis.*

## Usage

1.  Run the main application:

    ```bash
    python main.py
    ```

2.  **Monitoring**:
    - Set the **Duration** (default is 3 seconds for quick testing, adjust as needed).
    - Set the **Interval** (sampling rate).
    - Click **Start Test** to begin monitoring.
    - Click **Stop Test** to end early.
    - Use **Partial Result** or **Full Result** to generate a PNG report of the current session.

3.  **Traffic Analysis**:
    - **Netstat (simple)**: Click to run a sampling of active connections based on the set duration.
    - **Advanced (scapy)**: Click to run packet capture. **Requires running as Administrator.**

## Testing

The project includes a suite of unit tests. To run them:

```bash
python -m unittest discover tests
```

## Considerations

- **Admin Privileges**: The "Advanced (scapy)" traffic analysis mode requires raw socket access, which means you must run the application as an Administrator (Windows) or with `sudo` (Linux).
- **Firewalls**: Ensure your firewall allows the application to send ICMP pings and make HTTP requests to `api.ipify.org` for public IP checks.

## Project Structure

- `main.py`: Entry point and GUI implementation.
- `monitor.py`: Background thread for pinging and IP checking.
- `traffic_analysis.py`: Logic for `netstat` parsing and `scapy` packet sniffing.
- `report.py`: Generates PNG reports using `matplotlib`.
- `utils.py`: Helper functions.
- `tests/`: Unit tests.
