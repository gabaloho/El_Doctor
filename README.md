# El Doctor - A Monitoring Tool

## Overview

**El Doctor** is a custom monitoring tool designed to collect and display system metrics in real-time. It provides an interactive terminal interface using the `curses` library, allowing users to monitor CPU usage, memory usage, disk usage, and network traffic. The tool also logs metrics to a CSV file and sends email notifications if critical thresholds are exceeded.

## Features

- Real-time monitoring of system metrics.
- Interactive terminal interface using `curses`.
- Logging of metrics to a CSV file.
- Email notifications for critical conditions (high CPU, memory, or disk usage).
- Configurable thresholds for critical conditions.
- Simple exit mechanism by pressing the 'q' key.

## Installation

### Prerequisites

- Python 3.x
- Required Python packages: `psutil`, `smtplib`, `curses`

### Step 1: Install Python and Required Packages

1. **Install Python 3**: Ensure that Python 3 is installed on your system. You can check this by running:

   ```bash
   python3 --version

### Step 3: Run the Script

Run the script using the following command:

```bash
python3 el_doctor.py
