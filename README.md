
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
   ```

### Step 3: Run the Script

Run the script using the following command:

```bash
python3 el_doctor.py
```

## Exiting the Script

To exit the monitoring interface, press the `'q'` key. If the terminal becomes unresponsive, you can reset it by typing `reset` in the terminal.

## Usage

Once the script is running, it will display the following metrics in real-time:

- **Timestamp**: The current date and time.
- **CPU Usage**: The percentage of CPU currently in use.
- **Memory Usage**: The amount of used memory in MB and the total available memory in MB.
- **Disk Usage**: The amount of used disk space in GB and the total disk space in GB.
- **Incoming Traffic**: The total bytes received over the network.
- **Outgoing Traffic**: The total bytes sent over the network.

If any of the monitored metrics exceed the configured critical thresholds, an email notification will be sent to the specified recipient.

## Code Structure

### Main Functions

- `send_email(subject, body)`: Sends an email notification with the specified subject and body.
- `collect_metrics()`: Collects system metrics, including CPU usage, memory usage, disk usage, and network traffic.
- `log_metrics(metrics)`: Logs the collected metrics to a CSV file.
- `check_critical_conditions(metrics)`: Checks if any of the collected metrics exceed the configured critical thresholds and sends an email notification if they do.
- `display_metrics(stdscr)`: Displays the collected metrics in an interactive curses window.

### Configuration Variables

- `EMAIL_ADDRESS`: Your email address for sending notifications.
- `EMAIL_PASSWORD`: Your email password or app password for authentication.
- `TO_EMAIL`: The recipient's email address for notifications.
- `CSV_FILE`: The name of the CSV file where metrics will be logged.
- `CRITICAL_CPU_THRESHOLD`: The CPU usage percentage threshold for sending notifications.
- `CRITICAL_MEMORY_THRESHOLD`: The memory usage percentage threshold for sending notifications.
- `CRITICAL_DISK_THRESHOLD`: The disk usage percentage threshold for sending notifications.

## Conclusion

**El Doctor** is a powerful and customizable monitoring tool that allows users to keep track of their system's performance in real-time. By leveraging Python's `curses` library and the `psutil` package, it provides a user-friendly interface and essential monitoring capabilities.
