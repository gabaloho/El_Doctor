import os
import time
import csv
import smtplib
import psutil
import curses
from datetime import datetime

# Configuration
CSV_FILE = 'system_metrics.csv'
EMAIL_ADDRESS = 'youremail@gmail.com'  # Replace with your Gmail 
address
EMAIL_PASSWORD = 'eX AM PLE PASS Wd'  # Use your Gmail app 
passwordpython
TO_EMAIL = "yourExample@duck.com"
CRITICAL_CPU_THRESHOLD = 90  # in percentage
CRITICAL_MEMORY_THRESHOLD = 90  # in percentage
CRITICAL_DISK_THRESHOLD = 90  # in percentage

def send_email(subject, body):
    """Send an email notification."""
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        message = f'Subject: {subject}\n\n{body}'
        server.sendmail(EMAIL_ADDRESS, TO_EMAIL, message)

def collect_metrics():
    """Collect system metrics."""
    cpu_usage = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()

    metrics = {
        'timestamp': datetime.now(),
        'cpu_usage': cpu_usage,
        'used_memory': memory.used / (1024 ** 2),  # Convert to MB
        'total_memory': memory.total / (1024 ** 2),  # Convert to MB
        'used_disk': disk.used / (1024 ** 3),  # Convert to GB
        'total_disk': disk.total / (1024 ** 3),  # Convert to GB
        'incoming_traffic': net_io.bytes_recv,
        'outgoing_traffic': net_io.bytes_sent
    }
    return metrics

def log_metrics(metrics):
    """Log metrics to a CSV file."""
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([metrics['timestamp'], metrics['cpu_usage'], 
metrics['used_memory'],
                         metrics['total_memory'], metrics['used_disk'], 
metrics['total_disk'],
                         metrics['incoming_traffic'], 
metrics['outgoing_traffic']])

def check_critical_conditions(metrics):
    """Check for critical conditions and send notifications."""
    if metrics['cpu_usage'] > CRITICAL_CPU_THRESHOLD:
        send_email("Critical CPU Usage Alert", f"CPU usage is at 
{metrics['cpu_usage']}%")
    if (metrics['used_memory'] / metrics['total_memory'] * 100) > 
CRITICAL_MEMORY_THRESHOLD:
        send_email("Critical Memory Usage Alert", f"Memory usage is at 
{metrics['used_memory']} MB / {metrics['total_memory']} MB")
    if (metrics['used_disk'] / metrics['total_disk'] * 100) > 
CRITICAL_DISK_THRESHOLD:
        send_email("Critical Disk Usage Alert", f"Disk usage is at 
{metrics['used_disk']} GB / {metrics['total_disk']} GB")

def display_metrics(stdscr):
    """Display metrics in a curses window."""
    curses.curs_set(0)  # Hide the cursor
    stdscr.nodelay(1)  # Don't block on input
    stdscr.timeout(1000)  # Refresh every second

    while True:
        stdscr.clear()
        metrics = collect_metrics()
        log_metrics(metrics)
        check_critical_conditions(metrics)

        stdscr.addstr(0, 0, f"Timestamp: {metrics['timestamp']}")
        stdscr.addstr(1, 0, f"CPU Usage: {metrics['cpu_usage']}%")
        stdscr.addstr(2, 0, f"Memory Usage: {metrics['used_memory']} MB / 
{metrics['total_memory']} MB")
        stdscr.addstr(3, 0, f"Disk Usage: {metrics['used_disk']} GB / 
{metrics['total_disk']} GB")
        stdscr.addstr(4, 0, f"Incoming Traffic: 
{metrics['incoming_traffic']} bytes")
        stdscr.addstr(5, 0, f"Outgoing Traffic: 
{metrics['outgoing_traffic']} bytes")
        stdscr.refresh()

        if stdscr.getch() == ord('q'):  # Press 'q' to exit
            break

if __name__ == "__main__":
    curses.wrapper(display_metrics)

