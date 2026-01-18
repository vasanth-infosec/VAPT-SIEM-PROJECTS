import psycopg2
from psycopg2 import sql
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from flask import Flask, request, jsonify
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime, timedelta
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)

# SocketIO configuration with specific allowed origins
socketio = SocketIO(app, cors_allowed_origins=["http://localhost:63903", "http://127.0.0.1:5000"])

# Enable CORS for all origins, including socket.io
CORS(app, resources={r"/*": {"origins": "*"}})

# Database connection configuration
DB_CONFIG = {
    "dbname": "login_db",  # Replace with your database name
    "user": "postgres",  # Replace with your PostgreSQL username
    "password": "001",  # Replace with your PostgreSQL password
    "host": "127.0.0.1",  # Replace with your PostgreSQL host if not local
    "port": "5432"  # Default PostgreSQL port
}

# Secret key and IV for AES decryption
secret_key = 'vasanthakumar007'
iv = '0000000000000000'


# List of suspicious countries (ISO 3166-1 alpha-2 country codes)
suspicious_countries = [
    "RU", "CN", "UA", "TR", "BR", "KR", "MX", "VN", "PL", "ZA", "AR", "RO",
    "IR", "PK", "BG", "TH", "MY", "ID", "US", "GB", "IL"
]

# Define day and night times (e.g., 6 AM to 6 PM as day, 6 PM to 6 AM as night)
DAY_START_HOUR = 6  # 6 AM
NIGHT_START_HOUR = 18  # 6 PM

# SMTP settings for sending emails
SMTP_SERVER = 'smtp.gmail.com'  # Replace with your SMTP server
SMTP_PORT = 587  # Typically 587 for TLS
SMTP_USER = 'aravind_slcs_intern4@aravind.org'  # Replace with your email address
SMTP_PASSWORD = 'qvys qbmy wspn kxsx'  # Replace with your email password
TO_EMAIL = '22242@slcs.edu.in'  # Replace with the recipient's email address

# Function to send an email notification
def send_email(subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = TO_EMAIL
        msg['Subject'] = subject

        # Attach the body to the email
        msg.attach(MIMEText(body, 'plain'))

        # Setup the SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # Start TLS encryption
        server.login(SMTP_USER, SMTP_PASSWORD)

        # Send the email
        text = msg.as_string()
        server.sendmail(SMTP_USER, TO_EMAIL, text)
        server.quit()
        print(f"Email sent to {TO_EMAIL}")
    except Exception as e:
        print(f"Error sending email: {e}")

# Function to get a connection to the PostgreSQL database
def get_db_connection():
    try:
        conn = psycopg2.connect(
            dbname=DB_CONFIG["dbname"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            host=DB_CONFIG["host"],
            port=DB_CONFIG["port"]
        )
        return conn
    except Exception as e:
        print(f"Error connecting to the database: {e}")
        return None

# Decrypt the encrypted data using AES with CBC mode
def decrypt_data(encrypted_data, secret_key, iv):
    try:
        encrypted_bytes = base64.b64decode(encrypted_data)
        cipher = AES.new(secret_key.encode(), AES.MODE_CBC, iv.encode())
        decrypted_data = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception as e:
        print(f"Error decrypting data: {e}")
        raise

# Function to insert decrypted data into the PostgreSQL database
def insert_telemetry_data(data):
    try:
        conn = get_db_connection()
        if not conn:
            print("Database connection failed!")
            return
        cursor = conn.cursor()

        # Insert into telemetry table
        cursor.execute('''
            INSERT INTO telemet (timestamp, ip, city, region, country, latitude, longitude,
                                 user_agent, os, browser, device_type, viewport_width,
                                 viewport_height, url, referrer, event_type, login_status,
                                 app_name, log_id, network_protocol, status_code, response_message)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            data['timestamp'],
            data['ipInfo'].get('ip', 'Unknown'),
            data['ipInfo'].get('city', 'Unknown'),
            data['ipInfo'].get('region', 'Unknown'),
            data['ipInfo'].get('country', 'Unknown'),
            data['ipInfo'].get('loc', 'Unknown').split(',')[0] if data['ipInfo'].get('loc') else None,
            data['ipInfo'].get('loc', 'Unknown').split(',')[1] if data['ipInfo'].get('loc') else None,
            data['userAgent'],
            data['os'],
            data['browser'],
            data['deviceType'],
            data['viewportWidth'],
            data['viewportHeight'],
            data['url'],
            data['referrer'],
            data['eventType'],
            data['loginStatus'],
            data['app_name'],
            data['log_id'],
            data['network_protocol'],
            data['status_code'],
            data['response_message']
        ))

        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error inserting telemetry data: {e}")

# Modify your security checks to send real-time alerts
def send_realtime_alert(alert_message):
    socketio.emit('new_alert', {'message': alert_message})

# Function to check if an IP is blocked
def is_ip_blocked(ip):
    try:
        conn = get_db_connection()
        if not conn:
            return False
        cursor = conn.cursor()

        # Check if the IP is in the blocked_ips table
        cursor.execute("SELECT ip FROM blocked_ips WHERE ip = %s", (ip,))
        result = cursor.fetchone()

        cursor.close()
        conn.close()

        # If the result is None, the IP is not blocked
        return result is not None
    except Exception as e:
        print(f"Error checking if IP is blocked: {e}")
        return False

# Function to block an IP
def block_ip(ip, reason):
    try:
        conn = get_db_connection()
        if not conn:
            return
        cursor = conn.cursor()

        # Insert the blocked IP into the blocked_ips table with the reason
        cursor.execute("""
            INSERT INTO blocked_ips (ip, reason) VALUES (%s, %s)
        """, (ip, reason))

        conn.commit()
        cursor.close()
        conn.close()

        print(f"IP {ip} blocked for reason: {reason}")
    except Exception as e:
        print(f"Error blocking IP {ip}: {e}")


# Function to check if the IP is from a suspicious country
def check_ip_anonymity(ip):
    try:
        conn = get_db_connection()
        if not conn:
            return "Database connection failed"
        cursor = conn.cursor()

        # Query the database for geolocation information based on the IP
        cursor.execute("""
            SELECT country FROM telemet WHERE ip = %s
        """, (ip,))
        result = cursor.fetchone()

        if not result:
            print(f"No geolocation data found for IP: {ip}")
            return None

        country = result[0]

        if country in suspicious_countries:
            print(f"Suspicious country detected: {country}")
            # Send an email alert for suspicious country
            return f"Suspicious country detected: {country}"
        else:
            print(f"Normal country detected: {country}")
            return None
    except Exception as e:
        print(f"Error checking IP anonymity: {e}")
        return "Error checking IP anonymity"

# Function to check if the request was made during night hours (suspicious activity)
def check_day_to_night_timing(ip_address):
    try:
        conn = get_db_connection()
        if not conn:
            print("Database connection failed!")
            return "Error checking day to night timing"

        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp FROM telemet WHERE ip = %s ORDER BY timestamp DESC LIMIT 1
        """, (ip_address,))

        result = cursor.fetchone()

        if not result:
            print(f"No data found for IP: {ip_address}")
            return None

        timestamp = result[0]
        cursor.close()
        conn.close()

        # If the timestamp is a string, convert it to datetime
        if isinstance(timestamp, str):
            request_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            request_time = timestamp

        hour = request_time.hour
        if hour >= NIGHT_START_HOUR or hour < DAY_START_HOUR:
            print(f"Suspicious activity detected: request made during night hours ({hour}:00).")
            return f"Suspicious activity detected: request made during night hours ({hour}:00)."
        else:
            print(f"Normal activity detected: request made during day hours ({hour}:00).")
            return f"Normal activity detected: request made during day hours ({hour}:00)."
    except Exception as e:
        print(f"Error checking day to night timing for IP {ip_address}: {e}")
        return "Error checking day to night timing"

# Function to check for brute force attempts based on failed login attempts
TIME_WINDOW_MINUTES = 1  # E.g., 5 minutes

# Convert the time window in minutes to timedelta
TIME_WINDOW = timedelta(minutes=TIME_WINDOW_MINUTES)

def get_max_failed_attempts():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Query to fetch the maximum allowed failed login attempts from the config table
        cursor.execute("SELECT value FROM config WHERE parameter = 'max_failed_attempts'")
        max_attempts = cursor.fetchone()[0]
        cursor.close()
        conn.close()

        return max_attempts
    except Exception as e:
        print(f"Error fetching max failed attempts from the database: {e}")
        return 5  # Default to 5 if the database fetch fails

def is_bruteforce(ip_address):
    try:
        # Get the max failed attempts from the database
        max_failed_attempts = get_max_failed_attempts()

        # Calculate the time window (e.g., TIME_WINDOW minutes before now)
        time_limit = datetime.now() - TIME_WINDOW

        conn = get_db_connection()
        cursor = conn.cursor()

        # Query to count failed login attempts from the same IP within the time window
        cursor.execute("""
            SELECT COUNT(*) FROM telemet
            WHERE ip = %s AND login_status = 'failure' AND timestamp > %s
        """, (ip_address, time_limit))

        failed_attempts = cursor.fetchone()[0]
        cursor.close()
        conn.close()

        # If the failed attempts exceed the threshold, it's a brute force attack
        if failed_attempts >= max_failed_attempts:
            print(f"Brute force attempt detected from IP: {ip_address}")
            return True  # Flag as brute force
        return False
    except Exception as e:
        print(f"Error detecting brute force attack: {e}")
        return False

@app.route('/api/send_data', methods=['POST'])
def receive_telemetry():
    try:
        data = request.get_json()
        decrypted_data = decrypt_data(data['encryptedData'], secret_key, iv)
        ip_address = decrypted_data['ipInfo'].get('ip', 'Unknown')

        # Check if the IP is blocked
        if is_ip_blocked(ip_address):
            return jsonify({"status": "error", "message": f"IP {ip_address} is blocked"}), 403

        insert_telemetry_data(decrypted_data)

        detected_issues = []
        if is_bruteforce(ip_address):
            detected_issues.append("Brute force attempt detected")

        suspicious_message = check_ip_anonymity(ip_address)
        if suspicious_message:
            detected_issues.append(suspicious_message)

        night_message = check_day_to_night_timing(ip_address)
        if "Suspicious activity" in night_message:
            detected_issues.append(night_message)

        # If any issues were detected, block the IP and send alerts
        if detected_issues:
            issue_summary = "; ".join(detected_issues)
            send_email("Security Alert Detected", f"Issues detected: {issue_summary}")
            send_realtime_alert(issue_summary)  # Send real-time alert to frontend

            # Block the IP if suspicious activity is detected
            block_ip(ip_address, issue_summary)

            return jsonify({"status": "error", "message": issue_summary}), 403

        return jsonify({"status": "success", "message": "Telemetry data received"}), 200
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
