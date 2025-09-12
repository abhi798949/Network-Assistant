#!/usr/bin/env python3
# flask_code2.py
# Full Flask app with per-device folders for running/backups/current/golden and generate_config_only route
# Enhanced with better XR device handling and pattern detection fixes
# Added Golden Config feature - mark backups as golden and dedicated golden restore
# Authentication: Flask-Login integration (login/logout and protected routes)

# Requirements (create requirements.txt):
# Flask
# flask-login
# netmiko
# PyYAML
# paramiko
# schedule
# Install with: pip install Flask flask-login netmiko PyYAML paramiko schedule

import os
import psutil
import re
import json
import logging
import threading
import schedule
import time as t
import difflib
import shutil
from difflib import unified_diff
from datetime import datetime, timezone
import zipfile
import tempfile
import subprocess
from flask import make_response
import yaml
import paramiko
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from netmiko import ConnectHandler, exceptions
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from ping3 import ping
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import threading
from datetime import datetime, timezone

# Local parser utilities (must exist in utils/)
from utils.cohere_parser import get_action_from_prompt, extract_config_commands

# ---------------------------
# App & config
# ---------------------------
app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # CHANGE for prod: os.urandom(24).hex()

INFLUX_CONFIG = {
    'url': 'http://localhost:8086',
    'token': '4gI-2t-1FOYtW9n1iNT8eSj-iPkU1kLFJ8B0s6yzShaJEl0VEJk8VDFY-kY4LAfaN7mFjRO057tU5ODxji2PKw==',  # Change this
    'org': 'Vayu',
    'bucket': 'Vayu'
}
# Initialize InfluxDB client
try:
    influx_client = InfluxDBClient(
        url=INFLUX_CONFIG['url'],
        token=INFLUX_CONFIG['token'],
        org=INFLUX_CONFIG['org']
    )
    write_api = influx_client.write_api(write_options=SYNCHRONOUS)
    logging.info("InfluxDB client initialized successfully")
except Exception as e:
    logging.error(f"Failed to initialize InfluxDB client: {e}")
    influx_client = None
    write_api = None


# Flask-Login setup (app must exist before init)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"   # redirect to /login if not logged in

# Simple user store (replace with DB/hashes in production)
USERS = {
    "vayu": "Vayu@123!",
    "admin": "WWTwwt1!"
}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in USERS:
        return User(user_id)
    return None

# ---------------------------
# Base directories (per-device structure)
# ---------------------------
RUNNING_ROOT = "running_configs"   # running_configs/<device>/<date>/<files>
BACKUP_ROOT = "backups"            # backups/<device>/<files>
CURRENT_ROOT = "current_configs"   # current_configs/<device>/<files>
UPLOAD_FOLDER = "uploads"
GOLDEN_ROOT = "golden_configs"     # golden_configs/<device>/<files>

# Ensure base dirs exist
for d in (RUNNING_ROOT, BACKUP_ROOT, CURRENT_ROOT, UPLOAD_FOLDER, GOLDEN_ROOT):
    os.makedirs(d, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB



# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler(), logging.FileHandler('app.log')]
)

# ---------------------------
# Load devices
# ---------------------------
def load_devices():
    try:
        with open("devices.yaml") as f:
            data = yaml.safe_load(f)
            if not data or "devices" not in data:
                logging.warning("devices.yaml is missing 'devices' key.")
                return []
            return data["devices"]
    except FileNotFoundError:
        logging.warning("devices.yaml not found. Please create it.")
        return []
    except yaml.YAMLError as e:
        logging.error(f"YAML error loading devices.yaml: {e}")
        return []
    except Exception as e:
        logging.error(f"Error loading devices.yaml: {e}")
        return []

devices = load_devices()
# device_map maps label like "Name (IP)" -> device dict
device_map = {f"{d['name']} ({d['ip']})": d for d in devices}
device_labels = list(device_map.keys())

# ---------------------------
# Helpers
# ---------------------------
def timestamp_now(fmt="%Y%m%d_%H%M"):
    return datetime.now().strftime(fmt)

def safe_device_folder(root, device_name):
    """
    Create and return path to device-specific folder under given root.
    """
    folder = os.path.join(root, device_name)
    os.makedirs(folder, exist_ok=True)
    return folder

def get_conn_params(info):
    try:
        params = {
            "device_type": info["device_type"],
            "host": info["ip"],
            "username": info["username"],
            "password": info["password"],
            "timeout": info.get("timeout", 15),  # Increased timeout
            "session_timeout": info.get("session_timeout", 60),  # Increased session timeout
        }
        if "port" in info:
            params["port"] = info["port"]
        if "key_file" in info and info["key_file"]:
            params["key_file"] = info["key_file"]
            
        # Add specific parameters for XR devices to handle pattern detection
        if info["device_type"].lower() in ["cisco_xr", "cisco_ios_xr"]:
            params["conn_timeout"] = 20
            params["timeout"] = 30  # This is the read timeout for commands
            params["session_timeout"] = 90  # Longer session timeout for XR
            params["fast_cli"] = False  # Disable fast CLI for XR to avoid timing issues
            # Add global delay factor for XR devices
            params["global_delay_factor"] = 2
        return params
    except KeyError as e:
        logging.error(f"Missing device info key: {e}")
        raise
# Metric Collection

def write_device_metrics(device_label, metrics_data):
    """
    Write device metrics to InfluxDB
    """
    if not write_api:
        logging.warning("InfluxDB write API not available")
        return
    
    try:
        device_info = device_map.get(device_label, {})
        device_name = device_info.get('name', device_label.split('(')[0].strip())
        device_ip = device_info.get('ip', 'unknown')
        
        # Create point for device metrics
        point = Point("device_health") \
            .tag("device_name", device_name) \
            .tag("device_label", device_label) \
            .tag("device_ip", device_ip) \
            .tag("device_type", device_info.get('device_type', 'unknown')) \
            .time(datetime.now(timezone.utc))
        
        # Add metrics fields
        if metrics_data.get('cpu') is not None:
            point = point.field("cpu_usage", float(metrics_data['cpu']))
        
        if metrics_data.get('memory') is not None:
            point = point.field("memory_usage", float(metrics_data['memory']))
        
        # Add status as numeric field for easier querying
        status_mapping = {
            'healthy': 0,
            'high_cpu': 1,
            'high_memory': 2,
            'timeout': 3,
            'auth_failed': 4,
            'unreachable': 5
        }
        point = point.field("status_code", status_mapping.get(metrics_data.get('status'), 5))
        point = point.field("status", metrics_data.get('status', 'unknown'))
        
        # Connectivity status
        point = point.field("reachable", 1 if metrics_data.get('status') not in ['timeout', 'unreachable'] else 0)
        
        write_api.write(bucket=INFLUX_CONFIG['bucket'], org=INFLUX_CONFIG['org'], record=point)
        
    except Exception as e:
        logging.error(f"Failed to write metrics to InfluxDB for {device_label}: {e}")

def write_backup_event(device_label, event_type, success, message=""):
    """
    Write backup/restore events to InfluxDB
    """
    if not write_api:
        return
        
    try:
        device_info = device_map.get(device_label, {})
        device_name = device_info.get('name', device_label.split('(')[0].strip())
        
        point = Point("backup_events") \
            .tag("device_name", device_name) \
            .tag("device_label", device_label) \
            .tag("event_type", event_type) \
            .field("success", 1 if success else 0) \
            .field("message", message) \
            .time(datetime.now(timezone.utc))
        
        write_api.write(bucket=INFLUX_CONFIG['bucket'], org=INFLUX_CONFIG['org'], record=point)
        
    except Exception as e:
        logging.error(f"Failed to write backup event to InfluxDB: {e}")

def write_config_change_event(device_label, commands_count, success, diff_lines=0):
    """
    Write configuration change events to InfluxDB
    """
    if not write_api:
        return
        
    try:
        device_info = device_map.get(device_label, {})
        device_name = device_info.get('name', device_label.split('(')[0].strip())
        
        point = Point("config_changes") \
            .tag("device_name", device_name) \
            .tag("device_label", device_label) \
            .field("commands_count", commands_count) \
            .field("success", 1 if success else 0) \
            .field("diff_lines", diff_lines) \
            .time(datetime.now(timezone.utc))
        
        write_api.write(bucket=INFLUX_CONFIG['bucket'], org=INFLUX_CONFIG['org'], record=point)
        
    except Exception as e:
        logging.error(f"Failed to write config change event to InfluxDB: {e}")

# ---------------------------
# Enhanced XR-aware config functions
# ---------------------------
def save_config_for_comparison(conn, device_name, prefix="snap"):
    """
    Save current running config into RUNNING_ROOT/<device>/<date>/<prefix_device_timestamp>.cfg
    Return the config text (string).
    """
    try:
        dev_type = getattr(conn, 'device_type', '').lower()
        if "juniper" in dev_type:
            out = conn.send_command("show configuration | display-set", read_timeout=60)
        elif "xr" in dev_type:
            # Use longer timeout for XR devices
            out = conn.send_command("show running-config", read_timeout=60)
        else:
            out = conn.send_command("show running-config", read_timeout=30)
    except Exception as e:
        logging.error(f"Failed to retrieve config for {device_name}: {e}")
        return ""

    date_folder = datetime.now().strftime("%Y%m%d")
    device_folder = os.path.join(RUNNING_ROOT, device_name, date_folder)
    os.makedirs(device_folder, exist_ok=True)
    fname = os.path.join(device_folder, f"{prefix}_{device_name}_{timestamp_now()}.cfg")
    try:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(out)
    except Exception as e:
        logging.error(f"Failed to write running config file {fname}: {e}")
    return out

def backup_device_config(device_name, device_info):
    """
    Retrieve running-config and save to backups/<device_name>/running_<timestamp>.cfg
    Also save a copy under current_configs/<device_name>/current_<timestamp>.cfg
    Returns the backup absolute path.
    """
    device_type = device_info.get("device_type", "").lower()
    
    if "juniper" in device_type:
        commands = ["show configuration | display-set"]
        cmd_kwargs = {"read_timeout": 60}
    elif "xr" in device_type:
        commands = ["show running-config"]
        cmd_kwargs = {"delay_factor": 4, "read_timeout": 120}
    else:
        commands = ["show running-config"]
        cmd_kwargs = {"read_timeout": 30}

    output = ""
    last_err = None
    try:
        with ConnectHandler(**get_conn_params(device_info)) as conn:
            if "juniper" not in device_type and "xr" not in device_type:
                try:
                    conn.enable()
                except Exception:
                    pass
            
            for cmd in commands:
                try:
                    output = conn.send_command(cmd, **cmd_kwargs)
                    if output and len(output.strip()) > 10 and "error" not in output.lower():
                        break
                except Exception as e:
                    last_err = e
                    continue
                    
            if not output or len(output.strip()) < 10:
                raise Exception(f"No configuration retrieved. Last error: {last_err}")
                
    except exceptions.NetMikoTimeoutException as e:
        raise Exception(f"Timeout: {e}")
    except exceptions.ConnectionException as e:
        raise Exception(f"Connection failed: {e}")
    except Exception as e:
        raise Exception(f"Backup failed: {e}")

    # Save to backups/<device>/
    device_backup_folder = safe_device_folder(BACKUP_ROOT, device_name)
    fname = f"running_{timestamp_now()}.cfg"
    backup_path = os.path.join(device_backup_folder, fname)
    with open(backup_path, "w", encoding="utf-8") as f:
        f.write(output)

    # Save to current_configs/<device>/
    device_current_folder = safe_device_folder(CURRENT_ROOT, device_name)
    current_fname = f"current_{timestamp_now()}.cfg"
    current_path = os.path.join(device_current_folder, current_fname)
    with open(current_path, "w", encoding="utf-8") as f:
        f.write(output)

    # Attempt remote send (non-fatal)
    try:
        send_to_remote(backup_path, device_name)
    except Exception as e:
        logging.warning(f"Remote send failed: {e}")

    return backup_path

def restore_device_config(device_info, file_info, device_name):
    """
    Restore config using the new restore.py approach for XR devices,
    fallback to original method for non-XR devices.
    """
    # Determine file path based on file_info
    if isinstance(file_info, dict):
        fname = file_info.get('name')
        ftype = file_info.get('type')
        path_field = file_info.get('path', fname)
        if ftype == 'timestamped_backup':
            path = os.path.join(BACKUP_ROOT, device_name, path_field)
        elif ftype == 'current_config':
            path = os.path.join(CURRENT_ROOT, device_name, path_field)
        elif ftype == 'golden_config':
            path = os.path.join(GOLDEN_ROOT, device_name, path_field)
        else:
            path = os.path.join(BACKUP_ROOT, device_name, path_field)
    else:
        fname = file_info
        path = None
        for base in (BACKUP_ROOT, CURRENT_ROOT, GOLDEN_ROOT):
            candidate = os.path.join(base, device_name, fname)
            if os.path.exists(candidate):
                path = candidate
                break
        if not path:
            raise Exception(f"File {fname} not found for device {device_name}")

    if not os.path.exists(path):
        raise Exception(f"Restore file does not exist: {path}")

    device_type = device_info.get("device_type", "").lower()
    
    # Use new XR restore method for XR devices
    if "xr" in device_type:
        return restore_xr_device_config(device_info, path, fname)
    else:
        # Use original method for non-XR devices
        return restore_non_xr_device_config(device_info, path, fname)

def restore_xr_device_config(device_info, config_file_path, filename):
    """
    Restore XR device configuration using the new restore.py method
    """
    # Import the restore function
    from restore import xr_restore_config
    
    try:
        # Extract connection parameters
        host = device_info.get("ip")
        username = device_info.get("username")
        password = device_info.get("password")
        port = device_info.get("port", 22)
        
        # Use file method with SCP transfer and commit replace for full restore
        result = xr_restore_config(
            host=host,
            username=username,
            password=password,
            port=port,
            method="file",
            local_file=config_file_path,
            remote_filename=f"restore_{timestamp_now()}.cfg",
            file_system="disk0:",
            replace=True,  # Use commit replace for full configuration replacement
            commit_comment=f"Restored from {filename}",
            fast_cli=False  # More reliable for XR devices
        )
        
        if result.get("ok"):
            logging.info(f"XR restore successful for {device_info.get('name')}: {result.get('log')}")
            return f"Successfully restored {filename} to {device_info.get('name')} using XR native method"
        else:
            raise Exception(f"XR restore failed: {result.get('log', 'Unknown error')}")
            
    except Exception as e:
        logging.error(f"XR restore failed: {e}")
        raise Exception(f"XR restore failed: {str(e)}")

def restore_non_xr_device_config(device_info, config_file_path, filename):
    """
    Restore configuration for non-XR devices using the original method
    """
    # Read and parse the config file
    with open(config_file_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    
    lines = content.splitlines()
    device_type = device_info.get("device_type", "").lower()
    
    # Filter commands based on device type
    commands = []
    
    if "juniper" in device_type:
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and (line.startswith('set ') or line.startswith('delete ')):
                commands.append(line)
    else:
        # Standard IOS filtering
        skip_patterns = [
            'building configuration',
            'current configuration',
            'last configuration change',
            'version ',
            'end',
            'exit'
        ]
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith('!') or line.startswith('#'):
                continue
            
            skip_line = False
            for pattern in skip_patterns:
                if line.lower().startswith(pattern.lower()):
                    skip_line = True
                    break
            
            if not skip_line:
                if (len(line.split()) >= 3 and 
                    any(month in line for month in ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
                                                   'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])):
                    skip_line = True
                elif re.search(r'\d{2}:\d{2}:\d{2}', line):
                    skip_line = True
            
            if not skip_line:
                commands.append(line)

    if not commands:
        raise Exception(f"No valid configuration commands found in {filename}")

    logging.info(f"Restoring {len(commands)} commands to {device_info.get('name')}")
    
    try:
        conn_params = get_conn_params(device_info)
        with ConnectHandler(**conn_params) as conn:
            if "juniper" not in device_type:
                try:
                    conn.enable()
                except Exception as enable_err:
                    logging.warning(f"Enable command failed: {enable_err}")
            
            if "juniper" in device_type:
                try:
                    conn.send_config_set(commands)
                    conn.send_command("commit")
                    return f"Restored {filename} to {device_info.get('name')} ({len(commands)} commands applied)"
                except Exception as juniper_err:
                    raise Exception(f"Juniper configuration failed: {juniper_err}")
            else:
                try:
                    conn.send_config_set(commands)
                    try:
                        conn.save_config()
                    except Exception as save_err:
                        logging.warning(f"Could not save config: {save_err}")
                    
                    return f"Restored {filename} to {device_info.get('name')} ({len(commands)} commands applied)"
                except Exception as ios_err:
                    raise Exception(f"IOS configuration failed: {ios_err}")
                    
    except exceptions.NetMikoTimeoutException as e:
        raise Exception(f"Timeout during restore: {e}. The device may be busy or the config is too large.")
    except exceptions.NetMikoAuthenticationException as e:
        raise Exception(f"Authentication failed: {e}")
    except exceptions.ConnectionException as e:
        raise Exception(f"Connection failed: {e}")
    except Exception as e:
        raise Exception(f"Restore failed: {e}")


def diff_configs(device_name, device_info):
    """
    Compare live running config with the last saved current config for the device.
    """
    device_type = device_info.get("device_type", "").lower()
    try:
        with ConnectHandler(**get_conn_params(device_info)) as conn:
            if "juniper" not in device_type and "xr" not in device_type:
                try:
                    conn.enable()
                except Exception:
                    pass
                    
            if "juniper" in device_type:
                running = conn.send_command("show configuration | display-set", read_timeout=60).splitlines()
            elif "xr" in device_type:
                running = conn.send_command("show running-config", read_timeout=60).splitlines()
            else:
                running = conn.send_command("show running-config").splitlines()
                
    except exceptions.NetMikoTimeoutException as e:
        raise Exception(f"Timeout retrieving running config - {e}")
    except exceptions.ConnectionException as e:
        raise Exception(f"Connection failed - {e}")
    except Exception as e:
        raise Exception(f"Error retrieving config: {e}")

    # find latest in current_configs/<device>/ 
    current_device_folder = os.path.join(CURRENT_ROOT, device_name)
    saved = None
    if os.path.exists(current_device_folder):
        files = sorted(os.listdir(current_device_folder), reverse=True)
        for f in files:
            if f.endswith(('.cfg', '.txt')):
                with open(os.path.join(current_device_folder, f), "r", encoding="utf-8") as fh:
                    saved = fh.read().splitlines()
                break

    if saved is None:
        return f"No saved current config found for {device_name}"

    diff_list = list(unified_diff(saved, running, fromfile='Saved', tofile='Running', lineterm=''))
    if not diff_list:
        return "✅ No differences found."
    return "\n".join(diff_list)

def perform_backup_for_devices(device_list):
    threads = []
    for label in device_list:
        t = threading.Thread(target=backup_device_thread, args=(label,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

def backup_device_thread(label):
    info = device_map.get(label)
    if not info:
        logging.warning(f"Device mapping not found for {label}")
        return
    try:
        p = backup_device_config(info["name"], info)
        logging.info(f"[Scheduled] backup saved: {p}")
    except Exception as e:
        logging.error(f"[Scheduled] backup failed for {label}: {e}")

# Scheduler background
def run_scheduler():
    while True:
        try:
            schedule.run_pending()
        except Exception as e:
            logging.error(f"Scheduler error: {e}")
        t.sleep(60)

scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
scheduler_thread.start()

# ---------------------------
# Golden Config Functions
# ---------------------------
def mark_as_golden(device_name, backup_filename):
    """
    Copy a backup file to the golden_configs folder for the device.
    Returns the new golden config path.
    """
    # Source path in backups folder
    backup_path = os.path.join(BACKUP_ROOT, device_name, backup_filename)
    
    if not os.path.exists(backup_path):
        raise Exception(f"Backup file not found: {backup_path}")
    
    # Create golden folder for device
    golden_folder = safe_device_folder(GOLDEN_ROOT, device_name)
    
    # Create golden filename with timestamp
    timestamp = timestamp_now()
    golden_filename = f"golden_{device_name}_{timestamp}.cfg"
    golden_path = os.path.join(golden_folder, golden_filename)
    
    # Copy the backup to golden folder
    shutil.copy2(backup_path, golden_path)
    
    logging.info(f"Marked backup {backup_filename} as golden config: {golden_path}")
    return golden_path

# ---------------------------
# Error handlers
# ---------------------------
@app.errorhandler(404)
def not_found_error(error):
    if request.accept_mimetypes.best == 'application/json':
        return jsonify({'error': 'Not found'}), 404
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Page Not Found</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="text-center">
                        <h1 class="display-1">404</h1>
                        <p class="fs-3"><span class="text-danger">Oops!</span> Page not found.</p>
                        <p class="lead">The page you're looking for doesn't exist.</p>
                        <a href="/" class="btn btn-primary">Go Home</a>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''', 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large'}), 413

@app.errorhandler(500)
def internal_error(e):
    logging.error(f"Internal server error: {e}")
    if request.accept_mimetypes.best == 'application/json':
        return jsonify({'error': 'Internal server error'}), 500
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Server Error</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="text-center">
                        <h1 class="display-1">500</h1>
                        <p class="fs-3"><span class="text-danger">Oops!</span> Something went wrong.</p>
                        <p class="lead">We're experiencing some technical difficulties.</p>
                        <a href="/" class="btn btn-primary">Go Home</a>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''', 500

# ---------------------------
# Routes
# ---------------------------

# Note: GET /login handled above; protect other routes with login
@app.route('/generate_config_only', methods=['POST'])
def generate_config_only():
    """
    Generate commands from prompt (preview only) and return JSON list of commands.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        prompt = data.get('prompt', '').strip()
        if not prompt:
            return jsonify({'error': 'No prompt provided'}), 400

        try:
            ai_action = get_action_from_prompt(prompt)
            commands = extract_config_commands(ai_action)
        except Exception as e:
            logging.error(f"AI parse failed: {e}")
            return jsonify({'error': 'Failed to parse commands from prompt'}), 500

        if not commands:
            return jsonify({'error': 'No valid configuration commands found'}), 400

        return jsonify({'success': True, 'commands': commands, 'count': len(commands)})
    except Exception as e:
        logging.error(f"generate_config_only error: {e}")
        return jsonify({'error': f'Failed to generate config: {str(e)}'}), 500

@app.route('/get_backup_files')
def get_backup_files():
    """
    Return list of files for selected device from backups/current/golden folders.
    Supports query param 'mode' with values: 'backup' (backups + current),
    'golden' (golden only), 'all' (all three). Default is 'all'.
    Response: list of {name, path, type, date, can_mark_golden}
    """
    try:
        device_label = request.args.get('device')
        mode = request.args.get('mode', 'all').lower()
        if not device_label or device_label not in device_map:
            return jsonify([])

        info = device_map[device_label]
        device_name = info['name']
        results = []

        # mode = backup => backups + current
        if mode in ('backup', 'all'):
            device_backup_folder = os.path.join(BACKUP_ROOT, device_name)
            if os.path.exists(device_backup_folder):
                for f in sorted(os.listdir(device_backup_folder), reverse=True):
                    if f.lower().endswith(('.cfg', '.txt')):
                        full = os.path.join(device_backup_folder, f)
                        results.append({
                            'name': f,
                            'path': f,
                            'type': 'timestamped_backup',
                            'date': datetime.fromtimestamp(os.path.getmtime(full)).isoformat(),
                            'can_mark_golden': True,  # Backups can be marked as golden
                            'device_name': device_name
                        })

            device_current_folder = os.path.join(CURRENT_ROOT, device_name)
            if os.path.exists(device_current_folder):
                for f in sorted(os.listdir(device_current_folder), reverse=True):
                    if f.lower().endswith(('.cfg', '.txt')):
                        full = os.path.join(device_current_folder, f)
                        results.append({
                            'name': f,
                            'path': f,
                            'type': 'current_config',
                            'date': datetime.fromtimestamp(os.path.getmtime(full)).isoformat(),
                            'can_mark_golden': True,  # Current configs can be marked as golden
                            'device_name': device_name
                        })

        # mode = golden => only golden
        if mode in ('golden', 'all'):
            device_golden_folder = os.path.join(GOLDEN_ROOT, device_name)
            if os.path.exists(device_golden_folder):
                for f in sorted(os.listdir(device_golden_folder), reverse=True):
                    if f.lower().endswith(('.cfg', '.txt')):
                        full = os.path.join(device_golden_folder, f)
                        results.append({
                            'name': f,
                            'path': f,
                            'type': 'golden_config',
                            'date': datetime.fromtimestamp(os.path.getmtime(full)).isoformat(),
                            'can_mark_golden': False,  # Golden configs cannot be marked as golden again
                            'device_name': device_name
                        })

        return jsonify(results)
    except Exception as e:
        logging.error(f"get_backup_files error: {e}")
        return jsonify([])

@app.route('/mark_as_golden', methods=['POST'])
def mark_as_golden_route():
    """
    Mark a backup file as golden config.
    Expects JSON: { device_name: "device", backup_filename: "filename" }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        device_name = data.get('device_name')
        backup_filename = data.get('backup_filename')
        file_type = data.get('file_type', 'timestamped_backup')  # backup, current, etc.
        
        if not device_name or not backup_filename:
            return jsonify({'error': 'Device name and backup filename required'}), 400
        
        # Determine source path based on file type
        if file_type == 'current_config':
            source_path = os.path.join(CURRENT_ROOT, device_name, backup_filename)
        else:  # default to timestamped_backup
            source_path = os.path.join(BACKUP_ROOT, device_name, backup_filename)
        
        if not os.path.exists(source_path):
            return jsonify({'error': 'Source file not found'}), 404
        
        # Create golden folder for device
        golden_folder = safe_device_folder(GOLDEN_ROOT, device_name)
        
        # Create golden filename with timestamp
        timestamp = timestamp_now()
        golden_filename = f"golden_{device_name}_{timestamp}.cfg"
        golden_path = os.path.join(golden_folder, golden_filename)
        
        # Copy the file to golden folder
        shutil.copy2(source_path, golden_path)
        
        logging.info(f"Marked {backup_filename} as golden config: {golden_path}")
        
        return jsonify({
            'success': True, 
            'message': f'Backup marked as golden config: {golden_filename}',
            'golden_filename': golden_filename,
            'golden_path': golden_path
        })
    except Exception as e:
        logging.error(f"mark_as_golden error: {e}")
        return jsonify({'error': f'Failed to mark as golden: {str(e)}'}), 500

@app.route('/execute_command', methods=['POST'])
def execute_command():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        selected_devices = data.get('devices', [])
        prompt = data.get('prompt', '')
        if not selected_devices or not prompt:
            return jsonify({'error': 'Please select devices and enter a prompt'}), 400

        try:
            commands = extract_config_commands(get_action_from_prompt(prompt))
        except Exception as e:
            logging.error(f"Failed to parse commands: {e}")
            return jsonify({'error': 'Failed to parse commands from prompt'}), 400

        if not commands:
            return jsonify({'error': 'No valid commands found in prompt'}), 400

        if commands and all(c.strip().lower().startswith('show') for c in commands):
            return jsonify({'error': 'Only verify is allowed for show commands. Use Verify.'}), 400

        results = {'commands': commands, 'device_results': []}

        for label in selected_devices:
            if label not in device_map:
                results['device_results'].append({'device': label, 'success': False, 'message': 'Device not found'})
                continue
            info = device_map[label]
            device_name = info['name']

            device_result = {'device': label, 'success': False, 'message': '', 'command_outputs': [], 'config_diff': ''}

            try:
                with ConnectHandler(**get_conn_params(info)) as conn:
                    device_type = info.get("device_type", "").lower()
                    
                    if "juniper" not in device_type and "xr" not in device_type:
                        try:
                            conn.enable()
                        except Exception:
                            pass

                    old_cfg = save_config_for_comparison(conn, device_name, prefix="old_running")

                    config_commands = [c for c in commands if not c.strip().lower().startswith('show')]
                    if config_commands:
                        if "xr" in device_type:
                            # Enhanced XR handling
                            try:
                                conn.config_mode()
                                for cmd in config_commands:
                                    conn.send_command_timing(cmd, delay_factor=2)
                                conn.send_command("commit", read_timeout=30)
                                conn.exit_config_mode()
                                device_result['message'] = 'XR Configuration applied and committed successfully'
                            except Exception as xr_err:
                                try:
                                    conn.send_command("abort")
                                    conn.exit_config_mode()
                                except:
                                    pass
                                raise Exception(f"XR config failed: {xr_err}")
                        elif "juniper" in device_type:
                            conn.send_config_set(config_commands)
                            conn.send_command("commit")
                            device_result['message'] = 'Juniper Configuration applied and committed successfully'
                        else:
                            conn.send_config_set(config_commands)
                            device_result['message'] = 'Configuration applied successfully'

                    for cmd in commands:
                        if cmd.strip().lower().startswith('show'):
                            try:
                                timeout = 60 if "xr" in device_type else 30
                                out = conn.send_command(cmd, read_timeout=timeout)
                                device_result['command_outputs'].append({'command': cmd, 'output': out})
                            except Exception as ce:
                                logging.error(f"Show failed on {label}: {ce}")
                                device_result['command_outputs'].append({'command': cmd, 'output': f'Error: {ce}'})

                    new_cfg = save_config_for_comparison(conn, device_name, prefix="new_running")
                    if old_cfg and new_cfg:
                        diff_text = '\n'.join(difflib.unified_diff(old_cfg.splitlines(), new_cfg.splitlines(), fromfile="Before", tofile="After", lineterm=""))
                        device_result['config_diff'] = diff_text if diff_text else "No changes detected."
                    else:
                        device_result['config_diff'] = "Could not generate diff - failed to save configs"

                    device_result['success'] = True

            except Exception as e:
                logging.error(f"Execute failed for {label}: {e}")
                device_result['message'] = f'Error: {str(e)}'

            results['device_results'].append(device_result)

        return jsonify(results)
    except Exception as e:
        logging.error(f"execute_command error: {e}")
        return jsonify({'error': f'Failed to process command: {str(e)}'}), 500
    
@app.route('/verify_command', methods=['POST'])
def verify_command():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        selected_devices = data.get('devices', [])
        prompt = data.get('prompt', '')
        if not selected_devices or not prompt:
            return jsonify({'error': 'Please select devices and enter a prompt'}), 400

        results = {'device_results': []}

        for label in selected_devices:
            if label not in device_map:
                results['device_results'].append({'device': label, 'success': False, 'message': 'Device not found'})
                continue
                
            info = device_map[label]
            device_result = {'device': label, 'success': False, 'message': '', 'command_outputs': [], 'config_diff': ''}

            try:
                # Generate device-specific commands using the enhanced parser
                from utils.cohere_parser import get_action_from_prompt_with_device, extract_config_commands
                ai_response = get_action_from_prompt_with_device(prompt, info)
                commands = extract_config_commands(ai_response)
                
                if not commands:
                    device_result['message'] = 'No valid commands generated from prompt'
                    results['device_results'].append(device_result)
                    continue

                # Store the generated commands in the results for this device
                if 'commands' not in results:
                    results['commands'] = commands  # Use the first device's commands for display
                
                with ConnectHandler(**get_conn_params(info)) as conn:
                    device_type = info.get("device_type", "").lower()
                    
                    if "juniper" not in device_type and "xr" not in device_type:
                        try:
                            conn.enable()
                        except Exception:
                            pass

                    for cmd in commands:
                        try:
                            if cmd.strip().lower().startswith('show'):
                                timeout = 60 if "xr" in device_type else 30
                                out = conn.send_command(cmd, read_timeout=timeout)
                                device_result['command_outputs'].append({'command': cmd, 'output': out})
                            else:
                                device_result['command_outputs'].append({'command': cmd, 'output': 'Command validated (not executed in verify mode)'})
                        except Exception as ce:
                            logging.error(f"Verify command failed on {label}: {ce}")
                            device_result['command_outputs'].append({'command': cmd, 'output': f'Error: {ce}'})

                    device_result['success'] = True
                    device_result['message'] = 'Verification completed successfully'

            except Exception as e:
                logging.error(f"Verify failed for {label}: {e}")
                device_result['message'] = f'Error: {str(e)}'

            results['device_results'].append(device_result)

        return jsonify(results)
    except Exception as e:
        logging.error(f"verify_command error: {e}")
        return jsonify({'error': f'Failed to process verify command: {str(e)}'}), 500

def run_asis_command(device_info, commands, device_name):
    """
    Restore config from a file_info (dict with name/type) or filename string.
    Enhanced with better XR handling.
    """
    device_type = device_info.get("device_type", "").lower()
    print(f"DEBUG: command {commands}")

    if not commands:
        
        raise Exception(f"No valid configuration commands found in {commands}")

    try:
        conn_params = get_conn_params(device_info)
        with ConnectHandler(**conn_params) as conn:
            if "juniper" not in device_type and "xr" not in device_type:
                try:
                    conn.enable()
                except Exception:
                    pass
            
            if commands:
                if "xr" in device_type:
                    try:
                        conn.config_mode()
                        chunk_size = 20  # Process 20 commands at a time
                        for i in range(0, len(commands), chunk_size):
                            chunk = commands[i:i + chunk_size]
                            for cmd in chunk:
                                try:
                                    result = conn.send_command_timing(cmd, delay_factor=2)
                                    if 'error' in result.lower() or 'invalid' in result.lower():
                                        logging.warning(f"Possible error in command '{cmd}': {result}")
                                except Exception as cmd_err:
                                    logging.error(f"Error sending command '{cmd}': {cmd_err}")
                                    continue
                        try:
                            conn.commit()
                        except Exception as commit_err:
                            logging.error(f"Commit failed on XR: {commit_err}")
                            conn.send_command("abort")
                            raise Exception(f"XR configuration failed: {commit_err}")
                        finally:
                            conn.exit_config_mode()
                    except Exception as e:
                        raise Exception(f"XR command execution failed: {e}")

                elif "juniper" in device_type:
                    conn.send_config_set(commands)
                else:
                    conn.send_config_set(commands)
                    
        return f"Executed {len(commands)} commands on {device_name}"

    except NetMikoTimeoutException as e:
        raise Exception(f"Timeout during restore - {e}. Try breaking config into smaller files.")
    except NetMikoAuthenticationException as e:
        raise Exception(f"Authentication failed - {e}")
    except Exception as e:
        raise Exception(f"Connection/config error: {e}")
    
    
    
@app.route('/run_asis_command', methods=['POST'])
def run_asis_command():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        selected_devices = data.get('devices', [])
        prompt = data.get('prompt', '')

        if not selected_devices or not prompt:
            return jsonify({'error': 'Please select devices and enter a prompt'}), 400

        try:
            commands = prompt
            print(f"DEBUG: execute {commands}")
        except Exception as e:
            logging.error(f"Failed to parse commands: {e}")
            return jsonify({'error': 'Failed to parse commands from prompt'}), 400

        if not commands:
            return jsonify({'error': 'No valid commands found in prompt'}), 400

        results = {'commands': commands, 'device_results': []}

        for label in selected_devices:
            if label not in device_map:
                results['device_results'].append({
                    'device': label,
                    'success': False,
                    'message': 'Device not found'
                })
                continue

            info = device_map[label]
            device_result = {
                'device': label,
                'success': False,
                'message': '',
                'command_outputs': [],
                'config_diff': ''
            }

            try:
                with ConnectHandler(**get_conn_params(info)) as conn:
                    device_type = info.get("device_type", "").lower()

                    if "juniper" not in device_type and "xr" not in device_type:
                        try:
                            conn.enable()
                        except Exception:
                            pass

                    if commands:
                        try:
                                timeout = 60 if "xr" in device_type else 30
                                out = conn.send_command(commands, read_timeout=timeout)
                                device_result['command_outputs'].append({
                                    'command': commands,
                                    'output': out
                                })
                        except Exception as ce:
                            logging.error(f"Verify command failed on {label}: {ce}")
                            device_result['command_outputs'].append({
                                'command': commands,
                                'output': f'Error: {ce}'
                            })

                    device_result['success'] = True
                    device_result['message'] = 'Verification completed successfully'

            except Exception as e:
                logging.error(f"Verify failed for {label}: {e}")
                device_result['message'] = f'Error: {str(e)}'

            results['device_results'].append(device_result)

        return jsonify(results)

    except Exception as e:
        logging.error(f"verify_command error: {e}")
        return jsonify({'error': f'Failed to process verify command: {str(e)}'}), 500
#AI explanation

@app.route('/ai/explain', methods=['POST'])
@login_required
def ai_explain():
    try:
        data = request.get_json(silent=True) or {}
        vendor = data.get('vendor')
        from utils.cohere_parser import explain_commands, explain_commands_rich

        # Preferred: contextual (command + output)
        items = data.get('items')
        if isinstance(items, list) and items:
            out = explain_commands_rich(items, vendor)
            return jsonify({"success": True, "explanations": out})

        # Legacy: commands only
        commands = data.get('commands') or []
        out = explain_commands(commands, vendor)
        return jsonify({"success": True, "explanations": out})
    except Exception as e:
        app.logger.exception("ai_explain failed")
        return jsonify({"error": str(e)}), 500

    
@app.route('/backup_devices', methods=['POST'])
def backup_devices_route():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        selected_devices = data.get('devices', [])
        if not selected_devices:
            return jsonify({'error': 'Please select devices to backup'}), 400

        results = []
        for label in selected_devices:
            if label not in device_map:
                results.append({'device': label, 'success': False, 'message': 'Device not found'})
                continue
            info = device_map[label]
            try:
                backup_path = backup_device_config(info['name'], info)
                filename = os.path.basename(backup_path)
                # Return a relative download path usable by frontend
                results.append({'device': label, 'success': True, 'message': 'Backup saved', 'download_path': filename})
            except Exception as e:
                logging.error(f"Backup failed for {label}: {e}")
                results.append({'device': label, 'success': False, 'message': str(e)})
        return jsonify({'results': results})
    except Exception as e:
        logging.error(f"backup_devices error: {e}")
        return jsonify({'error': f'Failed to backup devices: {str(e)}'}), 500

@app.route('/restore_devices', methods=['POST'])
def restore_devices_route():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Get the device and files from request
        device_label = data.get('device')
        selected_files = data.get('files', [])
        
        if not device_label or not selected_files:
            return jsonify({'error': 'Please select a device and backup files'}), 400

        # Validate device exists
        if device_label not in device_map:
            return jsonify({'error': 'Device not found'}), 400
            
        info = device_map[device_label]
        device_name = info['name']

        # Group files by device (in case we want to support multi-device restore later)
        # For now, all files should belong to the same device
        device_files = {}
        for file_obj in selected_files:
            file_device = file_obj.get('device_name', device_name)
            if file_device not in device_files:
                device_files[file_device] = []
            device_files[file_device].append(file_obj)

        results = []
        
        for dev_name, files in device_files.items():
            # Find device info for this device name
            device_info = None
            target_label = None
            for label, info in device_map.items():
                if info['name'] == dev_name:
                    device_info = info
                    target_label = label
                    break
            
            if not device_info:
                results.append({
                    'device': dev_name, 
                    'success': False, 
                    'message': f'Device info not found for {dev_name}'
                })
                continue

            device_result = {
                'device': target_label,
                'success': False,
                'message': '',
                'messages': []
            }
            
            try:
                # Restore each file for this device
                for file_obj in files:
                    try:
                        restore_msg = restore_device_config(device_info, file_obj, dev_name)
                        device_result['messages'].append(restore_msg)
                    except Exception as file_err:
                        error_msg = f"Failed to restore {file_obj.get('name', 'unknown')}: {str(file_err)}"
                        device_result['messages'].append(error_msg)
                        logging.error(f"File restore error: {file_err}")
                
                # Check if any files were successfully restored
                if device_result['messages']:
                    device_result['success'] = True
                    device_result['message'] = f"Restore completed for {len(files)} file(s)"
                else:
                    device_result['message'] = "No files were successfully restored"
                    
            except Exception as e:
                logging.error(f"Device restore failed for {dev_name}: {e}")
                device_result['message'] = f'Device restore failed: {str(e)}'
            
            results.append(device_result)

        return jsonify({'results': results})
        
    except Exception as e:
        logging.error(f"restore_devices error: {e}")
        return jsonify({'error': f'Failed to restore devices: {str(e)}'}), 500
@app.route('/schedule_backup', methods=['POST'])
def schedule_backup_route():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        selected_devices = data.get('devices', [])
        schedule_date = data.get('date', '')
        schedule_time = data.get('time', '')
        if not selected_devices or not schedule_date or not schedule_time:
            return jsonify({'error': 'Please fill all fields'}), 400

        try:
            scheduled_datetime = datetime.strptime(f"{schedule_date} {schedule_time}", "%Y-%m-%d %H:%M")
        except Exception as e:
            logging.error(f"Invalid date/time format: {e}")
            return jsonify({'error': 'Invalid date or time format.'}), 400

        if scheduled_datetime <= datetime.now():
            return jsonify({'error': 'Scheduled time must be in the future'}), 400

        def job(device_list=selected_devices, sched_time=scheduled_datetime):
            now = datetime.now()
            if now >= sched_time:
                logging.info(f"[Scheduled Job Triggered at {now}]")
                perform_backup_for_devices(device_list)
                return schedule.CancelJob

        schedule.every(1).minutes.do(job)

        return jsonify({'success': True, 'message': f'Backup scheduled for {scheduled_datetime.strftime("%Y-%m-%d %I:%M %p")} for selected devices.'})
    except Exception as e:
        logging.error(f"schedule_backup error: {e}")
        return jsonify({'error': f'Failed to schedule backup: {str(e)}'}), 500

# Add a new route for bulk download of all files for a device
@app.route('/download_backup/<device_name>/<path:filename>')
def download_backup_route(device_name, filename):
    try:
        from urllib.parse import unquote
        import atexit
        
        # URL decode the device name
        device_name = unquote(device_name)
        
        # Extract device name from label format "DeviceName (IP)"
        clean_device_name = device_name
        if "(" in device_name and ")" in device_name:
            clean_device_name = device_name.split("(")[0].strip()
        
        # Log for debugging
        logging.info(f"Download request - Device: '{device_name}', Clean: '{clean_device_name}', File: '{filename}'")
        
        # Define search order and folders
        search_folders = [
            (CURRENT_ROOT, "current_configs"),
            (BACKUP_ROOT, "backups"), 
            (GOLDEN_ROOT, "golden_configs")
        ]
        
        found_file_path = None
        found_folder_type = None
        
        for folder_root, folder_name in search_folders:
            folder_path = os.path.join(folder_root, clean_device_name)
            file_path = os.path.join(folder_path, filename)
            
            logging.info(f"Checking: {file_path}")
            
            if os.path.exists(file_path):
                logging.info(f"Found file: {file_path}")
                found_file_path = file_path
                found_folder_type = folder_name
                break
            
            # Also try with original device_name (in case it has special chars)
            original_device_name = unquote(request.view_args['device_name'])
            if original_device_name != clean_device_name:
                alt_folder_path = os.path.join(folder_root, original_device_name)
                alt_file_path = os.path.join(alt_folder_path, filename)
                
                logging.info(f"Checking alternative: {alt_file_path}")
                
                if os.path.exists(alt_file_path):
                    logging.info(f"Found file at alternative path: {alt_file_path}")
                    found_file_path = alt_file_path
                    found_folder_type = folder_name
                    break
        
        if not found_file_path:
            # List available files for debugging
            logging.error(f"File not found. Available folders:")
            for folder_root, folder_name in search_folders:
                base_path = os.path.join(folder_root, clean_device_name)
                if os.path.exists(base_path):
                    files = os.listdir(base_path)
                    logging.error(f"  {folder_name}/{clean_device_name}: {files}")
                else:
                    logging.error(f"  {folder_name}/{clean_device_name}: FOLDER DOES NOT EXIST")
            
            return jsonify({
                'error': 'File not found',
                'device': device_name,
                'filename': filename,
                'searched_paths': [f"{folder_root}/{clean_device_name}/{filename}" for folder_root, _ in search_folders]
            }), 404
        
        # Create a temporary file that will be automatically cleaned up
        temp_zip_fd, temp_zip_path = tempfile.mkstemp(suffix='.zip')
        
        try:
            # Close the file descriptor immediately since we'll open it with zipfile
            os.close(temp_zip_fd)
            
            # Create zip file
            with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Create the folder structure: DeviceName/ConfigType/filename
                archive_path = f"{clean_device_name}/{found_folder_type}/{filename}"
                zipf.write(found_file_path, archive_path)
            
            # Read the zip content
            with open(temp_zip_path, 'rb') as zip_file:
                zip_data = zip_file.read()
            
            # Create response with proper headers
            response = make_response(zip_data)
            response.headers['Content-Type'] = 'application/zip'
            response.headers['Content-Disposition'] = f'attachment; filename="{clean_device_name}_{filename}.zip"'
            
            return response
            
        finally:
            # Clean up temp file in finally block to ensure it gets deleted
            try:
                if os.path.exists(temp_zip_path):
                    os.unlink(temp_zip_path)
            except OSError as e:
                logging.warning(f"Could not delete temp file {temp_zip_path}: {e}")
        
    except Exception as e:
        logging.error(f"Download error for {device_name}/{filename}: {e}")
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

# Also fix the bulk download route with the same pattern
@app.route('/download_device_all/<device_name>')
def download_device_all(device_name):
    """
    Download all backup/current/golden files for a device in organized zip structure
    """
    try:
        from urllib.parse import unquote
        
        device_name = unquote(device_name)
        clean_device_name = device_name
        if "(" in device_name and ")" in device_name:
            clean_device_name = device_name.split("(")[0].strip()
        
        search_folders = [
            (CURRENT_ROOT, "current_configs"),
            (BACKUP_ROOT, "backups"), 
            (GOLDEN_ROOT, "golden_configs")
        ]
        
        # Create a temporary file that will be automatically cleaned up
        temp_zip_fd, temp_zip_path = tempfile.mkstemp(suffix='.zip')
        
        try:
            # Close the file descriptor immediately since we'll open it with zipfile
            os.close(temp_zip_fd)
            
            # Create zip file with all device files organized by type
            with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                file_count = 0
                
                for folder_root, folder_name in search_folders:
                    device_folder = os.path.join(folder_root, clean_device_name)
                    
                    if os.path.exists(device_folder):
                        for filename in os.listdir(device_folder):
                            if filename.lower().endswith(('.cfg', '.txt')):
                                file_path = os.path.join(device_folder, filename)
                                archive_path = f"{clean_device_name}/{folder_name}/{filename}"
                                zipf.write(file_path, archive_path)
                                file_count += 1
                
                if file_count == 0:
                    return jsonify({'error': 'No files found for device'}), 404
            
            # Read the zip content
            with open(temp_zip_path, 'rb') as zip_file:
                zip_data = zip_file.read()
            
            # Create response
            response = make_response(zip_data)
            response.headers['Content-Type'] = 'application/zip'
            response.headers['Content-Disposition'] = f'attachment; filename="{clean_device_name}_all_configs.zip"'
            
            return response
            
        finally:
            # Clean up temp file in finally block to ensure it gets deleted
            try:
                if os.path.exists(temp_zip_path):
                    os.unlink(temp_zip_path)
            except OSError as e:
                logging.warning(f"Could not delete temp file {temp_zip_path}: {e}")
        
    except Exception as e:
        logging.error(f"Bulk download error for {device_name}: {e}")
        return jsonify({'error': f'Bulk download failed: {str(e)}'}), 500

@app.route('/diff_configs', methods=['POST'])
def diff_configs_route():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        selected_devices = data.get('devices', [])
        if not selected_devices:
            return jsonify({'error': 'Please select devices to compare'}), 400

        results = []
        for label in selected_devices:
            if label not in device_map:
                results.append({'device': label, 'success': False, 'message': 'Device not found'})
                continue
            info = device_map[label]
            try:
                d = diff_configs(info['name'], info)
                results.append({'device': label, 'success': True, 'message': 'Diff generated', 'diff': d})
            except Exception as e:
                logging.error(f"diff failed for {label}: {e}")
                results.append({'device': label, 'success': False, 'message': str(e)})
        return jsonify({'results': results})
    except Exception as e:
        logging.error(f"diff_configs error: {e}")
        return jsonify({'error': f'Failed to compare configs: {str(e)}'}), 500

@app.route('/upload_config', methods=['POST'])
def upload_config_endpoint():
    """
    Upload a config file. Form may include:
      - config_file (file)
      - device (optional device label, e.g. 'XR1 (1.2.3.4)')
      - config_type (optional: 'backup'|'golden'|'current') default 'backup'
    """
    try:
        if 'config_file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        file = request.files['config_file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not (file.filename.endswith('.cfg') or file.filename.endswith('.txt')):
            return jsonify({'error': 'Only .cfg and .txt allowed'}), 400

        safe_name = secure_filename(file.filename)
        device_label = request.form.get('device')
        config_type = request.form.get('config_type', 'backup')

        timestamp = timestamp_now("%Y%m%d_%H%M")
        filename = f"uploaded_{timestamp}_{safe_name}"

        if device_label and device_label in device_map:
            device_name = device_map[device_label]['name']
            if config_type == 'golden':
                device_folder = safe_device_folder(GOLDEN_ROOT, device_name)
            elif config_type == 'current':
                device_folder = safe_device_folder(CURRENT_ROOT, device_name)
            else:
                device_folder = safe_device_folder(BACKUP_ROOT, device_name)
            filepath = os.path.join(device_folder, filename)
        else:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

        file.save(filepath)
        return jsonify({'success': True, 'message': f'File uploaded: {filename}', 'path': filepath})
    except Exception as e:
        logging.error(f"upload_config error: {e}")
        return jsonify({'error': f'Failed to upload config: {str(e)}'}), 500

# ---------------------------
# Golden config endpoints
# ---------------------------
@app.route('/save_golden', methods=['POST'])
def save_golden():
    """
    Save a golden config for a device.
    Expects JSON: { device: "<label>", config: "<config text>" }
    device should be the label used in device_map (e.g. "XR1 (1.2.3.4)")
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        device_label = data.get('device')
        config_text = data.get('config', '').strip()
        if not device_label or device_label not in device_map:
            return jsonify({'error': 'Invalid or missing device'}), 400
        if not config_text:
            return jsonify({'error': 'No config provided'}), 400

        device_name = device_map[device_label]['name']
        device_folder = safe_device_folder(GOLDEN_ROOT, device_name)
        golden_path = os.path.join(device_folder, "golden-config.txt")
        with open(golden_path, "w", encoding="utf-8") as fh:
            fh.write(config_text)
        return jsonify({'success': True, 'message': f'Golden config saved for {device_label}', 'path': golden_path})
    except Exception as e:
        logging.error(f"save_golden error: {e}")
        return jsonify({'error': f'Failed to save golden config: {str(e)}'}), 500

@app.route('/get_golden/<device_name>', methods=['GET'])
def get_golden(device_name):
    """
    Return the golden config content for the given device name (not label).
    Note: the front-end can call /get_golden/<device_name> where device_name is the device['name'].
    """
    try:
        golden_path = os.path.join(GOLDEN_ROOT, device_name, "golden-config.txt")
        if not os.path.exists(golden_path):
            return jsonify({'error': 'Golden config not found'}), 404
        with open(golden_path, "r", encoding="utf-8") as fh:
            content = fh.read()
        return jsonify({'success': True, 'config': content})
    except Exception as e:
        logging.error(f"get_golden error: {e}")
        return jsonify({'error': f'Failed to load golden config: {str(e)}'}), 500

# ---------------------------
# Additional XR debugging endpoint
# ---------------------------
@app.route('/test_xr_connection', methods=['POST'])
def test_xr_connection():
    """
    Test XR device connection and provide debugging info.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        device_label = data.get('device')
        if not device_label or device_label not in device_map:
            return jsonify({'error': 'Device not found'}), 400
            
        info = device_map[device_label]
        device_type = info.get("device_type", "").lower()
        
        if "xr" not in device_type:
            return jsonify({'error': 'This endpoint is for XR devices only'}), 400
            
        test_results = {
            'device': device_label,
            'connection_test': False,
            'config_mode_test': False,
            'prompt_detection': '',
            'error_details': []
        }
        
        try:
            conn_params = get_conn_params(info)
            with ConnectHandler(**conn_params) as conn:
                test_results['connection_test'] = True
                test_results['prompt_detection'] = conn.find_prompt()
                
                # Test config mode entry/exit
                try:
                    conn.config_mode()
                    test_results['config_mode_test'] = True
                    conn.exit_config_mode()
                except Exception as config_err:
                    test_results['error_details'].append(f"Config mode test failed: {config_err}")
                    
        except Exception as conn_err:
            test_results['error_details'].append(f"Connection failed: {conn_err}")
            
        return jsonify(test_results)
        
    except Exception as e:
        logging.error(f"test_xr_connection error: {e}")
        return jsonify({'error': f'Test failed: {str(e)}'}), 500

# ---------------------------
# Protect all routes (before_request)
# ---------------------------
@app.before_request
def require_login():
    # Allow login, static files, and a few public endpoints needed by frontend to fetch files
    allowed_routes = [
        "login", "static", "get_backup_files", "download_backup_route", "download_device_all",
        "get_golden"
    ]
    endpoint = request.endpoint or ""
    # Flask endpoints sometimes include blueprint, so compare by start
    if endpoint not in allowed_routes and not current_user.is_authenticated:
        return redirect(url_for("login"))

# ---------------------------
# Example Protected Route (homepage)
# ---------------------------
# Add these routes to your flask_code2.py file, before the require_login function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and USERS[username] == password:
            user = User(username)
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password')
    
    # Create a proper template string that Flask can render
    login_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Network Configuration Manager</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            }
            .login-card {
                background: white;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                overflow: hidden;
                max-width: 400px;
                width: 100%;
            }
            .login-header {
                background: linear-gradient(90deg, #4a90e2, #357abd);
                color: white;
                padding: 20px;
                text-align: center;
            }
            .login-body {
                padding: 30px;
            }
            .logo {
                background: white;
                color: #4a90e2;
                padding: 8px 12px;
                border-radius: 6px;
                font-weight: 700;
                display: inline-block;
                margin-bottom: 10px;
            }
            .btn-primary {
                background: #4a90e2;
                border-color: #4a90e2;
            }
            .btn-primary:hover {
                background: #357abd;
                border-color: #357abd;
            }
        </style>
    </head>
    <body>
        <div class="login-card">
            <div class="login-header">
                <div class="logo">NCM</div>
                <h4>Network Configuration Manager</h4>
                <p class="mb-0">Please sign in to continue</p>
            </div>
            <div class="login-body">
                <!-- Flash messages -->
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        <div class="alert alert-danger alert-dismissible fade show" role="alert">
                            {{ messages[0] }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endif %}
                {% endwith %}
                
                <form method="POST" action="{{ url_for('login') }}">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required 
                               placeholder="Enter your username" value="{{ request.form.username or '' }}">
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required
                               placeholder="Enter your password">
                    </div>
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="fas fa-sign-in-alt me-2"></i>Sign In
                    </button>
                </form>
            </div>
        </div>
        
        <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''
    
    # Use render_template_string to properly render the template with Flask context
    from flask import render_template_string
    return render_template_string(login_template)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    try:
        return render_template('a.html', devices=device_labels, user=current_user.id)
    except Exception as e:
        logging.error(f"Error rendering index: {e}")
        return "Error loading page", 500


@app.route('/health_check', methods=['POST'])
def health_check():
    selected = request.json.get("devices", [])
    results = []

    for label in selected:  # label is like "XR1 (192.168.29.161)"
        dev = device_map.get(label)
        if not dev:
            result = {
                "device": label,
                "status": "unreachable",
                "cpu": None,
                "memory": None,
                "uptime": "N/A",
                "error": "Device not found in devices.yaml"
            }
            results.append(result)
            # Write metrics to InfluxDB in background
            threading.Thread(target=write_device_metrics, args=(label, result), daemon=True).start()
            continue

        try:
            conn_params = get_conn_params(dev)
            conn = ConnectHandler(**conn_params)
            
            device_type = dev.get("device_type", "").lower()
            
            # CPU parsing - works for both IOS and XR
            try:
                if "xr" in device_type:
                    cpu_output = conn.send_command("show processes cpu", read_timeout=30)
                    # XR format: "CPU utilization for one minute: 2%; five minutes: 2%"
                    cpu_match = re.search(r"CPU utilization for one minute:\s*(\d+)%", cpu_output)
                else:
                    cpu_output = conn.send_command("show processes cpu | include one minute")
                    # IOS format: "CPU utilization for one minute: 2%"
                    cpu_match = re.search(r"(\d+)%.*one minute", cpu_output)
                
                cpu_val = int(cpu_match.group(1)) if cpu_match else None
            except Exception as e:
                logging.warning(f"CPU parsing failed for {label}: {e}")
                cpu_val = None

            # Memory parsing - different for XR vs IOS
            try:
                if "xr" in device_type:
                    # XR memory command and parsing
                    mem_output = conn.send_command("show memory summary", read_timeout=30)
                    # Parse XR format: "Physical Memory: 8192M total (4600M available)"
                    mem_match = re.search(r"Physical Memory:\s*(\d+)M total \((\d+)M available\)", mem_output)
                    if mem_match:
                        total_mb = int(mem_match.group(1))
                        available_mb = int(mem_match.group(2))
                        used_mb = total_mb - available_mb
                        mem_val = round((used_mb / total_mb) * 100, 1) if total_mb > 0 else None
                    else:
                        mem_val = None
                else:
                    # IOS memory parsing
                    mem_output = conn.send_command("show processes memory | include Processor Pool")
                    mem_match = re.search(r"(\d+)K used, (\d+)K free", mem_output.replace(",", ""))
                    if mem_match:
                        used_kb = int(mem_match.group(1))
                        free_kb = int(mem_match.group(2))
                        total_kb = used_kb + free_kb
                        mem_val = round((used_kb / total_kb) * 100, 1) if total_kb > 0 else None
                    else:
                        mem_val = None
            except Exception as e:
                logging.warning(f"Memory parsing failed for {label}: {e}")
                mem_val = None

            # Uptime parsing
            try:
                if "xr" in device_type:
                    uptime_output = conn.send_command("show version | include uptime", read_timeout=30)
                else:
                    uptime_output = conn.send_command("show version | include uptime")
                
                # Clean up the uptime output
                uptime_lines = [line.strip() for line in uptime_output.split('\n') if 'uptime' in line.lower()]
                uptime_display = uptime_lines[0] if uptime_lines else "N/A"
            except Exception as e:
                logging.warning(f"Uptime parsing failed for {label}: {e}")
                uptime_display = "N/A"

            # Determine overall status
            status = "healthy"
            if cpu_val is not None and cpu_val > 80:
                status = "high_cpu"
            elif mem_val is not None and mem_val > 80:
                status = "high_memory"

            result = {
                "device": label,
                "status": status,
                "cpu": cpu_val,
                "cpu_text": f"{cpu_val}%" if cpu_val is not None else "N/A",
                "memory": mem_val,
                "memory_text": f"{mem_val}%" if mem_val is not None else "N/A",
                "uptime": uptime_display
            }
            results.append(result)
            
            # Write metrics to InfluxDB in background
            threading.Thread(target=write_device_metrics, args=(label, result), daemon=True).start()
            
            conn.disconnect()

        except exceptions.NetMikoTimeoutException as e:
            result = {
                "device": label,
                "status": "timeout",
                "cpu": None,
                "cpu_text": "N/A",
                "memory": None,
                "memory_text": "N/A",
                "uptime": "N/A",
                "error": f"Connection timeout: {str(e)}"
            }
            results.append(result)
            threading.Thread(target=write_device_metrics, args=(label, result), daemon=True).start()
            

        except exceptions.NetMikoTimeoutException as e:
            results.append({
                "device": label,
                "status": "timeout",
                "cpu": None,
                "cpu_text": "N/A",
                "memory": None,
                "memory_text": "N/A",
                "uptime": "N/A",
                "error": f"Connection timeout: {str(e)}"
            })
        except exceptions.NetMikoAuthenticationException as e:
            results.append({
                "device": label,
                "status": "auth_failed",
                "cpu": None,
                "cpu_text": "N/A", 
                "memory": None,
                "memory_text": "N/A",
                "uptime": "N/A",
                "error": f"Authentication failed: {str(e)}"
            })
        except Exception as e:
            results.append({
                "device": label,
                "status": "unreachable",
                "cpu": None,
                "cpu_text": "N/A",
                "memory": None,
                "memory_text": "N/A",
                "uptime": "N/A",
                "error": str(e)
            })

    return jsonify({"results": results})


@app.route('/connectivity_check', methods=['POST'])
def connectivity_check():
    selected = request.json.get("devices", [])
    results = []

    for label in selected:
        dev = device_map.get(label)
        if not dev:
            results.append({
                "device": label,
                "reachable": False,
                "message": "Device not found in devices.yaml"
            })
            continue

        try:
            delay = ping(dev["ip"], timeout=1)
            reachable = delay is not None
            results.append({
                "device": label,
                "reachable": reachable,
                "message": f"Reachable ({round(delay*1000)} ms)" if reachable else "Unreachable"
            })
        except Exception as e:
            results.append({
                "device": label,
                "reachable": False,
                "message": str(e)
            })

    return jsonify({"results": results})
    
@app.route('/tig_status')
@login_required
def tig_status():
    """
    Check TIG stack connectivity status and return objects the UI expects.
    """
    influxdb = {'running': False, 'message': 'Not checked'}
    grafana  = {'running': False, 'message': 'Not checked'}
    telegraf = {'running': False, 'message': 'Not checked'}
    metrics_opt = None

    # InfluxDB check
    try:
        if influx_client:
            query_api = influx_client.query_api()
            q = f'from(bucket:"{INFLUX_CONFIG["bucket"]}") |> range(start: -1h) |> limit(n:1)'
            _ = list(query_api.query(q, org=INFLUX_CONFIG['org']))
            influxdb = {'running': True, 'message': 'OK'}

            # Optional: show a rough count for last 24h
            cq = f'from(bucket:"{INFLUX_CONFIG["bucket"]}") |> range(start: -24h) |> count()'
            cr = list(query_api.query(cq, org=INFLUX_CONFIG['org']))
            if cr and cr[0].records:
                metrics_opt = {'points_24h': cr[0].records[0].get_value()}
    except Exception as e:
        logging.error(f"InfluxDB status check failed: {e}")
        influxdb = {'running': False, 'message': str(e)}

    # Grafana check (uses localhost:3000 by default)
    try:
        import requests
        graf_url = os.environ.get("GRAFANA_URL", "http://localhost:3000")
        r = requests.get(f"{graf_url}/api/health", timeout=5)
        grafana = {'running': r.status_code == 200, 'message': f'status {r.status_code}'}
    except Exception as e:
        logging.error(f"Grafana status check failed: {e}")
        grafana = {'running': False, 'message': str(e)}

    # Telegraf check (HTTP metrics endpoint, then process fallback)
    try:
        import requests
        r = requests.get("http://localhost:9273/metrics", timeout=3)  # change if your endpoint differs
        telegraf = {'running': r.status_code == 200,
                    'message': 'metrics endpoint OK' if r.status_code == 200 else f'status {r.status_code}'}
    except Exception as e:
        # Fallback: process check (psutil is already imported in this file)
        try:
            running = any('telegraf' in (p.info.get('name') or '').lower()
                          for p in psutil.process_iter(attrs=['name']))
            telegraf = {'running': running, 'message': 'process running' if running else str(e)}
        except Exception as e2:
            telegraf = {'running': False, 'message': str(e2)}

    return jsonify({
        'influxdb': influxdb,
        'grafana': grafana,
        'telegraf': telegraf,
        'metrics': metrics_opt
    })

# Start TIG collection for selected devices
@app.route('/tig_start', methods=['POST'])
@login_required
def tig_start():
    try:
        data = request.get_json(silent=True) or {}
        devices = data.get('devices', [])
        if not devices:
            return jsonify({'success': False, 'error': 'No devices provided'}), 400

        # TODO: start your scheduler / background thread here
        # e.g., schedule.every(30).seconds.do(poll_and_write_metrics, devices)

        return jsonify({'success': True, 'started_for': devices})
    except Exception as e:
        logging.error(f"tig_start error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Stop TIG collection
@app.route('/tig_stop', methods=['POST'])
@login_required
def tig_stop():
    try:
        # TODO: cancel scheduler / background job here
        return jsonify({'success': True, 'message': 'Monitoring stopped'})
    except Exception as e:
        logging.error(f"tig_stop error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
#@app.route('/download_backup/<device_name>/<path:filename>')
#def download_backup_route(device_name, filename):
@app.route('/download_backup/<device_name>/<path:filename>', endpoint='download_backup_with_device')
@app.route('/download_backup/<path:filename>', endpoint='download_backup_no_device')
def download_backup_route(filename, device_name=None):
    # ... your existing logic ...
    # make sure this works when device_name is None

    try:
        from urllib.parse import unquote
        import atexit
        
        # URL decode the device name
        device_name = unquote(device_name)
        
        # Extract device name from label format "DeviceName (IP)"
        clean_device_name = device_name
        if "(" in device_name and ")" in device_name:
            clean_device_name = device_name.split("(")[0].strip()
        
        # Log for debugging
        logging.info(f"Download request - Device: '{device_name}', Clean: '{clean_device_name}', File: '{filename}'")
        
        # Define search order and folders
        search_folders = [
            (CURRENT_ROOT, "current_configs"),
            (BACKUP_ROOT, "backups"), 
            (GOLDEN_ROOT, "golden_configs")
        ]
        
        found_file_path = None
        found_folder_type = None
        
        for folder_root, folder_name in search_folders:
            folder_path = os.path.join(folder_root, clean_device_name)
            file_path = os.path.join(folder_path, filename)
            
            logging.info(f"Checking: {file_path}")
            
            if os.path.exists(file_path):
                logging.info(f"Found file: {file_path}")
                found_file_path = file_path
                found_folder_type = folder_name
                break
            
            # Also try with original device_name (in case it has special chars)
            original_device_name = unquote(request.view_args['device_name'])
            if original_device_name != clean_device_name:
                alt_folder_path = os.path.join(folder_root, original_device_name)
                alt_file_path = os.path.join(alt_folder_path, filename)
                
                logging.info(f"Checking alternative: {alt_file_path}")
                
                if os.path.exists(alt_file_path):
                    logging.info(f"Found file at alternative path: {alt_file_path}")
                    found_file_path = alt_file_path
                    found_folder_type = folder_name
                    break
        
        if not found_file_path:
            # List available files for debugging
            logging.error(f"File not found. Available folders:")
            for folder_root, folder_name in search_folders:
                base_path = os.path.join(folder_root, clean_device_name)
                if os.path.exists(base_path):
                    files = os.listdir(base_path)
                    logging.error(f"  {folder_name}/{clean_device_name}: {files}")
                else:
                    logging.error(f"  {folder_name}/{clean_device_name}: FOLDER DOES NOT EXIST")
            
            return jsonify({
                'error': 'File not found',
                'device': device_name,
                'filename': filename,
                'searched_paths': [f"{folder_root}/{clean_device_name}/{filename}" for folder_root, _ in search_folders]
            }), 404
        
        # Read and analyze the configuration file
        with open(found_file_path, 'r', encoding='utf-8') as f:
            config_content = f.read()
        
        # Extract commands and generate AI explanations
        ai_explanations = generate_config_explanations(config_content, clean_device_name)
        
        # Create a temporary file that will be automatically cleaned up
        temp_zip_fd, temp_zip_path = tempfile.mkstemp(suffix='.zip')
        
        try:
            # Close the file descriptor immediately since we'll open it with zipfile
            os.close(temp_zip_fd)
            
            # Create zip file with config and explanations
            with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add the original configuration file
                archive_path = f"{clean_device_name}/{found_folder_type}/{filename}"
                zipf.write(found_file_path, archive_path)
                
                # Add AI explanations as a separate file
                explanation_filename = f"{filename.rsplit('.', 1)[0]}_explanations.txt"
                explanation_archive_path = f"{clean_device_name}/{found_folder_type}/{explanation_filename}"
                zipf.writestr(explanation_archive_path, ai_explanations)
            
            # Read the zip content
            with open(temp_zip_path, 'rb') as zip_file:
                zip_data = zip_file.read()
            
            # Create response with proper headers
            response = make_response(zip_data)
            response.headers['Content-Type'] = 'application/zip'
            response.headers['Content-Disposition'] = f'attachment; filename="{clean_device_name}_{filename}_with_explanations.zip"'
            
            return response
            
        finally:
            # Clean up temp file in finally block to ensure it gets deleted
            try:
                if os.path.exists(temp_zip_path):
                    os.unlink(temp_zip_path)
            except OSError as e:
                logging.warning(f"Could not delete temp file {temp_zip_path}: {e}")
        
    except Exception as e:
        logging.error(f"Download error for {device_name}/{filename}: {e}")
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

def generate_config_explanations(config_content, device_name):
    """
    Generate AI explanations for configuration commands including usage examples
    """
    try:
        # Find device info to determine vendor/type
        device_info = None
        for label, info in device_map.items():
            if info['name'] == device_name:
                device_info = info
                break
        
        vendor = "cisco"  # default
        if device_info:
            device_type = device_info.get('device_type', '').lower()
            if 'juniper' in device_type:
                vendor = "juniper"
            elif 'arista' in device_type:
                vendor = "arista"
            elif 'xr' in device_type:
                vendor = "cisco_xr"
        
        # Parse configuration into commands
        lines = config_content.splitlines()
        commands = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('!') and not line.startswith('#'):
                # Skip common non-command lines
                skip_patterns = [
                    'building configuration',
                    'current configuration',
                    'last configuration change',
                    'version ',
                    'end'
                ]
                
                if not any(pattern in line.lower() for pattern in skip_patterns):
                    commands.append(line)
        
        # Use the existing AI explanation function
        from utils.cohere_parser import explain_commands_with_usage
        
        # Generate explanations with usage examples
        explanations = explain_commands_with_usage(commands[:50], vendor)  # Limit to first 50 commands
        
        # Format the explanations nicely
        formatted_explanation = f"""
CONFIGURATION ANALYSIS AND EXPLANATIONS
========================================

Device: {device_name}
Vendor: {vendor.upper()}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

========================================

This document provides detailed explanations for each configuration command,
including their purpose, usage, and implementation examples for terminal/PuTTY.

========================================

{explanations}

========================================
IMPLEMENTATION GUIDE
========================================

How to implement these commands in PuTTY/Terminal:

1. USING PUTTY:
   - Open PuTTY and connect to your device
   - Login with your credentials
   - Enter privileged mode: enable
   - Enter configuration mode: configure terminal
   - Copy and paste commands one by one
   - Save configuration: copy running-config startup-config

2. USING TERMINAL/SSH:
   - ssh username@device_ip
   - Enter privileged mode: enable
   - Enter configuration mode: configure terminal
   - Apply commands sequentially
   - Verify configuration: show running-config
   - Save: write memory or copy run start

3. BEST PRACTICES:
   - Always backup current configuration before changes
   - Test commands in lab environment first
   - Apply changes during maintenance windows
   - Document all changes made
   - Verify functionality after implementation

4. ROLLBACK PROCEDURES:
   - Keep backup configurations ready
   - Use configuration replace for quick rollback
   - Have console access available
   - Plan rollback steps before implementation

========================================
"""
        
        return formatted_explanation
        
    except Exception as e:
        logging.error(f"Failed to generate AI explanations: {e}")
        return f"""
CONFIGURATION FILE: {device_name}

AI explanation generation failed: {str(e)}

The configuration file is included in this download for manual review.
Please refer to vendor documentation for command explanations.
"""

def explain_commands_with_usage(commands, vendor="cisco"):
    """
    Enhanced explanation function that includes usage and implementation details
    """
    try:
        # Import the existing explanation function
        from utils.cohere_parser import explain_commands
        
        # Get basic explanations
        basic_explanations = explain_commands(commands, vendor)
        
        # Enhance with usage examples for common commands
        enhanced_explanations = []
        
        for i, command in enumerate(commands):
            explanation = f"Command {i+1}: {command}\n"
            
            # Add basic AI explanation if available
            if isinstance(basic_explanations, list) and i < len(basic_explanations):
                explanation += f"Explanation: {basic_explanations[i]}\n"
            elif isinstance(basic_explanations, str):
                explanation += f"Explanation: {basic_explanations}\n"
            
            # Add usage examples for common command types
            usage_example = get_usage_example(command, vendor)
            if usage_example:
                explanation += f"Usage Example: {usage_example}\n"
            
            # Add implementation notes
            impl_notes = get_implementation_notes(command, vendor)
            if impl_notes:
                explanation += f"Implementation Notes: {impl_notes}\n"
            
            explanation += "-" * 50 + "\n"
            enhanced_explanations.append(explanation)
        
        return "\n".join(enhanced_explanations)
        
    except Exception as e:
        logging.error(f"Enhanced explanation failed: {e}")
        return f"Enhanced explanations unavailable: {str(e)}\n\nBasic command list:\n" + "\n".join(f"{i+1}. {cmd}" for i, cmd in enumerate(commands))

def get_usage_example(command, vendor):
    """
    Provide usage examples for common commands
    """
    cmd_lower = command.lower().strip()
    
    examples = {
        'interface': f"To configure this interface:\n  Router(config)# {command}\n  Router(config-if)# [interface commands]\n  Router(config-if)# no shutdown",
        'ip address': f"Applied under interface configuration:\n  Router(config-if)# {command}",
        'router': f"Enters routing protocol configuration:\n  Router(config)# {command}\n  Router(config-router)# [routing commands]",
        'access-list': f"Apply to interface:\n  Router(config)# {command}\n  Router(config)# interface [interface]\n  Router(config-if)# ip access-group [acl-name] [in|out]",
        'vlan': f"VLAN configuration:\n  Switch(config)# {command}\n  Switch(config-vlan)# name [vlan-name]",
        'spanning-tree': f"STP configuration:\n  Switch(config)# {command}",
        'hostname': f"System identification:\n  Router(config)# {command}",
        'enable secret': f"Privileged mode password:\n  Router(config)# {command}",
    }
    
    for keyword, example in examples.items():
        if keyword in cmd_lower:
            return example
    
    return None

def get_implementation_notes(command, vendor):
    """
    Provide implementation-specific notes
    """
    cmd_lower = command.lower().strip()
    
    notes = {
        'interface': "⚠️ Always verify interface is administratively up after configuration",
        'ip address': "⚠️ Ensure subnet masks are correct and no IP conflicts exist",
        'router': "⚠️ Remember to configure network statements and neighbor relationships",
        'access-list': "⚠️ Test ACL rules carefully - incorrect rules can block legitimate traffic",
        'vlan': "⚠️ Ensure VLAN is allowed on trunk ports if needed",
        'enable secret': "⚠️ Use strong passwords and document securely",
        'no shutdown': "✅ This command brings the interface online",
        'shutdown': "⚠️ This command disables the interface - use with caution",
    }
    
    for keyword, note in notes.items():
        if keyword in cmd_lower:
            return note
    
    return None



# ---------------------------
# Run
# ---------------------------
if __name__ == '__main__':
    # Ensure base directories present
    for folder in (RUNNING_ROOT, BACKUP_ROOT, CURRENT_ROOT, GOLDEN_ROOT, UPLOAD_FOLDER):
        os.makedirs(folder, exist_ok=True)
    app.run(debug=True, port=5000, host='0.0.0.0')


