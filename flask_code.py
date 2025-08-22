#!/usr/bin/env python3
# flask_code2.py
# Full Flask app with per-device folders for running/backups/current/golden and generate_config_only route
# Enhanced with better XR device handling and pattern detection fixes
# Added Golden Config feature - mark backups as golden and dedicated golden restore

import os
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
from flask import make_response
import yaml
import paramiko
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from netmiko import ConnectHandler, exceptions

# Local parser utilities (must exist)
from utils.cohere_parser import get_action_from_prompt, extract_config_commands

# ---------------------------
# App & config
# ---------------------------
app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # change for prod

# Base directories (per-device structure)
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

# Remote Ubuntu backup details (change as needed)
CLIENT_USER = "vayu2"
CLIENT_PASS = "vayu123!"
CLIENT_IP   = "10.235.6.41"
CLIENT_DIR  = "/home/vayu2/Desktop"

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
device_map = {f"{d['name']} ({d['ip']})": d for d in devices}
device_labels = list(device_map.keys())

# ---------------------------
# Helpers
# ---------------------------
def timestamp_now(fmt="%Y%m%d_%H%M%S"):
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

def send_to_remote(local_file, device_name):
    """SFTP transfer of backup to remote Ubuntu directory (optional)."""
    try:
        utc_time = datetime.now(timezone.utc)
        utc_filename = f"running_{device_name}_{utc_time:%Y-%m-%d_%H%M}.txt"

        transport = paramiko.Transport((CLIENT_IP, 22))
        transport.connect(username=CLIENT_USER, password=CLIENT_PASS)
        sftp = paramiko.SFTPClient.from_transport(transport)

        remote_backup_root = f"{CLIENT_DIR}/backups"
        try:
            sftp.stat(remote_backup_root)
        except IOError:
            sftp.mkdir(remote_backup_root)

        remote_device_folder = f"{remote_backup_root}/{device_name}"
        try:
            sftp.stat(remote_device_folder)
        except IOError:
            sftp.mkdir(remote_device_folder)

        remote_file_path = f"{remote_device_folder}/{utc_filename}"
        sftp.put(local_file, remote_file_path)

        sftp.close()
        transport.close()
        logging.info(f"Backup stored on remote Ubuntu: {remote_file_path}")
    except Exception as e:
        logging.error(f"Failed to send backup to remote Ubuntu: {e}")

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
    Restore config from a file_info (dict with name/type) or filename string.
    Enhanced with better XR handling.
    """
    if isinstance(file_info, dict):
        fname = file_info.get('name')
        ftype = file_info.get('type')
        # file_info.path may be relative or just filename, depending on UI
        path_field = file_info.get('path', fname)
        if ftype == 'timestamped_backup':
            path = os.path.join(BACKUP_ROOT, device_name, path_field)
        elif ftype == 'current_config':
            path = os.path.join(CURRENT_ROOT, device_name, path_field)
        elif ftype == 'golden_config':
            path = os.path.join(GOLDEN_ROOT, device_name, path_field)
        else:
            # fallback to backup
            path = os.path.join(BACKUP_ROOT, device_name, path_field)
    else:
        # string name – search in backups/current/golden
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

    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    device_type = device_info.get("device_type", "").lower()
    
    # Filter commands based on device type
    if "juniper" in device_type:
        commands = [ln for ln in lines if ln and not ln.startswith('#') and (ln.startswith('set ') or ln.startswith('delete '))]
    elif "xr" in device_type:
        # For XR, filter out comments and empty lines, but be more permissive
        commands = []
        for ln in lines:
            ln = ln.strip()
            if ln and not ln.startswith('!') and not ln.startswith('#') and not ln.startswith('Building configuration'):
                # Skip common XR output headers
                if not any(header in ln.lower() for header in ['current configuration', 'building configuration', 'last configuration change']):
                    commands.append(ln)
    else:
        commands = [ln for ln in lines if ln and not ln.startswith('!') and not ln.startswith('#')]

    if not commands:
        raise Exception(f"No valid configuration commands found in {fname}")

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
                    # For XR devices, use config mode with commit
                    try:
                        # Enter config mode
                        conn.config_mode()
                        
                        # Send commands in smaller chunks to avoid timeout
                        chunk_size = 20  # Process 20 commands at a time
                        for i in range(0, len(commands), chunk_size):
                            chunk = commands[i:i + chunk_size]
                            for cmd in chunk:
                                try:
                                    # Send command and wait for prompt with longer timeout
                                    result = conn.send_command_timing(cmd, delay_factor=2)
                                    if 'error' in result.lower() or 'invalid' in result.lower():
                                        logging.warning(f"Possible error in command '{cmd}': {result}")
                                except Exception as cmd_err:
                                    logging.error(f"Error sending command '{cmd}': {cmd_err}")
                                    # Continue with next command
                                    continue
                        
                        # Commit configuration
                        commit_result = conn.send_command("commit", read_timeout=30)
                        if 'failed' in commit_result.lower() or 'error' in commit_result.lower():
                            raise Exception(f"Commit failed: {commit_result}")
                        
                        # Exit config mode
                        conn.exit_config_mode()
                        
                    except Exception as config_err:
                        # Try to exit config mode gracefully
                        try:
                            conn.send_command("abort")
                            conn.exit_config_mode()
                        except:
                            pass
                        raise Exception(f"XR configuration failed: {config_err}")
                        
                elif "juniper" in device_type:
                    conn.send_config_set(commands)
                    conn.send_command("commit")
                else:
                    # Standard IOS devices
                    conn.send_config_set(commands)
                    try:
                        conn.send_command("write memory")
                    except Exception:
                        # Not fatal if save fails
                        pass
                    
        return f"Restored {fname} to {device_name} ({len(commands)} commands applied)"
        
    except exceptions.NetMikoTimeoutException as e:
        raise Exception(f"Timeout during restore - {e}. Try breaking config into smaller files.")
    except exceptions.ConnectionException as e:
        raise Exception(f"Connection failed during restore - {e}")
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
# Replace your existing error handlers with these fixed versions:

# Replace your existing error handlers with these fixed versions:

@app.errorhandler(404)
def not_found_error(error):
    if request.accept_mimetypes.best == 'application/json':
        return jsonify({'error': 'Not found'}), 404
    # Return HTML directly instead of trying to render template
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
    # Return HTML directly instead of trying to render template
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
@app.route('/')
def index():
    try:
        return render_template('index.html', devices=device_labels)
    except Exception as e:
        logging.error(f"Error rendering index: {e}")
        return "Error loading page", 500

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

        try:
            commands = extract_config_commands(get_action_from_prompt(prompt))
        except Exception as e:
            logging.error(f"Failed to parse commands: {e}")
            return jsonify({'error': 'Failed to parse commands from prompt'}), 400

        if not commands:
            return jsonify({'error': 'No valid commands found in prompt'}), 400

        results = {'commands': commands, 'device_results': []}

        for label in selected_devices:
            if label not in device_map:
                results['device_results'].append({'device': label, 'success': False, 'message': 'Device not found'})
                continue
            info = device_map[label]
            device_result = {'device': label, 'success': False, 'message': '', 'command_outputs': [], 'config_diff': ''}

            try:
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
        selected_devices = data.get('devices', [])
        selected_files = data.get('files', [])
        if not selected_devices or not selected_files:
            return jsonify({'error': 'Please select devices and backup files'}), 400

        results = []
        for label in selected_devices:
            if label not in device_map:
                results.append({'device': label, 'success': False, 'message': 'Device not found'})
                continue
            info = device_map[label]
            device_name = info['name']
            device_result = {'device': label, 'success': False, 'message': '', 'messages': []}
            try:
                for f in selected_files:
                    device_result['messages'].append(restore_device_config(info, f, device_name))
                device_result['success'] = True
                device_result['message'] = f"Restored {len(selected_files)} file(s)"
            except Exception as e:
                logging.error(f"Restore failed for {label}: {e}")
                device_result['message'] = str(e)
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

        timestamp = timestamp_now("%Y%m%d_%H%M%S")
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
# Run
# ---------------------------
if __name__ == '__main__':
    # Ensure base directories present
    for folder in (RUNNING_ROOT, BACKUP_ROOT, CURRENT_ROOT, GOLDEN_ROOT, UPLOAD_FOLDER):
        os.makedirs(folder, exist_ok=True)
    app.run(debug=True, port=5000, host='0.0.0.0')
