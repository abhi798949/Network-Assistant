# flask_code.py
import io
import zipfile
import logging
import yaml
from flask import Flask, render_template, request, jsonify, send_from_directory
from netmiko import ConnectHandler
from datetime import datetime, timezone
import difflib
import os
import threading
import schedule
import time as t
import json
import paramiko  # For SFTP to remote Ubuntu
from utils.cohere_parser import get_action_from_prompt, extract_config_commands
import re
from flask import send_from_directory, abort

# ==== Remote Ubuntu backup details (Change these) ====
CLIENT_USER = "vayu2"
CLIENT_PASS = "vayu123!"
CLIENT_IP = "10.235.6.41"
CLIENT_DIR = "/home/vayu/Desktop"

app = Flask(__name__, template_folder="templates")

# ==== Folders & config ====
RUNNING_CONFIG_FOLDER = "running_configs"
UPLOAD_FOLDER = "uploads"
GOLDEN_CONFIG_FOLDER = "golden_configs"



os.makedirs(RUNNING_CONFIG_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(GOLDEN_CONFIG_FOLDER, exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs("utils", exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler()]
)

# Load device info
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
device_labels = list(device_map)

# Global for scheduler
scheduled_jobs = []

# Health check commands mapping for audit functionality (unchanged)
HEALTH_CHECK_COMMANDS = {
    "cisco_ios": [
        "show version",
        "show interfaces summary",
        "show ip route summary",
        "show memory statistics",
        "show processes cpu sorted",
        "show environment all",
        "show logging | include ERROR|WARN|CRITICAL",
        "show interfaces status | include err-disabled",
        "show spanning-tree summary"
    ],
    "cisco_xr": [
        "show version",
        "show interfaces brief",
        "show route summary",
        "show memory summary",
        "show processes cpu",
        "show environment all",
        "show logging | include ERROR|WARN|CRITICAL",
        "show interfaces brief | include Down",
        "show redundancy summary"
    ],
    "default": [
        "show version",
        "show interfaces",
        "show ip route",
        "show memory",
        "show processes",
        "show logging"
    ]
}

# Utility functions
def get_conn_params(info):
    try:
        return {
            "device_type": info["device_type"],
            # Netmiko expects "host" or "ip"; your code used "ip"
            "host": info.get("ip") or info.get("host"),
            "username": info["username"],
            "password": info["password"],
        }
    except KeyError as e:
        logging.error(f"Missing device info key: {e}")
        raise

def normalize_command(command):
    aliases = {
        "sh": "show",
        "conf": "configure",
        "config": "configure",
        "int": "interface",
        "ip": "ip",
        "no": "no",
        "wr": "write memory",
        "copy": "copy",
        "en": "enable",
        "dis": "disable",
        "desc": "description"
    }
    words = command.strip().split()
    if words and words[0] in aliases:
        words[0] = aliases[words[0]]
    return " ".join(words) if words else command

def send_to_remote(local_file, device_name):
    """Send backup file to remote Ubuntu via SFTP with UTC timestamp."""
    try:
        utc_time = datetime.now(timezone.utc)
        utc_filename = f"running_{device_name}_{utc_time:%Y-%m-%d_%H%M}.cfg"

        transport = paramiko.Transport((CLIENT_IP, 22))
        transport.connect(username=CLIENT_USER, password=CLIENT_PASS)
        sftp = paramiko.SFTPClient.from_transport(transport)

        remote_backup_root = f"{CLIENT_DIR}/backups"
        try:
            sftp.stat(remote_backup_root)
        except FileNotFoundError:
            sftp.mkdir(remote_backup_root)

        remote_device_folder = f"{remote_backup_root}/{device_name}"
        try:
            sftp.stat(remote_device_folder)
        except FileNotFoundError:
            sftp.mkdir(remote_device_folder)

        remote_file_path = f"{remote_device_folder}/{utc_filename}"
        sftp.put(local_file, remote_file_path)

        sftp.close()
        transport.close()
        logging.info(f"Backup stored on remote Ubuntu with UTC time: {remote_file_path}")
    except Exception as e:
        logging.error(f"Failed to send backup to remote Ubuntu: {e}")

def backup_config(conn, folder, name, label):
    config = conn.send_command("show running-config")
    os.makedirs(folder, exist_ok=True)

    # Normal backup path
    backup_file = os.path.join(folder, f"running_{name}_{datetime.now():%Y-%m-%d_%H%M}.cfg")
    with open(backup_file, "w", encoding="utf-8") as f:
        f.write(config)
    logging.info(f"Backup stored locally: {backup_file}")

    # Also save golden config copy
    golden_device_folder = os.path.join(GOLDEN_CONFIG_FOLDER, name)
    os.makedirs(golden_device_folder, exist_ok=True)
    golden_file = os.path.join(golden_device_folder, f"golden_{name}_{datetime.now():%Y-%m-%d_%H%M}.cfg")
    with open(golden_file, "w", encoding="utf-8") as gf:
        gf.write(config)
    logging.info(f"Golden config stored locally: {golden_file}")

    # Also send backup to remote Ubuntu
    send_to_remote(backup_file, name)
    return backup_file

    return os.path.basename(local_fname)

def restore_config(conn, folder, files, name, label):
    """Restore configuration by reading files from folder and pushing to device. Returns list of messages including CLI output."""
    results = []
    for f in files:
        path = os.path.join(folder, f)
        if not os.path.isfile(path):
            err = f"Configuration file '{f}' not found in {folder}"
            logging.error(err)
            results.append(f"❌ {err}")
            continue

        try:
            with open(path, 'r', encoding='utf-8') as config_file:
                config_content = config_file.read()

            # Basic filtering: remove comments/empty lines and common non-config lines
            skip_patterns = [
                'building configuration', 'current configuration', 'boot-start-marker',
                'boot-end-marker', 'end', 'hostname', '!', '#'
            ]
            config_lines = []
            for line in config_content.splitlines():
                lstrip = line.strip()
                if not lstrip:
                    continue
                low = lstrip.lower()
                if any(p in low for p in skip_patterns):
                    continue
                config_lines.append(lstrip)

            if not config_lines:
                results.append(f"⚠️ No valid configuration commands found in '{f}'")
                continue

            # Device type handling
            device_type = conn.device_type.lower()
            cli_out = ""
            if 'cisco_xr' in device_type:
                # XR: enter config mode and push lines with commit
                conn.config_mode()
                batch_size = 20
                for i in range(0, len(config_lines), batch_size):
                    batch = config_lines[i:i+batch_size]
                    for cmd in batch:
                        try:
                            cli_out += conn.send_command_timing(cmd, delay_factor=2) + "\n"
                        except Exception as cmd_error:
                            logging.warning(f"Command failed '{cmd}': {cmd_error}")
                commit_out = conn.send_command_timing("commit", delay_factor=5)
                cli_out += commit_out
                try:
                    conn.exit_config_mode()
                except Exception:
                    pass
            else:
                # IOS or others: use send_config_set
                try:
                    cli_out = conn.send_config_set(config_lines, delay_factor=2, strip_prompt=False, strip_command=False)
                except Exception as e:
                    # fallback: send one-by-one
                    try:
                        conn.config_mode()
                    except Exception:
                        pass
                    for cmd in config_lines:
                        try:
                            cli_out += conn.send_command_timing(cmd, delay_factor=2) + "\n"
                        except Exception as cmd_err:
                            logging.warning(f"Command failed '{cmd}': {cmd_err}")
                    try:
                        conn.exit_config_mode()
                    except Exception:
                        pass

            results.append(f"✅ Restored Successfully ")
        except Exception as e:
            logging.error(f"Restore failed for {label} file {f}: {e}")
            results.append(f"❌ Failed to restore '{f}' on {label}: {e}")
    return results

def save_config(conn, folder, name, prefix):
    try:
        config = conn.send_command("show running-config")
        fname = os.path.join(folder, f"{prefix}_{name}_{datetime.now():%Y-%m-%d_%H%M}.cfg")
        with open(fname, "w", encoding="utf-8") as f:
            f.write(config)
        return config
    except Exception as e:
        logging.error(f"Failed to save config for {name}: {e}")
        return ""

def backup_device_thread(label):
    info = device_map.get(label)
    if not info:
        logging.warning(f"Device info not found for label: {label}")
        return
    folder = os.path.join(RUNNING_CONFIG_FOLDER, info['name'])
    os.makedirs(folder, exist_ok=True)
    try:
        with ConnectHandler(**get_conn_params(info)) as conn:
            conn.enable()
            backup_config(conn, folder, info["name"], label)
            logging.info(f"[Scheduled] Backup done for {label}")
    except Exception as e:
        logging.error(f"[Scheduled] Backup failed for {label}: {e}")

def perform_backup_for_devices(device_list):
    threads = []
    for label in device_list:
        t = threading.Thread(target=backup_device_thread, args=(label,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

# Background scheduler loop
def run_scheduler():
    while True:
        try:
            schedule.run_pending()
        except Exception as e:
            logging.error(f"Scheduler error: {e}")
        t.sleep(60)

scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
scheduler_thread.start()

@app.route('/')
def index():
    try:
        return render_template('index.html', devices=device_labels)
    except Exception as e:
        logging.error(f"Error rendering index: {e}")
        return "Error loading page", 500

@app.route('/get_backup_files')
def get_backup_files():
    try:
        device_label = request.args.get('device')
        if not device_label or device_label not in device_map:
            return jsonify([])
        device_info = device_map[device_label]
        backup_dir = os.path.join(RUNNING_CONFIG_FOLDER, device_info["name"])
        if os.path.isdir(backup_dir):
            files = [f for f in os.listdir(backup_dir) if f.endswith('.cfg') or f.endswith('.cfg')]
            return jsonify(sorted(files))
        return jsonify([])
    except Exception as e:
        logging.error(f"Error getting backup files: {e}")
        return jsonify([])

@app.route('/get_golden_configs')
def get_golden_configs():
    device_label = request.args.get('device')
    if not device_label:
        return jsonify([])

    # Find matching device in device_map
    device_info = device_map.get(device_label)
    if not device_info:
        # Try matching by partial name
        base_name = device_label.split()[0]
        for k, v in device_map.items():
            if v["name"] == base_name or k.startswith(base_name):
                device_info = v
                break
    if not device_info:
        return jsonify([])

    golden_folder = os.path.join(GOLDEN_CONFIG_FOLDER, device_info["name"])
    if not os.path.exists(golden_folder):
        return jsonify([])

    files = [f for f in os.listdir(golden_folder) if f.endswith('.cfg') or f.endswith('.cfg')]
    return jsonify(sorted(files))



@app.route('/execute_command', methods=['POST'])
def execute_command():
    try:
        data = request.get_json()
        selected_devices = data.get('devices', [])
        prompt = data.get('prompt', '')

        if not selected_devices or not prompt:
            return jsonify({'error': 'Please select devices and enter a prompt'}), 400

        commands = extract_config_commands(get_action_from_prompt(prompt))
        # Block execution if all commands are show commands
        if commands and all(cmd.strip().lower().startswith('show') for cmd in commands):
            return jsonify({'error': 'Only verify is allowed for show commands. Please use the Verify Command button.'}), 400

        results = {
            'commands': commands,
            'device_results': []
        }

        for label in selected_devices:
            if label not in device_map:
                continue
            info = device_map[label]
            folder = os.path.join(RUNNING_CONFIG_FOLDER, info["name"])
            os.makedirs(folder, exist_ok=True)

            device_result = {
                'device': label,
                'success': False,
                'message': '',
                'command_outputs': [],
                'config_diff': ''
            }

            try:
                with ConnectHandler(**get_conn_params(info)) as conn:
                    conn.enable()
                    old_config = save_config(conn, folder, info["name"], "old_running")

                    config_commands = [c for c in commands if not c.strip().lower().startswith("show")]
                    if config_commands:
                        cmd_output = conn.send_config_set(config_commands)
                        device_result['message'] = 'Configuration applied successfully'
                        device_result['command_outputs'].append({'command': 'applied', 'output': cmd_output})

                    for cmd in commands:
                        if cmd.strip().lower().startswith("show"):
                            try:
                                output = conn.send_command(cmd)
                                device_result['command_outputs'].append({'command': cmd, 'output': output})
                            except Exception as ce:
                                logging.error(f"Show command failed on {label}: {ce}")
                                device_result['command_outputs'].append({'command': cmd, 'output': f'Error: {ce}'})

                    new_config = save_config(conn, folder, info["name"], "new_running")
                    diff = '\n'.join(difflib.unified_diff(old_config.splitlines(), new_config.splitlines(), fromfile="Before", tofile="After", lineterm=""))
                    device_result['config_diff'] = diff if diff else "No changes detected."
                    device_result['success'] = True
            except Exception as e:
                logging.error(f"Command execution failed for {label}: {e}")
                device_result['message'] = f'Error: {str(e)}'

            results['device_results'].append(device_result)

        return jsonify(results)

    except Exception as e:
        logging.error(f"Failed to process command: {e}")
        return jsonify({'error': f'Failed to process command: {str(e)}'}), 500

@app.route('/generate_config_only', methods=['POST'])
def generate_config_only():
    """
    Generates config commands from AI but does not apply them.
    """
    try:
        data = request.get_json()
        devices = data.get('devices', [])
        prompt = data.get('prompt', '').strip()

        if not devices or not prompt:
            return jsonify({'error': 'Please provide devices and prompt'}), 400

        # Use your existing AI generation logic here
        from utils.cohere_parser import get_action_from_prompt, extract_config_commands

        ai_response = get_action_from_prompt(prompt)
        config_commands = extract_config_commands(ai_response)

        return jsonify({'commands': config_commands})

    except Exception as e:
        logging.error(f"Failed to generate config only: {e}")
        return jsonify({'error': f'Failed to generate config: {str(e)}'}), 500


@app.route('/verify_command', methods=['POST'])
def verify_command():
    try:
        data = request.get_json()
        selected_devices = data.get('devices', [])
        prompt = data.get('prompt', '')

        if not selected_devices or not prompt:
            return jsonify({'error': 'Please select devices and enter a prompt'}), 400

        commands = extract_config_commands(get_action_from_prompt(prompt))
        results = {'commands': commands, 'device_results': []}

        for label in selected_devices:
            if label not in device_map:
                continue
            info = device_map[label]
            device_result = {'device': label, 'success': False, 'message': '', 'command_outputs': [], 'config_diff': ''}
            try:
                with ConnectHandler(**get_conn_params(info)) as conn:
                    conn.enable()
                    for cmd in commands:
                        try:
                            if cmd.strip().lower().startswith("show"):
                                output = conn.send_command(cmd)
                                device_result['command_outputs'].append({'command': cmd, 'output': output})
                            else:
                                device_result['command_outputs'].append({'command': cmd, 'output': 'Command validated (not executed in verify mode)'})
                        except Exception as ce:
                            logging.error(f"Command failed on {label}: {ce}")
                            device_result['command_outputs'].append({'command': cmd, 'output': f'Error: {ce}'})
                    device_result['success'] = True
                    device_result['message'] = 'Verification completed successfully'
            except Exception as e:
                logging.error(f"Verify command failed for {label}: {e}")
                device_result['message'] = f'Error: {str(e)}'
            results['device_results'].append(device_result)
        return jsonify(results)
    except Exception as e:
        logging.error(f"Failed to process verify command: {e}")
        return jsonify({'error': f'Failed to process command: {str(e)}'}), 500

@app.route('/backup_devices', methods=['POST'])
def backup_devices():
    try:
        data = request.get_json()
        selected_devices = data.get('devices', [])
        if not selected_devices:
            return jsonify({'error': 'Please select devices to backup'}), 400

        results = []
        for label in selected_devices:
            if label not in device_map:
                continue
            info = device_map[label]
            folder = os.path.join(RUNNING_CONFIG_FOLDER, info["name"])
            os.makedirs(folder, exist_ok=True)
            try:
                with ConnectHandler(**get_conn_params(info)) as conn:
                    conn.enable()
                    fname = backup_config(conn, folder, info["name"], label)
                    # Provide download link
                    download_url = f"/download_backup/{info['name']}/{os.path.basename(fname)}"
                    results.append({'device': label, 'success': True, 'download_url': download_url})
            except Exception as e:
                results.append({'device': label, 'success': False, 'message': str(e)})

        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/restore_devices', methods=['POST'])
def restore_devices():
    """
    Accepts:
      devices: [label1, label2]
      files: [filename1, filename2]  # names located either in device run folder or golden folder
      restore_type: 'backup' or 'golden'
    """
    try:
        data = request.get_json()
        selected_devices = data.get('devices', [])
        selected_files = data.get('files', [])
        restore_type = data.get('restore_type', 'backup')

        if not selected_devices or not selected_files:
            return jsonify({'error': 'Please select devices and backup/golden files'}), 400

        results = []
        for label in selected_devices:
            if label not in device_map:
                results.append({'device': label, 'success': False, 'message': 'Device not found'})
                continue
            info = device_map[label]
            # folder chosen based on restore_type
            if restore_type == 'golden':
                folder =os.path.join(GOLDEN_CONFIG_FOLDER, info["name"])
            else:
                folder = os.path.join(RUNNING_CONFIG_FOLDER, info["name"])

            try:
                with ConnectHandler(**get_conn_params(info)) as conn:
                    conn.enable()
                    messages = restore_config(conn, folder, selected_files, info["name"], label)
                    results.append({'device': label, 'success': True, 'messages': messages})
            except Exception as e:
                logging.error(f"Restore failed for {label}: {e}")
                results.append({'device': label, 'success': False, 'message': f'Error: {str(e)}'})
        return jsonify({'results': results})
    except Exception as e:
        logging.error(f"Failed to restore devices: {e}")
        return jsonify({'error': f'Failed to restore devices: {str(e)}'}), 500


@app.route('/schedule_backup', methods=['POST'])
def schedule_backup():
    try:
        data = request.get_json()
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

        def job(device_list=selected_devices, sched_time=scheduled_datetime):
            now = datetime.now()
            if now >= sched_time:
                logging.info(f"[Scheduled Job Triggered at {now}]")
                perform_backup_for_devices(device_list)
                return schedule.CancelJob

        schedule.every(1).minutes.do(job)
        return jsonify({'success': True, 'message': f'Backup scheduled for {scheduled_datetime.strftime("%Y-%m-%d %I:%M %p")} for selected devices.'})
    except Exception as e:
        logging.error(f"Failed to schedule backup: {e}")
        return jsonify({'error': f'Failed to schedule backup: {str(e)}'}), 500

@app.route('/download_backup/<device_name>/<path:filename>')
def download_backup(device_name, filename):
    """Download a specific backup file"""
    try:
        backup_dir = os.path.join(RUNNING_CONFIG_FOLDER, device_name)

        if not os.path.exists(os.path.join(backup_dir, filename)):
            return abort(404, description="Backup file not found")

        return send_from_directory(
            backup_dir,
            filename,
            as_attachment=True,
            download_name=filename  # ✅ ensures filename is preserved
        )
    except Exception as e:
        logging.error(f"Download failed for {device_name}/{filename}: {e}")
        return "Error downloading file", 500

@app.route('/upload_config', methods=['POST'])
def upload_config():
    """Upload configuration files (including golden)"""
    try:
        if 'config_file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        file = request.files['config_file']
        config_type = request.form.get('config_type', 'backup')  # 'backup' or 'golden'
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        allowed = ('.cfg', '.cfg')
        if file and file.filename.endswith(allowed):
            filename = f"uploaded_{datetime.now():%Y%m%d_%H%M%S}_{file.filename}"
            # If golden, save to GOLDEN_CONFIG_FOLDER
            if config_type == 'golden':
                os.makedirs(GOLDEN_CONFIG_FOLDER, exist_ok=True)
                file_path = os.path.join(GOLDEN_CONFIG_FOLDER, filename)
            else:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                file.save(file_path)
            except Exception as e:
                logging.error(f"Failed to save uploaded file: {e}")
                return jsonify({'error': 'Failed to save file.'}), 500
            return jsonify({'success': True, 'message': f'File uploaded: {filename}'})
        return jsonify({'error': 'Only .cfg and .cfg files are allowed'}), 400
    except Exception as e:
        logging.error(f"Upload config failed: {e}")
        return jsonify({'error': f'Failed to upload config: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
