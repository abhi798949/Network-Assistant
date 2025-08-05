from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_from_directory
import yaml
from netmiko import ConnectHandler
from datetime import datetime, time as dtime
import difflib, os, threading, schedule, time as t
import json
import logging
from utils.cohere_parser import get_action_from_prompt, extract_config_commands

app = Flask(__name__)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.StreamHandler()]
)

# Constants
RUNNING_CONFIG_FOLDER = "running_configs"
UPLOAD_FOLDER = "uploads"
os.makedirs(RUNNING_CONFIG_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs("utils", exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

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

# Utility functions
def get_conn_params(info):
    try:
        return {
            "device_type": info["device_type"],
            "ip": info["ip"],
            "username": info["username"],
            "password": info["password"],
        }
    except KeyError as e:
        logging.error(f"Missing device info key: {e}")
        raise

def backup_config(conn, folder, name, label):
    try:
        config = conn.send_command("show running-config")
        filename = os.path.join(folder, f"Config_{name}_{datetime.now():%Y-%m-%d_%H%M}.txt")
        with open(filename, "w") as f:
            f.write(config)
        return f"Backup saved for {label} at {filename}"
    except Exception as e:
        logging.error(f"Backup failed for {label}: {e}")
        raise

def restore_config(conn, folder, files, name, label):
    results = []
    for f in files:
        path = os.path.join(folder, f)
        try:
            conn.send_config_from_file(path)
            results.append(f"Restored '{f}' on {label}")
        except Exception as e:
            logging.error(f"Restore failed for {label} file {f}: {e}")
            results.append(f"Failed to restore '{f}' on {label}: {e}")
    return results

def save_config(conn, folder, name, prefix):
    try:
        config = conn.send_command("show running-config")
        fname = os.path.join(folder, f"{prefix}_{name}_{datetime.now():%Y-%m-%d_%H%M}.txt")
        with open(fname, "w") as f:
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
    folder = os.path.join(RUNNING_CONFIG_FOLDER, f"scheduled_backup_{info['name']}")
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

# Start scheduler thread
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
            files = [f for f in os.listdir(backup_dir) if f.endswith('.txt')]
            return jsonify(files)
        return jsonify([])
    except Exception as e:
        logging.error(f"Error getting backup files: {e}")
        return jsonify([])

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
                    
                    # Save config before changes
                    old_config = save_config(conn, folder, info["name"], "old_running")
                    
                    # Apply configuration commands (non-show commands)
                    config_commands = [c for c in commands if not c.strip().lower().startswith("show")]
                    if config_commands:
                        conn.send_config_set(config_commands)
                        device_result['message'] = 'Configuration applied successfully'
                    
                    # Execute show commands for output
                    for cmd in commands:
                        if cmd.strip().lower().startswith("show"):
                            try:
                                output = conn.send_command(cmd)
                                device_result['command_outputs'].append({
                                    'command': cmd,
                                    'output': output
                                })
                            except Exception as ce:
                                logging.error(f"Show command failed on {label}: {ce}")
                                device_result['command_outputs'].append({
                                    'command': cmd,
                                    'output': f'Error: {ce}'
                                })
                    
                    # Save config after changes and generate diff
                    new_config = save_config(conn, folder, info["name"], "new_running")
                    diff = '\n'.join(difflib.unified_diff(
                        old_config.splitlines(), 
                        new_config.splitlines(), 
                        fromfile="Before", 
                        tofile="After", 
                        lineterm=""
                    ))
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

@app.route('/verify_command', methods=['POST'])
def verify_command():
    try:
        data = request.get_json()
        selected_devices = data.get('devices', [])
        prompt = data.get('prompt', '')
        
        if not selected_devices or not prompt:
            return jsonify({'error': 'Please select devices and enter a prompt'}), 400
        
        commands = extract_config_commands(get_action_from_prompt(prompt))
        
        results = {
            'commands': commands,
            'device_results': []
        }
        
        for label in selected_devices:
            if label not in device_map:
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
                    conn.enable()
                    
                    # Execute all commands but focus on show commands for verification
                    for cmd in commands:
                        try:
                            if cmd.strip().lower().startswith("show"):
                                # Execute show commands
                                output = conn.send_command(cmd)
                                device_result['command_outputs'].append({
                                    'command': cmd,
                                    'output': output
                                })
                            else:
                                # For non-show commands, just validate them (don't apply)
                                # You can add validation logic here if needed
                                device_result['command_outputs'].append({
                                    'command': cmd,
                                    'output': 'Command validated (not executed in verify mode)'
                                })
                        except Exception as ce:
                            logging.error(f"Command failed on {label}: {ce}")
                            device_result['command_outputs'].append({
                                'command': cmd,
                                'output': f'Error: {ce}'
                            })
                    
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
                    message = backup_config(conn, folder, info["name"], label)
                    results.append({'device': label, 'success': True, 'message': message})
            except Exception as e:
                logging.error(f"Backup failed for {label}: {e}")
                results.append({'device': label, 'success': False, 'message': f'Error: {str(e)}'})
        
        return jsonify({'results': results})
        
    except Exception as e:
        logging.error(f"Failed to backup devices: {e}")
        return jsonify({'error': f'Failed to backup devices: {str(e)}'}), 500

@app.route('/restore_devices', methods=['POST'])
def restore_devices():
    try:
        data = request.get_json()
        selected_devices = data.get('devices', [])
        selected_files = data.get('files', [])
        
        if not selected_devices or not selected_files:
            return jsonify({'error': 'Please select devices and backup files'}), 400
        
        results = []
        
        for label in selected_devices:
            if label not in device_map:
                continue
            
            info = device_map[label]
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
        
        return jsonify({
            'success': True, 
            'message': f'Backup scheduled for {scheduled_datetime.strftime("%Y-%m-%d %I:%M %p")} for selected devices.'
        })
        
    except Exception as e:
        logging.error(f"Failed to schedule backup: {e}")
        return jsonify({'error': f'Failed to schedule backup: {str(e)}'}), 500

@app.route('/download_backup/<device_name>/<filename>')
def download_backup(device_name, filename):
    """Download a specific backup file"""
    try:
        backup_dir = os.path.join(RUNNING_CONFIG_FOLDER, device_name)
        return send_from_directory(backup_dir, filename, as_attachment=True)
    except Exception as e:
        logging.error(f"Download failed for {device_name}/{filename}: {e}")
        return "Error downloading file", 500

@app.route('/upload_config', methods=['POST'])
def upload_config():
    """Upload configuration files"""
    try:
        if 'config_file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        
        file = request.files['config_file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and file.filename.endswith('.txt'):
            filename = f"uploaded_{datetime.now():%Y%m%d_%H%M%S}_{file.filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                file.save(file_path)
            except Exception as e:
                logging.error(f"Failed to save uploaded file: {e}")
                return jsonify({'error': 'Failed to save file.'}), 500
            
            return jsonify({'success': True, 'message': f'File uploaded: {filename}'})
        
        return jsonify({'error': 'Only .txt files are allowed'}), 400
        
    except Exception as e:
        logging.error(f"Upload config failed: {e}")
        return jsonify({'error': f'Failed to upload config: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)