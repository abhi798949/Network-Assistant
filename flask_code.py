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
import sys
import json
import logging
from matplotlib import lines
import requests
import threading
import schedule
import time
import re
from difflib import unified_diff
import shutil
import zipfile
import tempfile
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, flash, make_response
from werkzeug.utils import secure_filename
from netmiko import ConnectHandler, exceptions
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from pdf_generator import ConfigChangePDFGenerator
from dotenv import load_dotenv
import yaml
import paramiko
import signal
import sys

# RBAC imports (Date:22/10/2025)
from rbac import RoleManager, Permission, Role

pdf_generator = ConfigChangePDFGenerator()
# Local imports
from utils.cohere_parsere import get_action_from_prompt, extract_config_commands
try:
    from snmp_monitor1 import SNMPMonitor
except ImportError:
    logging.warning("SNMP monitoring not available - install pysnmp")
    SNMPMonitor = None
# GRAFANA IMPORTS
from grafana import create_comprehensive_dashboard

load_dotenv()


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)




# ---------------------------
# App & config
# ---------------------------

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # CHANGE for prod: os.urandom(24).hex()

app.snmp_monitoring_enabled = False


# RBAC configuration (Date:22/10/2025)
role_manager = RoleManager()


# InfluxDB config - change as needed or use env vars
INFLUX_CONFIG = {
    'url': 'http://localhost:8086',
    'token': 'iG4dfjTsr7gKAn9rc_wZxYU2G1wN0zsUrOq9kj-DoOMKS2BccIgMejpak4lnUaXbFyjRT_QR5mcv3VOyXu4lnQ==',  # Change this
    'org': 'vayu',
    'bucket': 'vayuDB1',
    'username': 'vayu',  # or 'vayu'
    'password': 'vayu@123',  # or 'vayu123'
}


def create_grafana_dashboards(grafana_url=None, api_key=None, bucket=None, max_retries=3, delay=5):
    """
    Create both comprehensive and interface dashboards with retry logic.
    """
    grafana_url = grafana_url or os.environ.get("GRAFANA_URL", "http://localhost:3000")
    api_key = api_key or os.environ.get("GRAFANA_API_KEY")
    bucket = bucket or INFLUX_CONFIG.get("bucket", "vayuDB1")

    if not api_key:
        logging.error("GRAFANA_API_KEY not set")
        return {"success": False, "error": "GRAFANA_API_KEY not set"}

    # Check Grafana connectivity
    for attempt in range(max_retries):
        try:
            health_response = requests.get(f"{grafana_url}/api/health", timeout=10)
            if health_response.status_code != 200:
                logging.warning(f"Grafana health check failed: HTTP {health_response.status_code}")
                if attempt < max_retries - 1:
                    time.sleep(delay)
                    continue
                return {"success": False, "error": f"Grafana not reachable: HTTP {health_response.status_code}"}

            # Ensure InfluxDB datasource
            datasource_uid = ensure_influxdb_datasource(grafana_url, api_key, INFLUX_CONFIG)
            if not datasource_uid:
                logging.error("Failed to get or create InfluxDB datasource")
                if attempt < max_retries - 1:
                    time.sleep(delay)
                    continue
                return {"success": False, "error": "Failed to configure InfluxDB datasource"}

            # Create dashboards
            results = []
            dashboard_urls = []
            
            try:
                # Dashboard 1
                result1 = create_comprehensive_dashboard(grafana_url, api_key, bucket)
                results.append({"name": "Comprehensive Dashboard", "result": result1})
                dashboard_urls.append(f"{grafana_url}/d/network-device-dashboard")
                logging.info(f"Comprehensive dashboard created: {result1}")
            except Exception as e:
                logging.error(f"Failed to create comprehensive dashboard: {e}")
                results.append({"name": "Comprehensive Dashboard", "error": str(e)})

            success = all("error" not in r for r in results)           
            return {
                "success": success,
                "results": results,
                "dashboard_urls": dashboard_urls
            }
        except Exception as e:
            logging.error(f"Dashboard creation attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
                continue
            return {"success": False, "error": f"Dashboard creation failed: {str(e)}"}

def ensure_influxdb_datasource(grafana_url, api_key, influx_config):
    """Ensure InfluxDB datasource exists in Grafana"""
    try:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        response = requests.get(f"{grafana_url}/api/datasources", headers=headers, timeout=15)
        response.raise_for_status()
        datasources = response.json()
        influx_datasources = [ds for ds in datasources if ds.get("type") == "influxdb"]
        
        if influx_datasources:
            logging.info(f"Found InfluxDB datasource: {influx_datasources[0]['name']}")
            return influx_datasources[0]["uid"]
        
        logging.info("Creating new InfluxDB datasource...")
        datasource_payload = {
            "name": "InfluxDB",
            "type": "influxdb",
            "url": influx_config['url'],
            "access": "proxy",
            "isDefault": True,
            "jsonData": {
                "version": "Flux",
                "organization": influx_config['org'],
                "defaultBucket": influx_config['bucket'],
                "httpMode": "POST"
            },
            "secureJsonData": {
                "token": influx_config['token']
            }
        }
        create_response = requests.post(
            f"{grafana_url}/api/datasources",
            headers=headers,
            json=datasource_payload,
            timeout=15
        )
        create_response.raise_for_status()
        result = create_response.json()
        logging.info(f"Created InfluxDB datasource with UID: {result.get('uid')}")
        return result.get("uid")
    except Exception as e:
        logging.error(f"Datasource creation failed: {e}")
        return None
    
# Initialize InfluxDB client
def init_influxdb():
    """Initialize InfluxDB client and ensure bucket exists"""
    global influx_client, write_api
    try:
        influx_client = InfluxDBClient(
            url=INFLUX_CONFIG['url'],
            token=INFLUX_CONFIG['token'],
            org=INFLUX_CONFIG['org']
        )
        write_api = influx_client.write_api(write_options=SYNCHRONOUS)
        
        # Ensure bucket exists
        buckets_api = influx_client.buckets_api()
        bucket = buckets_api.find_bucket_by_name(INFLUX_CONFIG['bucket'])
        if not bucket:
            buckets_api.create_bucket(bucket_name=INFLUX_CONFIG['bucket'], org=INFLUX_CONFIG['org'])
            logging.info(f"Created InfluxDB bucket: {INFLUX_CONFIG['bucket']}")
        logging.info("InfluxDB client initialized successfully")
    except Exception as e:
        logging.error(f"Failed to initialize InfluxDB client: {e}")
        influx_client = None
        write_api = None

# Call at startup
init_influxdb()

# ---- Grafana Helper Functions ----
def _grafana_root():
    """Get Grafana data directory path"""
    base = Path(__file__).parent
    return base / "tig-stack" / "data" / "grafana"

def _grafana_db_path():
    """Get Grafana database path"""
    return _grafana_root() / "grafana.db"

def _grafana_url():
    """Get Grafana URL from environment or default"""
    return os.environ.get("GRAFANA_URL", "http://localhost:3000")


# Flask-Login setup (app must exist before init)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"   # redirect to /login if not logged in

class User(UserMixin):
    def __init__(self, username):
        self.id = username
        rbac_user = role_manager.users.get(username)
        if rbac_user:
            self.roles = rbac_user.roles
        else:
            self.roles = []

@login_manager.user_loader
def load_user(username):
    if username in role_manager.users:
        return User(username)
    return None

# ---------------------------
# Base directories (per-device structure)
# ---------------------------
RUNNING_ROOT = "running_configs"   # running_configs/<device>/<date>/<files>
BACKUP_ROOT = "backups"            # backups/<device>/<files>
CURRENT_ROOT = "current_configs"   # current_configs/<device>/<files>
UPLOAD_FOLDER = "uploads"
GOLDEN_ROOT = "golden_configs"     # golden_configs/<device>/<files>
AUDIT_LOGS_ROOT = "audit_logs"  # audit_logs/<device>/<files>
os.makedirs(AUDIT_LOGS_ROOT, exist_ok=True)

# Ensure base dirs exist
for d in (RUNNING_ROOT, BACKUP_ROOT, CURRENT_ROOT, UPLOAD_FOLDER, GOLDEN_ROOT,AUDIT_LOGS_ROOT):
    os.makedirs(d, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {'txt', 'cfg', 'conf', 'zip'}


def collect_real_netconf_data(device_info):
    """
    Execute real NETCONF methods and collect actual device output
    Enhanced to support both IOS-XR and Juniper devices with proper alarm and config handling
    """
    collected_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "device": device_info.get('name', 'Unknown'),
        "ip": device_info.get('ip', 'Unknown'),
        "methods": {},
        "comprehensive_audit": {
            "data": {}  # Initialize the nested structure properly
        }
    }
    driver = None
    
    try:
        # Determine device type and use appropriate driver
        device_type = device_info.get('device_type', '').lower()
        
        if 'juniper' in device_type or 'junos' in device_type:
            if not JUNOS_DRIVER_AVAILABLE:
                logging.error("Juniper NETCONF driver not available")
                return {"error": "Juniper NETCONF driver not available"}
            
            logging.info(f"Using Juniper NETCONF driver for {device_info['ip']}")
            driver = JunosNetconfDriver(
                hostname=device_info['ip'],
                username=device_info['username'],
                password=device_info['password'],
                timeout=60,
                optional_args={
                    "port": device_info.get('port', 830),
                    "config_lock": False
                }
            )
        else:
            if not IOSXR_DRIVER_AVAILABLE:
                logging.error("IOS-XR NETCONF driver not available")
                return {"error": "IOS-XR NETCONF driver not available"}
            
            logging.info(f"Using IOS-XR NETCONF driver for {device_info['ip']}")
            driver = IOSXRNETCONFDriver(
                hostname=device_info['ip'],
                username=device_info['username'],
                password=device_info['password'],
                timeout=60,
                optional_args={
                    "port": device_info.get('port', 2022),
                    "config_lock": False
                }
            )
        
        driver.open()
        
        # List of methods to execute - COMPREHENSIVE LIST
        methods_to_execute = [
            {'name': 'get_facts', 'params': {}, 'description': 'Device Facts'},
            {'name': 'get_interfaces', 'params': {}, 'description': 'Interface Details'},
            {'name': 'get_interfaces_counters', 'params': {}, 'description': 'Interface Statistics'},
            {'name': 'get_interfaces_ip', 'params': {}, 'description': 'Interface IP Addresses'},
            {'name': 'get_bgp_neighbors', 'params': {}, 'description': 'BGP Neighbors'},
            {'name': 'get_lldp_neighbors', 'params': {}, 'description': 'LLDP Neighbors'},
            {'name': 'get_arp_table', 'params': {'vrf': ''}, 'description': 'ARP Table'},
            {'name': 'get_mac_address_table', 'params': {}, 'description': 'MAC Address Table'},
            {'name': 'get_ntp_peers', 'params': {}, 'description': 'NTP Peers'},
            {'name': 'get_ntp_servers', 'params': {}, 'description': 'NTP Servers'},
            {'name': 'get_ntp_stats', 'params': {}, 'description': 'NTP Statistics'},
            {'name': 'get_environment', 'params': {}, 'description': 'Environment Status'},
            {'name': 'get_users', 'params': {}, 'description': 'User Accounts'},
            {'name': 'get_snmp_information', 'params': {}, 'description': 'SNMP Information'},
            {'name': 'get_config', 'params': {'retrieve': 'running'}, 'description': 'Running Configuration'},
            {'name': 'get_alarms', 'params': {}, 'description': 'Active Alarms'},  # CRITICAL: Alarms
            {'name': 'get_optics', 'params': {}, 'description': 'Optical Transceiver Data'},
        ]
        
        # Only add XR-specific methods for XR devices
        if 'xr' in device_type:
            methods_to_execute.extend([
                {'name': 'get_bgp_config', 'params': {'group': '', 'neighbor': ''}, 'description': 'BGP Configuration'},
                {'name': 'get_lldp_neighbors_detail', 'params': {'interface': ''}, 'description': 'LLDP Neighbors Detail'},
            ])
        
        # Execute each method and store in BOTH locations
        audit_data = {}  # Direct storage for audit
        
        for method_info in methods_to_execute:
            method_name = method_info['name']
            params = method_info['params']
            description = method_info['description']
            
            try:
                logging.info(f"Executing NETCONF method: {method_name}")
                method = getattr(driver, method_name)
                result = method(**params)
                
                # Convert result to formatted string for methods dict
                import json
                if isinstance(result, dict):
                    result_str = json.dumps(result, indent=2, default=str)
                elif isinstance(result, list):
                    result_str = json.dumps(result, indent=2, default=str)
                else:
                    result_str = str(result)
                
                # Store in methods dict (for compatibility)
                collected_data['methods'][method_name] = {
                    'description': description,
                    'status': 'success',
                    'output': result_str,
                    'data': result
                }
                
                # CRITICAL: Also store directly in audit_data for formatting
                # Map method names to audit keys
                audit_key_map = {
                    'get_facts': 'facts',
                    'get_interfaces': 'interfaces',
                    'get_interfaces_counters': 'interface_counters',
                    'get_interfaces_ip': 'interfaces_ip',
                    'get_bgp_neighbors': 'bgp_neighbors',
                    'get_bgp_config': 'bgp_config',
                    'get_lldp_neighbors': 'lldp_neighbors',
                    'get_lldp_neighbors_detail': 'lldp_neighbors_detail',
                    'get_arp_table': 'arp_table',
                    'get_mac_address_table': 'mac_table',
                    'get_ntp_peers': 'ntp_peers',
                    'get_ntp_servers': 'ntp_servers',
                    'get_ntp_stats': 'ntp_stats',
                    'get_environment': 'environment',
                    'get_users': 'users',
                    'get_snmp_information': 'snmp_info',
                    'get_alarms': 'alarms',  # CRITICAL
                    'get_optics': 'optics',
                    
                }
                
                audit_key = audit_key_map.get(method_name)
                if audit_key:
                    audit_data[audit_key] = result
                    logging.info(f"✓ Stored {method_name} as {audit_key} in audit_data")
                
                # Special handling for running config
                if method_name == 'get_config' and result:
                    # Extract running config text
                    if isinstance(result, dict):
                        running_config = result.get('running', '')
                    else:
                        running_config = str(result)
                    
                    audit_data['running_config'] = {'running': running_config}
                    logging.info(f"✓ Successfully retrieved running configuration ({len(running_config)} characters)")
                    
                # Special handling for alarms - ensure they're stored
                if method_name == 'get_alarms':
                    if result and isinstance(result, list):
                        alarm_count = len(result)
                        logging.info(f" Successfully retrieved {alarm_count} alarms")
                        logging.info(f"   Alarms: {[a.get('description', 'N/A')[:50] for a in result[:3]]}")
                    else:
                        logging.warning(f"¸ get_alarms returned no data or wrong type: {type(result)}")
                
                # Special handling for alarms
                if method_name == 'get_alarms':
                    alarm_count = len(result) if isinstance(result, list) else 0
                    logging.info(f"✓ Successfully retrieved {alarm_count} alarms")
                
            except AttributeError as ae:
                logging.warning(f"Method {method_name} not available for this device type: {ae}")
                collected_data['methods'][method_name] = {
                    'description': description,
                    'status': 'not_available',
                    'error': f"Method not available: {str(ae)}",
                    'output': None
                }
            except Exception as method_err:
                logging.error(f"Error executing {method_name}: {method_err}")
                collected_data['methods'][method_name] = {
                    'description': description,
                    'status': 'error',
                    'error': str(method_err),
                    'output': None
                }
        
        # Store the comprehensive audit data
        collected_data['comprehensive_audit'] = {
            'description': 'Comprehensive Device Audit',
            'status': 'success',
            'data': audit_data  # This is the key structure
        }
        
        collected_data['netconf_port'] = driver.port
        
        logging.info(f"✓ Comprehensive audit complete. Collected {len(audit_data)} data sections")
        logging.info(f"Sections: {', '.join(audit_data.keys())}")
        
        driver.close()
        
    except Exception as conn_err:
        logging.error(f"NETCONF connection failed: {conn_err}")
        collected_data['error'] = str(conn_err)
    
    return collected_data

# NETCONF availability (Date: 23/10/2025)

def format_netconf_output_for_audit(netconf_data):
    """
    Format comprehensive NETCONF audit data into detailed structured report.
    Shows ALL data collected from the device.
    FIXED: All variables initialized at function start to prevent UnboundLocalError
    """
    lines = []
    
    # Header
    lines.append("")
    lines.append("!" * 80)
    lines.append("! COMPREHENSIVE NETWORK DEVICE AUDIT REPORT")
    lines.append("!" * 80)
    lines.append(f"! Generated:     {netconf_data.get('timestamp', 'Unknown')}")
    lines.append(f"! Device:        {netconf_data.get('device', 'Unknown')}")
    lines.append(f"! IP Address:    {netconf_data.get('ip', 'Unknown')}")
    lines.append(f"! NETCONF Port:  {netconf_data.get('netconf_port', 'Unknown')}")
    lines.append("!" * 80)
    lines.append("")
    
    # Get comprehensive audit data
    audit_data = netconf_data.get('comprehensive_audit', {}).get('data', {})
    
    if not audit_data:
        lines.append("! No comprehensive audit data available")
        return lines
    
    # ========================================================================
    # SECTION 1: DEVICE FACTS & INVENTORY
    # ========================================================================
    facts = audit_data.get('facts', {})
    
    if facts:
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 1: DEVICE FACTS & INVENTORY")
        lines.append("!" + "=" * 78)
        lines.append("!")
        lines.append(f"! Hostname:          {facts.get('hostname', 'N/A')}")
        lines.append(f"! Vendor:            {facts.get('vendor', 'N/A')}")
        lines.append(f"! Model:             {facts.get('model', 'N/A')}")
        lines.append(f"! OS Version:        {facts.get('os_version', 'N/A')}")
        lines.append(f"! Serial Number:     {facts.get('serial_number', 'N/A')}")
        lines.append(f"! FQDN:              {facts.get('fqdn', 'N/A')}")
        uptime_sec = facts.get('uptime', 0)
        uptime_days = uptime_sec / 86400 if uptime_sec > 0 else 0
        lines.append(f"! Uptime:            {uptime_sec} seconds ({uptime_days:.1f} days)")
        
        # Interface list - show all interfaces without truncation
        interface_list = facts.get('interface_list', [])
        lines.append(f"! Interface Count:   {len(interface_list)}")
        lines.append("!")
        if interface_list:
            lines.append("! Interface List:")
            for i, intf in enumerate(interface_list, 1):
                lines.append(f"!   {i:3}. {intf}")
        lines.append("")
    
    # ========================================================================
    # SECTION 2: RUNNING CONFIGURATION
    # ========================================================================
    running_config = netconf_data.get('methods', {}).get('get_config', {}).get('output', '')
    
    if running_config:
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 2: RUNNING CONFIGURATION")
        lines.append("!" + "=" * 78)
        lines.append("!")
        lines.append("! Current Running Configuration:")
        lines.append("!")
        
        # Add the running configuration line by line with proper formatting
        for line in running_config.split('\n'):
            lines.append(f"! {line}")
        lines.append("")
    
    # ========================================================================
    # SECTION 3: ACTIVE ALARMS
    # ========================================================================
    alarms = audit_data.get('alarms', [])

    lines.append("")
    lines.append("!" + "=" * 78)
    lines.append("! SECTION 3: ACTIVE ALARMS")
    lines.append("!" + "=" * 78)

    if alarms and isinstance(alarms, list) and len(alarms) > 0:
        lines.append(f"! Total Active Alarms: {len(alarms)}")
        lines.append("!")
        
        # Group alarms by severity
        severity_groups = {}
        for alarm in alarms:
            severity = alarm.get('severity', 'unknown')
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(alarm)
        
        # Display summary by severity
        lines.append("! Alarms by Severity:")
        for severity in ['critical', 'major', 'minor', 'warning', 'info']:
            count = len(severity_groups.get(severity, []))
            if count > 0:
                lines.append(f"!   {severity.upper():10} : {count:3} alarm(s)")
        lines.append("!")
        
        # Display detailed alarm information
        for idx, alarm in enumerate(alarms, 1):
            lines.append(f"! Alarm {idx}:")
            lines.append(f"!   Severity:     {alarm.get('severity', 'N/A')}")
            lines.append(f"!   Description:  {alarm.get('description', 'N/A')}")
            lines.append(f"!   Location:     {alarm.get('location', 'N/A')}")
            lines.append(f"!   Timestamp:    {alarm.get('timestamp', 'N/A')}")
            
            # Optional fields
            if 'group' in alarm and alarm['group']:
                lines.append(f"!   Group:        {alarm.get('group', 'N/A')}")
            if 'category' in alarm and alarm['category']:
                lines.append(f"!   Category:     {alarm.get('category', 'N/A')}")
            if 'aid' in alarm and alarm['aid']:
                lines.append(f"!   Alarm ID:     {alarm.get('aid', 'N/A')}")
            if 'service_affecting' in alarm and alarm['service_affecting']:
                lines.append(f"!   Service Affecting: {alarm.get('service_affecting', 'N/A')}")
            if 'condition_description' in alarm and alarm['condition_description']:
                lines.append(f"!   Condition:    {alarm.get('condition_description', 'N/A')}")
            
            lines.append("!")
    else:
        lines.append("! No active alarms - Device is healthy")
    lines.append("")

    # ========================================================================
    # SECTION 4: DETAILED INTERFACE INFORMATION
    # ========================================================================
    interfaces = audit_data.get('interfaces', {})
    
    if interfaces:
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 4: DETAILED INTERFACE INFORMATION")
        lines.append("!" + "=" * 78)
        lines.append(f"! Total Interfaces: {len(interfaces)}")
        
        up_count = sum(1 for i in interfaces.values() if i.get('is_up'))
        lines.append(f"! Up:               {up_count}")
        lines.append(f"! Down:             {len(interfaces) - up_count}")
        lines.append("!")
        
        for intf_name, intf_info in interfaces.items():
            is_up = intf_info.get('is_up', False)
            is_enabled = intf_info.get('is_enabled', False)
            status = "Up" if is_up else "Down"
            admin = "Enabled" if is_enabled else "Disabled"
            
            lines.append(f"!")
            lines.append(f"! Interface: {intf_name}")
            lines.append(f"!   Status:          {status}")
            lines.append(f"!   Admin State:     {admin}")
            lines.append(f"!   Speed:           {intf_info.get('speed', 'N/A')} Mbps")
            lines.append(f"!   MTU:             {intf_info.get('mtu', 'N/A')}")
            lines.append(f"!   MAC Address:     {intf_info.get('mac_address', 'N/A')}")
            lines.append(f"!   Description:     {intf_info.get('description', 'N/A')}")
            lines.append(f"!   Last Flapped:    {intf_info.get('last_flapped', 'N/A')}")
        lines.append("")
    
    # ========================================================================
    # SECTION 5: INTERFACE STATISTICS & COUNTERS
    # ========================================================================
    counters = audit_data.get('interface_counters', {})
    
    if counters:
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 5: INTERFACE STATISTICS & COUNTERS")
        lines.append("!" + "=" * 78)
        lines.append("!")
        
        for intf_name, stats in counters.items():
            lines.append(f"!")
            lines.append(f"! Interface: {intf_name}")
            lines.append(f"!   RX Packets:")
            lines.append(f"!     Unicast:       {stats.get('rx_unicast_packets', 'N/A'):>15,}")
            lines.append(f"!     Multicast:     {stats.get('rx_multicast_packets', 'N/A'):>15,}")
            lines.append(f"!     Broadcast:     {stats.get('rx_broadcast_packets', 'N/A'):>15,}")
            lines.append(f"!   TX Packets:")
            lines.append(f"!     Unicast:       {stats.get('tx_unicast_packets', 'N/A'):>15,}")
            lines.append(f"!     Multicast:     {stats.get('tx_multicast_packets', 'N/A'):>15,}")
            lines.append(f"!     Broadcast:     {stats.get('tx_broadcast_packets', 'N/A'):>15,}")
            lines.append(f"!   Octets:")
            lines.append(f"!     RX:            {stats.get('rx_octets', 'N/A'):>15,} bytes")
            lines.append(f"!     TX:            {stats.get('tx_octets', 'N/A'):>15,} bytes")
            lines.append(f"!   Errors:")
            lines.append(f"!     RX Errors:     {stats.get('rx_errors', 'N/A'):>15,}")
            lines.append(f"!     TX Errors:     {stats.get('tx_errors', 'N/A'):>15,}")
            lines.append(f"!     RX Discards:   {stats.get('rx_discards', 'N/A'):>15,}")
            lines.append(f"!     TX Discards:   {stats.get('tx_discards', 'N/A'):>15,}")
        lines.append("")
    
    # ========================================================================
    # SECTION 6: IP ADDRESS CONFIGURATION
    # ========================================================================
    interfaces_ip = audit_data.get('interfaces_ip', {})
    
    if interfaces_ip:
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 6: IP ADDRESS CONFIGURATION")
        lines.append("!" + "=" * 78)
        lines.append("!")
        
        for intf, ip_data in interfaces_ip.items():
            lines.append(f"!")
            lines.append(f"! Interface: {intf}")
            
            if 'ipv4' in ip_data:
                lines.append("!   IPv4 Addresses:")
                for ip, ip_info in ip_data['ipv4'].items():
                    prefix = ip_info.get('prefix_length', 'N/A')
                    lines.append(f"!     {ip}/{prefix}")
            
            if 'ipv6' in ip_data:
                lines.append("!   IPv6 Addresses:")
                for ip, ip_info in ip_data['ipv6'].items():
                    prefix = ip_info.get('prefix_length', 'N/A')
                    lines.append(f"!     {ip}/{prefix}")
        lines.append("")
        
    # ========================================================================
    # SECTION 7: OPTICAL TRANSCEIVER DATA
    # ========================================================================
    # CRITICAL FIX: Initialize optics_data at the start of this section
    optics_data = audit_data.get('optics', {})

    # ✅ FIX: Add type checking and validation
    if optics_data and isinstance(optics_data, dict):
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 7: OPTICAL TRANSCEIVER DATA")
        lines.append("!" + "=" * 78)
        
        # Count interfaces with actual optics installed - with safe type checking
        total_ports = len(optics_data)
        ports_with_optics = 0
        empty_ports = 0
        
        for port_name, info in optics_data.items():
            # ✅ FIX: Ensure info is a dict before calling .get()
            if isinstance(info, dict):
                if info.get('physical_present', False):
                    ports_with_optics += 1
                else:
                    empty_ports += 1
            else:
                # If info is not a dict (e.g., string error message), count as empty
                logging.warning(f"Optics data for {port_name} is not a dict: {type(info)}")
                empty_ports += 1
        
        lines.append(f"! Total Optical Ports:      {total_ports}")
        lines.append(f"! Ports with Optics:        {ports_with_optics}")
        lines.append(f"! Empty Ports:              {empty_ports}")
        lines.append("!")
        
        # Only show interfaces that have optics installed
        if ports_with_optics > 0:
            lines.append("! Showing only interfaces with installed optics modules")
            lines.append("!")
            
            for interface, optics_info in optics_data.items():
                # ✅ FIX: Skip non-dict entries
                if not isinstance(optics_info, dict):
                    logging.warning(f"Skipping {interface}: optics_info is {type(optics_info)}")
                    continue
                
                # Skip interfaces without optics
                if not optics_info.get('physical_present', False):
                    continue
                
                lines.append("!")
                lines.append(f"! Interface: {interface}")
                lines.append("!" + "-" * 78)
                
                # Controller State
                lines.append("!  Controller State: Up")
                lines.append("!  Transport Admin State: In Service")
                lines.append("!  Laser State: On")
                lines.append("!")
                
                # Optics Status Header
                lines.append("!  Optics Status")
                lines.append(f"!          Optics Type:  {optics_info.get('transceiver_type', 'N/A')}")
                
                # Wavelength (if available)
                wavelength = optics_info.get('wavelength', '')
                if wavelength:
                    lines.append(f"!          Wavelength = {wavelength} nm")
                
                lines.append("!")
                
                # Alarm Status
                lines.append("!          Alarm Status:")
                lines.append("!          -------------")
                alarms = optics_info.get('alarms', [])
                if alarms:
                    for alarm in alarms:
                        lines.append(f"!          {alarm}")
                else:
                    lines.append("!          Detected Alarms: None")
                
                lines.append("!")
                
                # LOS/LOL/Fault Status (if available)
                los_status = optics_info.get('los_status', '')
                if los_status:
                    lines.append(f"!          LOS/LOL/Fault Status: {los_status}")
                
                # Laser Bias Current - safely get nested dict
                laser_bias_data = optics_info.get('laser_bias_current', {})
                laser_bias = laser_bias_data.get('instant', 0) if isinstance(laser_bias_data, dict) else 0
                lines.append(f"!          Laser Bias Current = {laser_bias:.1f} mA")
                
                # Actual TX Power - safely get nested dict
                tx_power_data = optics_info.get('output_power', {})
                tx_power = tx_power_data.get('instant', 0) if isinstance(tx_power_data, dict) else 0
                lines.append(f"!          Actual TX Power = {tx_power:.2f} dBm")
                
                # RX Power - safely get nested dict
                rx_power_data = optics_info.get('input_power', {})
                rx_power = rx_power_data.get('instant', 0) if isinstance(rx_power_data, dict) else 0
                lines.append(f"!          RX Power = {rx_power:.2f} dBm")
                
                lines.append("!")
                
                # Performance Monitoring
                pm_status = optics_info.get('performance_monitoring', 'Disable')
                lines.append(f"!          Performance Monitoring: {pm_status}")
                
                lines.append("!")
                
                # Threshold Values Table
                lines.append("!          THRESHOLD VALUES")
                lines.append("!          ----------------")
                lines.append("!          Parameter                 High Alarm  Low Alarm  High Warning  Low Warning")
                lines.append("!          ------------------------  ----------  ---------  ------------  -----------")
                
                # RX Power Thresholds - safely get dict
                rx_thresholds = optics_info.get('rx_power_thresholds', {})
                if isinstance(rx_thresholds, dict):
                    lines.append(f"!          Rx Power Threshold(dBm)   {rx_thresholds.get('high_alarm', 2.0):9.1f}  "
                                f"{rx_thresholds.get('low_alarm', -13.9):9.1f}  "
                                f"{rx_thresholds.get('high_warning', -1.0):12.1f}  "
                                f"{rx_thresholds.get('low_warning', -9.9):11.1f}")
                
                # TX Power Thresholds - safely get dict
                tx_thresholds = optics_info.get('tx_power_thresholds', {})
                if isinstance(tx_thresholds, dict):
                    lines.append(f"!          Tx Power Threshold(dBm)   {tx_thresholds.get('high_alarm', 1.6):9.1f}  "
                                f"{tx_thresholds.get('low_alarm', -11.3):9.1f}  "
                                f"{tx_thresholds.get('high_warning', -1.3):12.1f}  "
                                f"{tx_thresholds.get('low_warning', -7.3):11.1f}")
                
                # LBC Thresholds - safely get dict
                lbc_thresholds = optics_info.get('lbc_thresholds', {})
                if isinstance(lbc_thresholds, dict):
                    lines.append(f"!          LBC Threshold(mA)         {lbc_thresholds.get('high_alarm', 10.50):9.2f}  "
                                f"{lbc_thresholds.get('low_alarm', 2.50):9.2f}  "
                                f"{lbc_thresholds.get('high_warning', 10.50):12.2f}  "
                                f"{lbc_thresholds.get('low_warning', 2.50):11.2f}")
                
                # Temperature Thresholds - safely get dict
                temp_thresholds = optics_info.get('temp_thresholds', {})
                if isinstance(temp_thresholds, dict):
                    lines.append(f"!          Temp. Threshold(celsius)  {temp_thresholds.get('high_alarm', 75.00):9.2f}  "
                                f"{temp_thresholds.get('low_alarm', -5.00):9.2f}  "
                                f"{temp_thresholds.get('high_warning', 70.00):12.2f}  "
                                f"{temp_thresholds.get('low_warning', 0.00):11.2f}")
                
                # Voltage Thresholds - safely get dict
                voltage_thresholds = optics_info.get('voltage_thresholds', {})
                if isinstance(voltage_thresholds, dict):
                    lines.append(f"!          Voltage Threshold(volt)   {voltage_thresholds.get('high_alarm', 3.63):9.2f}  "
                                f"{voltage_thresholds.get('low_alarm', 2.97):9.2f}  "
                                f"{voltage_thresholds.get('high_warning', 3.46):12.2f}  "
                                f"{voltage_thresholds.get('low_warning', 3.13):11.2f}")
                
                lines.append("!")
                
                # Polarization parameters
                lines.append("!          Polarization parameters not supported by optics")
                lines.append("!")
                
                # Temperature - safely get nested dict
                temperature_data = optics_info.get('temperature', {})
                temperature = temperature_data.get('instant', 0) if isinstance(temperature_data, dict) else 0
                lines.append(f"!          Temperature = {temperature:.2f} Celsius")
                
                # Voltage - safely get nested dict
                voltage_data = optics_info.get('voltage', {})
                voltage = voltage_data.get('instant', 0) if isinstance(voltage_data, dict) else 0
                lines.append(f"!          Voltage = {voltage:.2f} V")
                
                lines.append("!")
                
                # Transceiver Vendor Details
                lines.append("!  Transceiver Vendor Details")
                lines.append(f"!          Form Factor            : {optics_info.get('form_factor', 'SFP+')}")
                lines.append(f"!          Optics type            : {optics_info.get('transceiver_type', 'N/A')}")
                lines.append(f"!          Name                   : {optics_info.get('vendor_name', 'N/A')}")
                lines.append(f"!          OUI Number             : {optics_info.get('oui_number', 'N/A')}")
                lines.append(f"!          Part Number            : {optics_info.get('vendor_part', 'N/A')}")
                lines.append(f"!          Rev Number             : {optics_info.get('rev_number', 'N/A')}")
                lines.append(f"!          Serial Number          : {optics_info.get('vendor_serial', 'N/A')}")
                lines.append(f"!          PID                    : {optics_info.get('pid', 'N/A')}")
                lines.append(f"!          VID                    : {optics_info.get('vid', 'N/A')}")
                lines.append(f"!          Hardware Version       : {optics_info.get('hardware_version', '0.0')}")
                lines.append(f"!          Date Code(yy/mm/dd)    : {optics_info.get('date_code', 'N/A')}")
                lines.append("!")
            
            lines.append("")
        else:
            lines.append("! NOTE: All optical ports are empty (no modules installed)")
            lines.append("!")
            lines.append("! Empty Port Summary:")
            
            # List empty ports in a compact format
            empty_ports_list = [intf for intf, info in optics_data.items() 
                            if isinstance(info, dict) and not info.get('physical_present', False)]
            
            # Show first 10 empty ports
            for i, port in enumerate(empty_ports_list[:10], 1):
                lines.append(f"!   {i:2}. {port}")
            
            if len(empty_ports_list) > 10:
                lines.append(f"!   ... and {len(empty_ports_list) - 10} more empty ports")
            
            lines.append("")
    elif isinstance(optics_data, str):
        # If optics_data is a string (error message), display it
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 7: OPTICAL TRANSCEIVER DATA")
        lines.append("!" + "=" * 78)
        lines.append(f"! ERROR: {optics_data}")
        lines.append("")
    else:
        # No optics data at all
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 7: OPTICAL TRANSCEIVER DATA")
        lines.append("!" + "=" * 78)
        lines.append("! No optical transceiver data available")
        lines.append("")
    
    # ========================================================================
    # SECTION 8: HARDWARE & ENVIRONMENT STATUS
    # ========================================================================

    environment = audit_data.get('environment', {})

    lines.append("")
    lines.append("!" + "=" * 78)
    lines.append("! SECTION 8: HARDWARE & ENVIRONMENT STATUS")
    lines.append("!" + "=" * 78)

    

    # ============================
    # HARDWARE INVENTORY
    # ============================
    hw_data = environment.get('hardware', {})
    lines.append("!")
    lines.append("! HARDWARE INVENTORY")
    lines.append("! " + "=" * 76)
    
    if hw_data and isinstance(hw_data, dict) and len(hw_data) > 0:
        # Group hardware by type
        chassis = []
        modules = []
        line_cards = []
        power_modules = []
        fan_trays = []
        other = []
        
        for hw_name, hw_info in hw_data.items():
            if not isinstance(hw_info, dict):
                continue
                
            desc = hw_info.get('description', '').lower()
            model = hw_info.get('model', 'N/A')
            serial = hw_info.get('serial_number', 'N/A')
            hw_rev = hw_info.get('hw_revision', 'N/A')
            sw_rev = hw_info.get('sw_revision', 'N/A')
            
            hw_entry = {
                'name': hw_name,
                'model': model,
                'serial': serial,
                'hw_rev': hw_rev,
                'sw_rev': sw_rev,
                'desc': desc
            }
            
            # Categorize
            if 'chassis' in desc or 'rack' in hw_name.lower():
                chassis.append(hw_entry)
            elif 'line card' in desc or 'linecard' in desc:
                line_cards.append(hw_entry)
            elif 'power' in desc or 'psu' in desc or 'pem' in desc:
                power_modules.append(hw_entry)
            elif 'fan' in desc:
                fan_trays.append(hw_entry)
            elif 'module' in desc or 'card' in desc:
                modules.append(hw_entry)
            else:
                other.append(hw_entry)
        
        # Print Chassis
        if chassis:
            lines.append("!")
            lines.append("! CHASSIS")
            lines.append("! " + "-" * 76)
            for item in chassis:
                lines.append(f"! Component: {item['name']}")
                if item['model'] != 'N/A':
                    lines.append(f"!   Model:        {item['model']}")
                if item['serial'] != 'N/A':
                    lines.append(f"!   Serial:       {item['serial']}")
                if item['hw_rev'] != 'N/A':
                    lines.append(f"!   HW Revision:  {item['hw_rev']}")
                if item['sw_rev'] != 'N/A':
                    lines.append(f"!   SW Revision:  {item['sw_rev']}")
                if item['desc'] not in ['n/a', 'unknown', '']:
                    lines.append(f"!   Description:  {item['desc']}")
                lines.append("!")
        
        # Print Line Cards
        if line_cards:
            lines.append("!")
            lines.append("! LINE CARDS")
            lines.append("! " + "-" * 76)
            for item in line_cards:
                lines.append(f"! Component: {item['name']}")
                if item['model'] != 'N/A':
                    lines.append(f"!   Model:  {item['model']}")
                if item['serial'] != 'N/A':
                    lines.append(f"!   Serial: {item['serial']}")
                lines.append("!")
        
        # Print Modules (limit to 10)
        if modules:
            lines.append("!")
            lines.append("! MODULES & CARDS")
            lines.append("! " + "-" * 76)
            for item in modules[:10]:
                lines.append(f"! {item['name']:45} Model: {item['model']}")
            if len(modules) > 10:
                lines.append(f"! ... and {len(modules) - 10} more modules")
            lines.append("!")
        
        # Print Power Modules
        if power_modules:
            lines.append("!")
            lines.append("! POWER MODULES")
            lines.append("! " + "-" * 76)
            for item in power_modules:
                lines.append(f"! {item['name']:45} Model: {item['model']}")
            lines.append("!")
        
        # Print Fan Trays
        if fan_trays:
            lines.append("!")
            lines.append("! FAN TRAYS")
            lines.append("! " + "-" * 76)
            for item in fan_trays:
                lines.append(f"! {item['name']:45} Model: {item['model']}")
            lines.append("!")
        
        # Summary
        lines.append("!")
        lines.append("! HARDWARE SUMMARY")
        lines.append("! " + "-" * 76)
        lines.append(f"! Total Components:    {len(hw_data)}")
        lines.append(f"!   Chassis:           {len(chassis)}")
        lines.append(f"!   Line Cards:        {len(line_cards)}")
        lines.append(f"!   Modules:           {len(modules)}")
        lines.append(f"!   Power Modules:     {len(power_modules)}")
        lines.append(f"!   Fan Trays:         {len(fan_trays)}")
        lines.append(f"!   Other:             {len(other)}")
        lines.append("!")
    else:
        lines.append("! ⚠ No hardware inventory data available")
        lines.append("!")
    
    lines.append("")
        
    # ========================================================================
    # SECTION 9: BGP CONFIGURATION & NEIGHBORS
    # ========================================================================
    bgp_config = audit_data.get('bgp_config', {})
    bgp_neighbors = audit_data.get('bgp_neighbors', {})
    
    lines.append("")
    lines.append("!" + "=" * 78)
    lines.append("! SECTION 9: BGP CONFIGURATION & NEIGHBORS")
    lines.append("!" + "=" * 78)
    
    if bgp_neighbors:
        lines.append("!")
        lines.append("! BGP Neighbor Summary:")
        for vrf, vrf_data in bgp_neighbors.items():
            peers = vrf_data.get('peers', {})
            lines.append(f"!")
            lines.append(f"!   VRF: {vrf}")
            lines.append(f"!   Router ID:        {vrf_data.get('router_id', 'N/A')}")
            lines.append(f"!   Total Peers:      {len(peers)}")
            
            up_peers = sum(1 for p in peers.values() if p.get('is_up'))
            lines.append(f"!   Established:      {up_peers}")
            if up_peers < len(peers):
                lines.append(f"!   Down:             {len(peers) - up_peers}")
            
            # Detail each peer
            if peers:
                lines.append("!")
                lines.append(f"!   Peer Details for VRF {vrf}:")
                for peer_ip, peer_data in peers.items():
                    lines.append(f"!")
                    lines.append(f"!     Peer IP:          {peer_ip}")
                    lines.append(f"!     Remote AS:        {peer_data.get('remote_as', 'N/A')}")
                    lines.append(f"!     Local AS:         {peer_data.get('local_as', 'N/A')}")
                    lines.append(f"!     State:            {'Up' if peer_data.get('is_up') else 'Down'}")
                    lines.append(f"!     Uptime:           {peer_data.get('uptime', 0)} seconds")
                    lines.append(f"!     Description:      {peer_data.get('description', 'N/A')}")
                    
                    # Address family details
                    af_data = peer_data.get('address_family', {})
                    for af_name, af_info in af_data.items():
                        lines.append(f"!     Address Family:   {af_name}")
                        lines.append(f"!       Received:       {af_info.get('received_prefixes', 0)}")
                        lines.append(f"!       Accepted:       {af_info.get('accepted_prefixes', 0)}")
                        lines.append(f"!       Sent:           {af_info.get('sent_prefixes', 0)}")
    else:
        lines.append("! No BGP neighbors configured")
    
    lines.append("")
    
    # ========================================================================
    # SECTION 10: ROUTING TABLE INFORMATION
    # ========================================================================
    route_summary = audit_data.get('route_summary', {})
    default_routes = audit_data.get('default_routes', {})
    
    lines.append("")
    lines.append("!" + "=" * 78)
    lines.append("! SECTION 10: ROUTING TABLE INFORMATION")
    lines.append("!" + "=" * 78)
    
    if route_summary:
        lines.append("!")
        lines.append("! Route Summary:")
        for ip_version in ['ipv4', 'ipv6']:
            protocols = route_summary.get(ip_version, {})
            if protocols:
                lines.append(f"!   {ip_version.upper()}:")
                for protocol, count in protocols.items():
                    lines.append(f"!     {protocol:20} {count:6} routes")
    
    if default_routes:
        lines.append("!")
        lines.append("! Default Routes:")
        for dest, routes in default_routes.items():
            lines.append(f"!   Destination: {dest}")
            for route in routes[:5]:
                lines.append(f"!     Protocol:     {route.get('protocol', 'N/A')}")
                lines.append(f"!     Next Hop:     {route.get('next_hop', 'N/A')}")
                lines.append(f"!     Interface:    {route.get('outgoing_interface', 'N/A')}")
                lines.append(f"!     Preference:   {route.get('preference', 'N/A')}")
    
    lines.append("")
    
    # ========================================================================
    # SECTION 11: LLDP NEIGHBORS
    # ========================================================================
    lldp_neighbors = audit_data.get('lldp_neighbors', {})
    lldp_detail = audit_data.get('lldp_neighbors_detail', {})
    
    if lldp_neighbors or lldp_detail:
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 11: LLDP NEIGHBORS")
        lines.append("!" + "=" * 78)
        lines.append("!")
        
        # Use detailed info if available, otherwise basic
        neighbor_data = lldp_detail if lldp_detail else lldp_neighbors
        
        for intf_name, neighbors in neighbor_data.items():
            lines.append(f"!")
            lines.append(f"! Local Interface: {intf_name}")
            
            for neighbor in neighbors:
                if isinstance(neighbor, dict):
                    lines.append(f"!   Neighbor:")
                    lines.append(f"!     System Name:       {neighbor.get('remote_system_name', neighbor.get('hostname', 'N/A'))}")
                    lines.append(f"!     Chassis ID:        {neighbor.get('remote_chassis_id', 'N/A')}")
                    lines.append(f"!     Remote Port:       {neighbor.get('remote_port', neighbor.get('port', 'N/A'))}")
                    lines.append(f"!     Port Description:  {neighbor.get('remote_port_description', 'N/A')}")
                    lines.append(f"!     System Desc:       {neighbor.get('remote_system_description', 'N/A')}")
                    if 'remote_system_capab' in neighbor:
                        caps = ', '.join(neighbor.get('remote_system_capab', []))
                        lines.append(f"!     Capabilities:      {caps}")
        lines.append("")
    
    # ========================================================================
    # SECTION 12: ARP TABLE
    # ========================================================================
    arp_table = audit_data.get('arp_table', [])
    
    if arp_table:
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 12: ARP TABLE")
        lines.append("!" + "=" * 78)
        lines.append(f"! Total Entries: {len(arp_table)}")
        lines.append("!")
        lines.append("! IP Address          MAC Address        Interface              Age")
        lines.append("! " + "-" * 76)
        
        for entry in arp_table[:100]:  # Show first 100 entries
            ip = entry.get('ip', 'N/A')
            mac = entry.get('mac', 'N/A')
            intf = entry.get('interface', 'N/A')
            age = entry.get('age', 0)
            lines.append(f"! {ip:19} {mac:18} {intf:20} {age:6.1f}s")
        
        if len(arp_table) > 100:
            lines.append(f"! ... and {len(arp_table) - 100} more entries")
        lines.append("")
    
    # ========================================================================
    # SECTION 13: MAC ADDRESS TABLE
    # ========================================================================
    mac_table = audit_data.get('mac_table', [])
    
    if mac_table:
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 13: MAC ADDRESS TABLE")
        lines.append("!" + "=" * 78)
        lines.append(f"! Total Entries: {len(mac_table)}")
        lines.append("!")
        lines.append("! MAC Address        VLAN   Interface              Static  Active")
        lines.append("! " + "-" * 76)
        
        for entry in mac_table[:100]:
            mac = entry.get('mac', 'N/A')
            vlan = entry.get('vlan', 0)
            intf = entry.get('interface', 'N/A')
            static = 'Yes' if entry.get('static') else 'No'
            active = 'Yes' if entry.get('active') else 'No'
            lines.append(f"! {mac:18} {vlan:6} {intf:20} {static:6} {active:6}")
        
        if len(mac_table) > 100:
            lines.append(f"! ... and {len(mac_table) - 100} more entries")
        lines.append("")
    
    # ========================================================================
    # SECTION 14: NTP CONFIGURATION & STATUS
    # ========================================================================
    ntp_peers = audit_data.get('ntp_peers', {})
    ntp_servers = audit_data.get('ntp_servers', {})
    ntp_stats = audit_data.get('ntp_stats', [])
    
    if ntp_peers or ntp_servers or ntp_stats:
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 14: NTP CONFIGURATION & STATUS")
        lines.append("!" + "=" * 78)
        
        if ntp_peers:
            lines.append("!")
            lines.append("! NTP Peers:")
            for peer in ntp_peers.keys():
                lines.append(f"!   {peer}")
        
        if ntp_servers:
            lines.append("!")
            lines.append("! NTP Servers:")
            for server in ntp_servers.keys():
                lines.append(f"!   {server}")
        
        if ntp_stats:
            lines.append("!")
            lines.append("! NTP Statistics:")
            for stat in ntp_stats:
                lines.append(f"!")
                lines.append(f"!   Remote:         {stat.get('remote', 'N/A')}")
                lines.append(f"!     Synchronized: {stat.get('synchronized', False)}")
                lines.append(f"!     Reference ID: {stat.get('referenceid', 'N/A')}")
                lines.append(f"!     Stratum:      {stat.get('stratum', 'N/A')}")
                lines.append(f"!     Type:         {stat.get('type', 'N/A')}")
                lines.append(f"!     Delay:        {stat.get('delay', 'N/A')} ms")
                lines.append(f"!     Offset:       {stat.get('offset', 'N/A')} ms")
                lines.append(f"!     Jitter:       {stat.get('jitter', 'N/A')} ms")
        lines.append("")
    
    # ========================================================================
    # SECTION 15: USER ACCOUNTS
    # ========================================================================
    users = audit_data.get('users', {})
    
    if users:
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 15: USER ACCOUNTS")
        lines.append("!" + "=" * 78)
        lines.append(f"! Total Users: {len(users)}")
        lines.append("!")
        
        for username, user_data in users.items():
            lines.append(f"! User: {username}")
            lines.append(f"!   Privilege Level: {user_data.get('level', 'N/A')}")
            # Don't show passwords for security
        lines.append("")
    
    # ========================================================================
    # SECTION 16: SNMP CONFIGURATION
    # ========================================================================
    snmp_info = audit_data.get('snmp_info', {})
    
    if snmp_info:
        lines.append("")
        lines.append("!" + "=" * 78)
        lines.append("! SECTION 17: SNMP CONFIGURATION")
        lines.append("!" + "=" * 78)
        lines.append("!")
        lines.append(f"! Chassis ID:  {snmp_info.get('chassis_id', 'N/A')}")
        lines.append(f"! Contact:     {snmp_info.get('contact', 'N/A')}")
        lines.append(f"! Location:    {snmp_info.get('location', 'N/A')}")
        
        communities = snmp_info.get('community', {})
        if communities:
            lines.append("!")
            lines.append("! Communities:")
            for comm_name, comm_data in communities.items():
                mode = comm_data.get('mode', 'N/A')
                acl = comm_data.get('acl', 'none')
                lines.append(f"!   {comm_name:20} Mode: {mode:5} ACL: {acl}")
        lines.append("")
    
    # Footer
    lines.append("")
    lines.append("!" * 80)
    lines.append("! END OF COMPREHENSIVE AUDIT REPORT")
    lines.append("!" * 80)
    
    return lines

    


# Modified collect_real_netconf_data function to support Juniper devices

def collect_real_netconf_data(device_info):
    """
    Execute real NETCONF methods and collect actual device output
    Enhanced to support both IOS-XR and Juniper devices with proper alarm and config handling
    """
    collected_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "device": device_info.get('name', 'Unknown'),
        "ip": device_info.get('ip', 'Unknown'),
        "methods": {}
    }
    
    try:
        # Determine device type and use appropriate driver
        device_type = device_info.get('device_type', '').lower()
        
        if 'juniper' in device_type or 'junos' in device_type:
            # Use Juniper NETCONF driver
            if not JUNOS_DRIVER_AVAILABLE:
                logging.error("Juniper NETCONF driver not available")
                return {"error": "Juniper NETCONF driver not available"}
            
            logging.info(f"Using Juniper NETCONF driver for {device_info['ip']}")
            driver = JunosNetconfDriver(
                hostname=device_info['ip'],
                username=device_info['username'],
                password=device_info['password'],
                timeout=60,
                optional_args={
                    "port": device_info.get('port', 830),
                    "config_lock": False
                }
            )
        else:
            # Use IOS-XR NETCONF driver
            if not IOSXR_DRIVER_AVAILABLE:
                logging.error("IOS-XR NETCONF driver not available")
                return {"error": "IOS-XR NETCONF driver not available"}
            
            logging.info(f"Using IOS-XR NETCONF driver for {device_info['ip']}")
            driver = IOSXRNETCONFDriver(
                hostname=device_info['ip'],
                username=device_info['username'],
                password=device_info['password'],
                timeout=60,
                optional_args={
                    "port": device_info.get('port', 2022),
                    "config_lock": False
                }
            )
        
        driver.open()
        
        # List of methods to execute with their parameters
        if 'juniper' in device_type or 'junos' in device_type:
            # Juniper-specific methods
            methods_to_execute = [
                {
                    'name': 'get_facts',
                    'params': {},
                    'description': 'Device Facts'
                },
                {
                    'name': 'get_interfaces',
                    'params': {},
                    'description': 'Interface Details'
                },
                {
                    'name': 'get_interfaces_counters',
                    'params': {},
                    'description': 'Interface Statistics'
                },
                {
                    'name': 'get_interfaces_ip',
                    'params': {},
                    'description': 'Interface IP Addresses'
                },
                {
                    'name': 'get_bgp_neighbors',
                    'params': {},
                    'description': 'BGP Neighbors'
                },
                {
                    'name': 'get_lldp_neighbors',
                    'params': {},
                    'description': 'LLDP Neighbors'
                },
                {
                    'name': 'get_arp_table',
                    'params': {},
                    'description': 'ARP Table'
                },
                {
                    'name': 'get_mac_address_table',
                    'params': {},
                    'description': 'MAC Address Table'
                },
                {
                    'name': 'get_ntp_peers',
                    'params': {},
                    'description': 'NTP Peers'
                },
                {
                    'name': 'get_ntp_servers',
                    'params': {},
                    'description': 'NTP Servers'
                },
                {
                    'name': 'get_environment',
                    'params': {},
                    'description': 'Environment Status'
                },
                {
                    'name': 'get_users',
                    'params': {},
                    'description': 'User Accounts'
                },
                {
                    'name': 'get_snmp_information',
                    'params': {},
                    'description': 'SNMP Information'
                },
                {
                    'name': 'get_config',
                    'params': {'retrieve': 'running'},
                    'description': 'Running Configuration'
                },
                # Add Juniper-specific alarm method if available
                {
                    'name': 'get_alarms',
                    'params': {},
                    'description': 'Active Alarms'
                },
            ]
        else:
            # IOS-XR methods - include get_alarms
            methods_to_execute = [
                {
                    'name': 'get_facts',
                    'params': {},
                    'description': 'Device Facts'
                },
                {
                    'name': 'get_interfaces',
                    'params': {},
                    'description': 'Interface Details'
                },
                {
                    'name': 'get_interfaces_counters',
                    'params': {},
                    'description': 'Interface Statistics'
                },
                {
                    'name': 'get_interfaces_ip',
                    'params': {},
                    'description': 'Interface IP Addresses'
                },
                {
                    'name': 'get_bgp_neighbors',
                    'params': {},
                    'description': 'BGP Neighbors'
                },
                {
                    'name': 'get_bgp_config',
                    'params': {'group': '', 'neighbor': ''},
                    'description': 'BGP Configuration'
                },
                {
                    'name': 'get_lldp_neighbors',
                    'params': {},
                    'description': 'LLDP Neighbors'
                },
                {
                    'name': 'get_lldp_neighbors_detail',
                    'params': {'interface': ''},
                    'description': 'LLDP Neighbors Detail'
                },
                {
                    'name': 'get_arp_table',
                    'params': {'vrf': ''},
                    'description': 'ARP Table'
                },
                {
                    'name': 'get_mac_address_table',
                    'params': {},
                    'description': 'MAC Address Table'
                },
                {
                    'name': 'get_ntp_peers',
                    'params': {},
                    'description': 'NTP Peers'
                },
                {
                    'name': 'get_ntp_servers',
                    'params': {},
                    'description': 'NTP Servers'
                },
                {
                    'name': 'get_ntp_stats',
                    'params': {},
                    'description': 'NTP Statistics'
                },
                {
                    'name': 'get_environment',
                    'params': {},
                    'description': 'Environment Status'
                },
                {
                    'name': 'get_users',
                    'params': {},
                    'description': 'User Accounts'
                },
                {
                    'name': 'get_snmp_information',
                    'params': {},
                    'description': 'SNMP Information'
                },
                {
                    'name': 'get_config',
                    'params': {'retrieve': 'running'},
                    'description': 'Running Configuration'
                },
                # Add alarms method for IOS-XR
                {
                    'name': 'get_alarms',
                    'params': {},
                    'description': 'Alarms status'
                },
            ]
        
        # Execute each method
        for method_info in methods_to_execute:
            method_name = method_info['name']
            params = method_info['params']
            description = method_info['description']
            
            try:
                logging.info(f"Executing NETCONF method: {method_name}")
                method = getattr(driver, method_name)
                result = method(**params)
                
                # Convert result to formatted string
                import json
                if isinstance(result, dict):
                    result_str = json.dumps(result, indent=2, default=str)
                elif isinstance(result, list):
                    result_str = json.dumps(result, indent=2, default=str)
                else:
                    result_str = str(result)
                
                collected_data['methods'][method_name] = {
                    'description': description,
                    'status': 'success',
                    'output': result_str,
                    'data': result
                }
                
                # Special handling for running config to ensure it's captured
                if method_name == 'get_config' and result:
                    logging.info(f"Successfully retrieved running configuration ({len(str(result))} characters)")
                
                # Special handling for alarms
                if method_name == 'get_alarms' and result:
                    logging.info(f"Successfully retrieved {len(result) if isinstance(result, list) else 1} alarms")
                
            except AttributeError as ae:
                # Method doesn't exist for this device type
                logging.warning(f"Method {method_name} not available for this device type: {ae}")
                collected_data['methods'][method_name] = {
                    'description': description,
                    'status': 'not_available',
                    'error': f"Method not available: {str(ae)}",
                    'output': None
                }
            except Exception as method_err:
                logging.error(f"Error executing {method_name}: {method_err}")
                collected_data['methods'][method_name] = {
                    'description': description,
                    'status': 'error',
                    'error': str(method_err),
                    'output': None
                }
        
        # Create comprehensive audit data from individual methods
        logging.info("Creating comprehensive audit from collected methods...")
        audit_data = {}
        
        # Collect data from individual methods
        if 'get_facts' in collected_data['methods'] and collected_data['methods']['get_facts']['status'] == 'success':
            audit_data['facts'] = collected_data['methods']['get_facts']['data']
        
        if 'get_interfaces' in collected_data['methods'] and collected_data['methods']['get_interfaces']['status'] == 'success':
            audit_data['interfaces'] = collected_data['methods']['get_interfaces']['data']
        
        if 'get_interfaces_counters' in collected_data['methods'] and collected_data['methods']['get_interfaces_counters']['status'] == 'success':
            audit_data['interface_counters'] = collected_data['methods']['get_interfaces_counters']['data']
        
        if 'get_interfaces_ip' in collected_data['methods'] and collected_data['methods']['get_interfaces_ip']['status'] == 'success':
            audit_data['interfaces_ip'] = collected_data['methods']['get_interfaces_ip']['data']
        
        if 'get_bgp_neighbors' in collected_data['methods'] and collected_data['methods']['get_bgp_neighbors']['status'] == 'success':
            audit_data['bgp_neighbors'] = collected_data['methods']['get_bgp_neighbors']['data']
        
        if 'get_lldp_neighbors' in collected_data['methods'] and collected_data['methods']['get_lldp_neighbors']['status'] == 'success':
            audit_data['lldp_neighbors'] = collected_data['methods']['get_lldp_neighbors']['data']
        
        if 'get_arp_table' in collected_data['methods'] and collected_data['methods']['get_arp_table']['status'] == 'success':
            audit_data['arp_table'] = collected_data['methods']['get_arp_table']['data']
        
        if 'get_mac_address_table' in collected_data['methods'] and collected_data['methods']['get_mac_address_table']['status'] == 'success':
            audit_data['mac_table'] = collected_data['methods']['get_mac_address_table']['data']
        
        if 'get_ntp_peers' in collected_data['methods'] and collected_data['methods']['get_ntp_peers']['status'] == 'success':
            audit_data['ntp_peers'] = collected_data['methods']['get_ntp_peers']['data']
        
        if 'get_ntp_servers' in collected_data['methods'] and collected_data['methods']['get_ntp_servers']['status'] == 'success':
            audit_data['ntp_servers'] = collected_data['methods']['get_ntp_servers']['data']
        
        if 'get_environment' in collected_data['methods'] and collected_data['methods']['get_environment']['status'] == 'success':
            audit_data['environment'] = collected_data['methods']['get_environment']['data']
        
        if 'get_users' in collected_data['methods'] and collected_data['methods']['get_users']['status'] == 'success':
            audit_data['users'] = collected_data['methods']['get_users']['data']
        
        if 'get_snmp_information' in collected_data['methods'] and collected_data['methods']['get_snmp_information']['status'] == 'success':
            audit_data['snmp_info'] = collected_data['methods']['get_snmp_information']['data']
        
        # Add alarms if available
        if 'get_alarms' in collected_data['methods'] and collected_data['methods']['get_alarms']['status'] == 'success':
            audit_data['alarms'] = collected_data['methods']['get_alarms']['data']
            logging.info(f"Added {len(audit_data['alarms']) if isinstance(audit_data['alarms'], list) else 1} alarms to audit data")
        else:
            # Try to get alarms from environment or other sources
            if 'environment' in audit_data and 'alarms' in audit_data['environment']:
                audit_data['alarms'] = audit_data['environment']['alarms']
        
        collected_data['comprehensive_audit'] = {
            'description': 'Comprehensive Device Audit',
            'status': 'success',
            'data': audit_data
        }
        
        collected_data['netconf_port'] = driver.port  # Record successful port
        
        driver.close()
        
    except Exception as conn_err:
        logging.error(f"NETCONF connection failed: {conn_err}")
        collected_data['error'] = str(conn_err)
    
    return collected_data


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
def filter_mode_commands(commands, device_type=""):
    """Filter out mode-change commands that Netmiko handles automatically."""
    filtered = []
    mode_commands = {'configure', 'configure terminal', 'conf t', 'config t',
                     'enable', 'exit', 'end', 'commit', 'abort'}
    
    for cmd in commands:
        cmd_clean = cmd.strip().lower()
        if not cmd_clean or cmd_clean.startswith('!') or cmd_clean.startswith('#'):
            continue
        if cmd_clean in mode_commands:
            logging.debug(f"Filtering out mode command: {cmd_clean}")
            continue
        if "xr" in device_type.lower() and cmd_clean in ['configure', 'commit']:
            continue
        filtered.append(cmd.strip())
    return filtered

def validate_xr_commands(commands):
    """Validate and clean XR commands."""
    cleaned = []
    for cmd in commands:
        cmd = cmd.strip()
        if not cmd:
            continue
        if cmd.lower() in ['configure', 'configure terminal', 'commit', 'end', 'exit', 'abort']:
            continue
        if cmd.lower().startswith('conf t'):
            cmd = cmd[6:].strip()
        if cmd:
            cleaned.append(cmd)
    return cleaned
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
    Return the config text (string) with timestamps filtered out for cleaner diffs.
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

    # Save the raw config to file
    date_folder = datetime.now().strftime("%Y%m%d")
    device_folder = os.path.join(RUNNING_ROOT, device_name, date_folder)
    os.makedirs(device_folder, exist_ok=True)
    fname = os.path.join(device_folder, f"{prefix}_{device_name}_{timestamp_now()}.cfg")
    try:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(out)
    except Exception as e:
        logging.error(f"Failed to write running config file {fname}: {e}")
    
    # Return filtered config for diff (remove timestamp lines)
    return filter_config_for_diff(out, dev_type)
def filter_config_for_diff(config_text, device_type=""):
    """
    Filter out timestamp and dynamic lines from config to get cleaner diffs.
    Returns filtered config text.
    """
    if not config_text:
        return ""
    
    lines = config_text.splitlines()
    filtered = []
    
    # Patterns to skip (timestamps, build info, etc.)
    skip_patterns = [
        r'^\s*!!\s*Last configuration change at',  # XR double-bang format - MOST IMPORTANT
        r'^\s*!\s*Last configuration change at',   # IOS/XR single-bang format
        r'^\s*Building configuration',              # Building config message
        r'^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+',   # Date lines (Wed Oct 8...)
        r'^\s*!\s*NVRAM config last updated',      # IOS NVRAM timestamp
        r'^\s*!\s*Time:',                           # Various time stamps
        r'^\d{2}:\d{2}:\d{2}\.\d{3}\s+[A-Z]{3}',   # Time with timezone (08:32:08.095 UTC)
        r'^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}',  # Full timestamp
    ]
    
    for line in lines:
        # Check if line matches any skip pattern
        skip_line = False
        for pattern in skip_patterns:
            if re.match(pattern, line.strip()):
                skip_line = True
                break
        
        if not skip_line:
            filtered.append(line)
    
    # Log the filtering results
    removed = len(lines) - len(filtered)
    if removed > 0:
        logging.debug(f"Filtered config: removed {removed} timestamp/header lines")
    
    return '\n'.join(filtered)

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
        return "No differences found."
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
        time.sleep(60)

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
# Add this to your flask_code3.py file

# Enhanced NETCONF Manager with comprehensive data collection
class NetconfAuditCollector:
    """Collects comprehensive device data via NETCONF for audit logs"""
    
    @staticmethod
    def collect_all_device_data(device_info):
        """
        Collect all available NETCONF data for a device
        Returns dict with all collected information
        """
        if not NETCONF_AVAILABLE:
            return {"error": "NETCONF not available"}
        
        driver = None
        collected_data = {
            "device_info": device_info,
            "facts": None,
            "interfaces": None,
            "interface_counters": None,
            "bgp_neighbors": None,
            "bgp_config": None,
            "environment": None,
            "arp_table": None,
            "mac_table": None,
            "lldp_neighbors": None,
            "ntp_peers": None,
            "ntp_servers": None,
            "ntp_stats": None,
            "users": None,
            "snmp_info": None,
            "interfaces_ip": None,
            "running_config": None,
            "errors": []
        }
        
        try:
            driver = IOSXRNETCONFDriver(
                hostname=device_info['ip'],
                username=device_info['username'],
                password=device_info['password'],
                timeout=60,
                optional_args={
                    "port": device_info.get('port', 2022),
                    "config_lock": False
                }
            )
            driver.open()
            
            # Collect each type of data with error handling
            methods_to_collect = [
                ('facts', driver.get_facts),
                ('interfaces', driver.get_interfaces),
                ('interface_counters', driver.get_interfaces_counters),
                ('bgp_neighbors', driver.get_bgp_neighbors),
                ('bgp_config', lambda: driver.get_bgp_config()),
                ('environment', driver.get_environment),
                ('arp_table', driver.get_arp_table),
                ('mac_table', driver.get_mac_address_table),
                ('lldp_neighbors', driver.get_lldp_neighbors),
                ('ntp_peers', driver.get_ntp_peers),
                ('ntp_servers', driver.get_ntp_servers),
                ('ntp_stats', driver.get_ntp_stats),
                ('users', driver.get_users),
                ('snmp_info', driver.get_snmp_information),
                ('interfaces_ip', driver.get_interfaces_ip),
                ('running_config', lambda: driver.get_config(retrieve='running', format='text'))
            ]
            
            for data_key, method in methods_to_collect:
                try:
                    collected_data[data_key] = method()
                    logging.info(f"Collected {data_key} for {device_info.get('name')}")
                except Exception as e:
                    error_msg = f"Failed to collect {data_key}: {str(e)}"
                    collected_data['errors'].append(error_msg)
                    logging.error(error_msg)
            
            return collected_data
            
        except Exception as e:
            collected_data['errors'].append(f"Driver connection failed: {str(e)}")
            logging.error(f"NETCONF connection failed for {device_info.get('name')}: {e}")
            return collected_data
        finally:
            if driver:
                try:
                    driver.close()
                except:
                    pass


def format_netconf_data_as_config(data):
    """
    Format collected NETCONF data as a readable .cfg file
    """
    lines = []
    
    # Header
    lines.append("!" * 80)
    lines.append("! COMPREHENSIVE DEVICE AUDIT REPORT")
    lines.append("! Generated via IOSXR NETCONF Driver")
    lines.append("!" * 80)
    lines.append(f"! Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("!" * 80)
    lines.append("")
    
    # Device Facts
    if data.get('facts'):
        lines.append("!" + "=" * 78)
        lines.append("! DEVICE FACTS")
        lines.append("!" + "=" * 78)
        facts = data['facts']
        lines.append(f"! Vendor:         {facts.get('vendor', 'N/A')}")
        lines.append(f"! Hostname:       {facts.get('hostname', 'N/A')}")
        lines.append(f"! Model:          {facts.get('model', 'N/A')}")
        lines.append(f"! OS Version:     {facts.get('os_version', 'N/A')}")
        lines.append(f"! Serial Number:  {facts.get('serial_number', 'N/A')}")
        lines.append(f"! Uptime:         {facts.get('uptime', 'N/A')} seconds")
        lines.append(f"! FQDN:           {facts.get('fqdn', 'N/A')}")
        lines.append(f"! Interface List: {', '.join(facts.get('interface_list', []))}")
        lines.append("")
    
    # Interfaces
    if data.get('interfaces'):
        lines.append("!" + "=" * 78)
        lines.append("! INTERFACE DETAILS")
        lines.append("!" + "=" * 78)
        for intf_name, intf_data in data['interfaces'].items():
            lines.append(f"!")
            lines.append(f"! Interface: {intf_name}")
            lines.append(f"!   Status:       {'Up' if intf_data.get('is_up') else 'Down'}")
            lines.append(f"!   Enabled:      {intf_data.get('is_enabled', False)}")
            lines.append(f"!   Speed:        {intf_data.get('speed', 'N/A')} Mbps")
            lines.append(f"!   MTU:          {intf_data.get('mtu', 'N/A')}")
            lines.append(f"!   MAC Address:  {intf_data.get('mac_address', 'N/A')}")
            lines.append(f"!   Description:  {intf_data.get('description', 'N/A')}")
        lines.append("")
    
    # Interface Counters
    if data.get('interface_counters'):
        lines.append("!" + "=" * 78)
        lines.append("! INTERFACE STATISTICS")
        lines.append("!" + "=" * 78)
        for intf_name, counters in data['interface_counters'].items():
            lines.append(f"!")
            lines.append(f"! Interface: {intf_name}")
            lines.append(f"!   RX Packets:   {counters.get('rx_unicast_packets', 'N/A')}")
            lines.append(f"!   TX Packets:   {counters.get('tx_unicast_packets', 'N/A')}")
            lines.append(f"!   RX Bytes:     {counters.get('rx_octets', 'N/A')}")
            lines.append(f"!   TX Bytes:     {counters.get('tx_octets', 'N/A')}")
            lines.append(f"!   RX Errors:    {counters.get('rx_errors', 'N/A')}")
            lines.append(f"!   TX Errors:    {counters.get('tx_errors', 'N/A')}")
            lines.append(f"!   RX Discards:  {counters.get('rx_discards', 'N/A')}")
            lines.append(f"!   TX Discards:  {counters.get('tx_discards', 'N/A')}")
        lines.append("")
    
    # BGP Neighbors
    if data.get('bgp_neighbors'):
        lines.append("!" + "=" * 78)
        lines.append("! BGP NEIGHBORS")
        lines.append("!" + "=" * 78)
        for vrf, vrf_data in data['bgp_neighbors'].items():
            lines.append(f"!")
            lines.append(f"! VRF: {vrf}")
            lines.append(f"!   Router ID: {vrf_data.get('router_id', 'N/A')}")
            for peer_ip, peer_data in vrf_data.get('peers', {}).items():
                lines.append(f"!")
                lines.append(f"!   Peer: {peer_ip}")
                lines.append(f"!     Remote AS:    {peer_data.get('remote_as', 'N/A')}")
                lines.append(f"!     Local AS:     {peer_data.get('local_as', 'N/A')}")
                lines.append(f"!     State:        {'Up' if peer_data.get('is_up') else 'Down'}")
                lines.append(f"!     Uptime:       {peer_data.get('uptime', 'N/A')} seconds")
                lines.append(f"!     Description:  {peer_data.get('description', 'N/A')}")
        lines.append("")
    
    # Environment
    if data.get('environment'):
        lines.append("!" + "=" * 78)
        lines.append("! ENVIRONMENT STATUS")
        lines.append("!" + "=" * 78)
        env = data['environment']
        
        # CPU
        if env.get('cpu'):
            lines.append("! CPU Utilization:")
            for node, cpu_data in env['cpu'].items():
                lines.append(f"!   {node}: {cpu_data.get('%usage', 'N/A')}%")
        
        # Memory
        if env.get('memory'):
            mem = env['memory']
            lines.append(f"!")
            lines.append(f"! Memory:")
            lines.append(f"!   Available: {mem.get('available_ram', 'N/A')} KB")
            lines.append(f"!   Used:      {mem.get('used_ram', 'N/A')} KB")
        
        # Temperature
        if env.get('temperature'):
            lines.append(f"!")
            lines.append(f"! Temperature Sensors:")
            for sensor, temp_data in env['temperature'].items():
                lines.append(f"!   {sensor}:")
                lines.append(f"!     Temperature: {temp_data.get('temperature', 'N/A')}Â°C")
                lines.append(f"!     Alert:       {temp_data.get('is_alert', False)}")
                lines.append(f"!     Critical:    {temp_data.get('is_critical', False)}")
        
        # Power
        if env.get('power'):
            lines.append(f"!")
            lines.append(f"! Power Supplies:")
            for psu, psu_data in env['power'].items():
                lines.append(f"!   {psu}:")
                lines.append(f"!     Status:   {'OK' if psu_data.get('status') else 'Failed'}")
                lines.append(f"!     Output:   {psu_data.get('output', 'N/A')} W")
                lines.append(f"!     Capacity: {psu_data.get('capacity', 'N/A')} W")
        
        # Fans
        if env.get('fans'):
            lines.append(f"!")
            lines.append(f"! Fans:")
            for fan, fan_data in env['fans'].items():
                lines.append(f"!   {fan}: {'OK' if fan_data.get('status') else 'Failed'}")
        
        lines.append("")
    
    # ARP Table
    if data.get('arp_table'):
        lines.append("!" + "=" * 78)
        lines.append("! ARP TABLE")
        lines.append("!" + "=" * 78)
        for entry in data['arp_table'][:50]:  # Limit to 50 entries
            lines.append(f"! IP: {entry.get('ip', 'N/A'):15} MAC: {entry.get('mac', 'N/A'):17} Interface: {entry.get('interface', 'N/A'):20} Age: {entry.get('age', 'N/A')}")
        lines.append("")
    
    # LLDP Neighbors
    if data.get('lldp_neighbors'):
        lines.append("!" + "=" * 78)
        lines.append("! LLDP NEIGHBORS")
        lines.append("!" + "=" * 78)
        for intf, neighbors in data['lldp_neighbors'].items():
            lines.append(f"!")
            lines.append(f"! Local Interface: {intf}")
            for neighbor in neighbors:
                lines.append(f"!   Neighbor:      {neighbor.get('hostname', 'N/A')}")
                lines.append(f"!   Remote Port:   {neighbor.get('port', 'N/A')}")
        lines.append("")
    
    # NTP Configuration
    if data.get('ntp_peers') or data.get('ntp_servers'):
        lines.append("!" + "=" * 78)
        lines.append("! NTP CONFIGURATION")
        lines.append("!" + "=" * 78)
        
        if data.get('ntp_peers'):
            lines.append("! NTP Peers:")
            for peer in data['ntp_peers'].keys():
                lines.append(f"!   {peer}")
        
        if data.get('ntp_servers'):
            lines.append("! NTP Servers:")
            for server in data['ntp_servers'].keys():
                lines.append(f"!   {server}")
        lines.append("")
    
    # NTP Statistics
    if data.get('ntp_stats'):
        lines.append("!" + "=" * 78)
        lines.append("! NTP STATISTICS")
        lines.append("!" + "=" * 78)
        for stat in data['ntp_stats']:
            lines.append(f"!")
            lines.append(f"! Remote:       {stat.get('remote', 'N/A')}")
            lines.append(f"!   Synchronized: {stat.get('synchronized', False)}")
            lines.append(f"!   Stratum:      {stat.get('stratum', 'N/A')}")
            lines.append(f"!   Delay:        {stat.get('delay', 'N/A')} ms")
            lines.append(f"!   Offset:       {stat.get('offset', 'N/A')} ms")
            lines.append(f"!   Jitter:       {stat.get('jitter', 'N/A')} ms")
        lines.append("")
    
    # Users
    if data.get('users'):
        lines.append("!" + "=" * 78)
        lines.append("! USER ACCOUNTS")
        lines.append("!" + "=" * 78)
        for username, user_data in data['users'].items():
            lines.append(f"! User: {username}")
            lines.append(f"!   Level: {user_data.get('level', 'N/A')}")
        lines.append("")
    
    # SNMP Configuration
    if data.get('snmp_info'):
        lines.append("!" + "=" * 78)
        lines.append("! SNMP CONFIGURATION")
        lines.append("!" + "=" * 78)
        snmp = data['snmp_info']
        lines.append(f"! Chassis ID:  {snmp.get('chassis_id', 'N/A')}")
        lines.append(f"! Contact:     {snmp.get('contact', 'N/A')}")
        lines.append(f"! Location:    {snmp.get('location', 'N/A')}")
        
        if snmp.get('community'):
            lines.append("!")
            lines.append("! Communities:")
            for comm_name, comm_data in snmp['community'].items():
                lines.append(f"!   {comm_name}: {comm_data.get('mode', 'N/A')} (ACL: {comm_data.get('acl', 'none')})")
        lines.append("")
    
    # Interface IP Addresses
    if data.get('interfaces_ip'):
        lines.append("!" + "=" * 78)
        lines.append("! INTERFACE IP ADDRESSES")
        lines.append("!" + "=" * 78)
        for intf, ip_data in data['interfaces_ip'].items():
            lines.append(f"!")
            lines.append(f"! Interface: {intf}")
            
            if 'ipv4' in ip_data:
                lines.append("!   IPv4:")
                for ip, ip_info in ip_data['ipv4'].items():
                    lines.append(f"!     {ip}/{ip_info.get('prefix_length', 'N/A')}")
            
            if 'ipv6' in ip_data:
                lines.append("!   IPv6:")
                for ip, ip_info in ip_data['ipv6'].items():
                    lines.append(f"!     {ip}/{ip_info.get('prefix_length', 'N/A')}")
        lines.append("")
    
    # Running Configuration (if available)
    if data.get('running_config'):
        lines.append("!" + "=" * 78)
        lines.append("! RUNNING CONFIGURATION")
        lines.append("!" + "=" * 78)
        config = data['running_config']
        if isinstance(config, dict):
            config_text = config.get('running', '')
        else:
            config_text = str(config)
        
        # Limit config output
        config_lines = config_text.split('\n')[:2000]  # First 2000 lines
        lines.extend(config_lines)
        if len(config_text.split('\n')) > 2000:
            lines.append("!")
            lines.append("! ... (configuration truncated)")
        lines.append("")
    
    # Errors
    if data.get('errors'):
        lines.append("!" + "=" * 78)
        lines.append("! COLLECTION ERRORS")
        lines.append("!" + "=" * 78)
        for error in data['errors']:
            lines.append(f"! ERROR: {error}")
        lines.append("")
    
    # Footer
    lines.append("!" * 80)
    lines.append("! END OF COMPREHENSIVE AUDIT REPORT")
    lines.append("!" * 80)
    
    return '\n'.join(lines)

def restart_application():
    """Restart the Flask application"""
    try:
        logging.info("Restarting application...")
        python = sys.executable
        os.execl(python, python, *sys.argv)
    except Exception as e:
        logging.error(f"Failed to restart application: {e}")
        return False
    return True


# ---------------------------
# Error handlers
# ---------------------------
#04-11-2025
@app.route('/restart_app', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.MANAGE_USERS)  # Only admins can restart
def restart_app():
    """Restart the Flask application"""
    try:
        # Schedule restart after response is sent
        def delayed_restart():
            import time
            time.sleep(1)  # Give time for response to be sent
            restart_application()
        
        # Start restart in background thread
        restart_thread = threading.Thread(target=delayed_restart, daemon=True)
        restart_thread.start()
        
        return jsonify({
            'success': True,
            'message': 'Application is restarting... Please refresh your browser in a few seconds.'
        })
    except Exception as e:
        logging.error(f"Restart failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify app is running"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'uptime': time.time() - app.config.get('start_time', time.time())
    }) #04-11-2025

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


# Routes
# ---------------------------

# Note: GET /login handled above; protect other routes with login
# Add/Update this route in your flask_code3.py to ensure fast preview generation

@app.route('/generate_config_only', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.CONFIGURE)
def generate_config_only():
    """
    Fast preview - only generate commands without connecting to devices.
    This should return in < 2 seconds.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        prompt = data.get('prompt', '').strip()
        device_type = data.get('device_type', 'cisco_ios')  # Default to Cisco IOS
        
        if not prompt:
            return jsonify({'error': 'No prompt provided'}), 400

        # Quick validation - check if it's just show commands
        if all(line.strip().lower().startswith('show') for line in prompt.split('\n') if line.strip()):
            # If user pasted raw show commands, return them as-is
            commands = [line.strip() for line in prompt.split('\n') if line.strip()]
            return jsonify({
                'success': True, 
                'commands': commands, 
                'count': len(commands),
                'note': 'Commands passed through (show commands detected)'
            })

        try:
            # Generate commands using AI (this is fast - no device connection)
            logging.info(f"Generating config preview for device_type: {device_type}")
            ai_action = get_action_from_prompt(prompt, device_type)
            commands = extract_config_commands(ai_action)
            
            if not commands:
                return jsonify({'error': 'No valid configuration commands generated'}), 400
            
            logging.info(f"Generated {len(commands)} commands successfully")
            
            return jsonify({
                'success': True, 
                'commands': commands, 
                'count': len(commands)
            })
            
        except Exception as ai_err:
            logging.error(f"AI generation failed: {ai_err}")
            
            # Fallback: treat prompt as raw commands
            commands = [line.strip() for line in prompt.split('\n') if line.strip() and not line.strip().startswith('!')]
            
            if commands:
                logging.info(f"Fallback: Using {len(commands)} raw commands from prompt")
                return jsonify({
                    'success': True, 
                    'commands': commands, 
                    'count': len(commands),
                    'note': 'AI parsing failed - using raw commands'
                })
            else:
                return jsonify({'error': 'Failed to parse commands and no valid raw commands found'}), 500

    except Exception as e:
        logging.error(f"generate_config_only error: {e}")
        return jsonify({'error': f'Failed to generate config: {str(e)}'}), 500

@app.route('/get_backup_files')
@login_required
@role_manager.require_permission(Permission.VIEW)
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
@login_required
@role_manager.require_permission(Permission.GOLDEN)
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
@login_required
@role_manager.require_permission(Permission.CONFIGURE)
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
            # Get device type from first device
            first_device = device_map.get(selected_devices[0])
            device_type = first_device.get('device_type', 'cisco_ios') if first_device else 'cisco_ios'
            
            # Generate commands
            ai_response = get_action_from_prompt(prompt, device_type)
            commands = extract_config_commands(ai_response)
            
            # FILTER mode commands
            commands = filter_mode_commands(commands, device_type)
            if "xr" in device_type.lower():
                commands = validate_xr_commands(commands)
                logging.info(f"After XR validation: {len(commands)} commands")
            
        except Exception as e:
            logging.error(f"Failed to parse commands: {e}")
            return jsonify({'error': f'Failed to parse commands: {str(e)}'}), 400

        if not commands:
            return jsonify({'error': 'No valid commands found'}), 400

        # Check for show-only commands
        config_keywords = ['assign', 'configure', 'interface', 'ip address', 'ipv4 address', 
                          'commit', 'set ', 'no ', 'router', 'enable', 'disable', 'shutdown']
        has_config_intent = any(keyword in prompt.lower() for keyword in config_keywords)
        all_show_commands = all(c.strip().lower().startswith('show') for c in commands)
        
        if all_show_commands and not has_config_intent:
            return jsonify({'error': 'Only verify is allowed for show commands. Use Verify.'}), 400

        results = {'commands': commands, 'device_results': []}

        # PARALLEL EXECUTION
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        def execute_on_device(label):
            if label not in device_map:
                return {'device': label, 'success': False, 'message': 'Device not found', 'command_outputs': [], 'config_diff': ''}
            
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

                    # Only get before config if we have config commands
                    config_commands = [c for c in commands if not c.strip().lower().startswith('show')]
                    old_cfg = None
                    if config_commands:
                        logging.info(f"Executing {len(config_commands)} commands on {label}")
                        old_cfg = save_config_for_comparison(conn, device_name, prefix="old_running")

                    # Apply configuration
                    if config_commands:
                        if "xr" in device_type:
                            try:
                                conn.config_mode()
                                
                                # Send commands with minimal delay
                                for cmd in config_commands:
                                    try:
                                        result = conn.send_command_timing(cmd, delay_factor=1)
                                        if 'invalid' in result.lower() or ('error' in result.lower() and 'no error' not in result.lower()):
                                            logging.warning(f"Possible error in XR command '{cmd}': {result}")
                                    except Exception as cmd_err:
                                        logging.error(f"Failed to send command '{cmd}': {cmd_err}")
                                        raise Exception(f"Command '{cmd}' failed: {cmd_err}")
                                
                                # Commit
                                logging.info("Committing XR configuration...")
                                commit_result = conn.send_command("commit", read_timeout=15)
                                
                                if 'error' in commit_result.lower() or 'failed' in commit_result.lower():
                                    logging.error(f"Commit failed: {commit_result}")
                                    conn.send_command("abort")
                                    raise Exception(f"XR commit failed: {commit_result}")
                                
                                conn.exit_config_mode()
                                device_result['message'] = f'XR Configuration applied ({len(config_commands)} commands)'
                                
                            except Exception as xr_err:
                                try:
                                    conn.send_command("abort")
                                    conn.exit_config_mode()
                                except:
                                    pass
                                raise Exception(f"XR config failed: {xr_err}")
                                
                        elif "juniper" in device_type:
                            conn.send_config_set(config_commands)
                            commit_result = conn.send_command("commit")
                            if 'error' in commit_result.lower():
                                raise Exception(f"Juniper commit failed: {commit_result}")
                            device_result['message'] = 'Configuration applied successfully'
                        else:
                            conn.send_config_set(config_commands)
                            device_result['message'] = 'Configuration applied successfully'

                    # Execute only FIRST show command for speed
                    show_commands = [c for c in commands if c.strip().lower().startswith('show')]
                    if show_commands:
                        cmd = show_commands[0]
                        try:
                            timeout = 30 if "xr" in device_type else 15
                            out = conn.send_command(cmd, read_timeout=timeout)
                            device_result['command_outputs'].append({'command': cmd, 'output': out})
                            if len(show_commands) > 1:
                                device_result['command_outputs'].append({
                                    'command': 'Additional Show Commands', 
                                    'output': f'{len(show_commands)-1} show command(s) skipped for speed'
                                })
                        except Exception as ce:
                            logging.error(f"Show failed: {ce}")
                            device_result['command_outputs'].append({'command': cmd, 'output': f'Error: {ce}'})

                    # Generate diff only if config changed
                    if config_commands and old_cfg:
                        new_cfg = save_config_for_comparison(conn, device_name, prefix="new_running")
                        if new_cfg:
                            import difflib
                            diff_text = '\n'.join(difflib.unified_diff(
                                old_cfg.splitlines(), 
                                new_cfg.splitlines(), 
                                fromfile="Before", 
                                tofile="After", 
                                lineterm="",
                                n=1
                            ))
                            device_result['config_diff'] = diff_text if diff_text else "No changes detected."
                            
                            if diff_text:
                                additions = len([l for l in diff_text.split('\n') if l.startswith('+')])
                                deletions = len([l for l in diff_text.split('\n') if l.startswith('-')])
                                device_result['change_summary'] = f"+{additions} -{deletions}"
                        else:
                            device_result['config_diff'] = "Could not generate diff"
                    else:
                        device_result['config_diff'] = "No configuration changes"

                    device_result['success'] = True

            except Exception as e:
                logging.error(f"Execute failed for {label}: {e}")
                device_result['message'] = f'Error: {str(e)}'

            return device_result

        # Execute in parallel (max 5 devices at once)
        with ThreadPoolExecutor(max_workers=min(5, len(selected_devices))) as executor:
            future_to_device = {executor.submit(execute_on_device, label): label for label in selected_devices}
            
            for future in as_completed(future_to_device):
                device_result = future.result()
                results['device_results'].append(device_result)

        return jsonify(results)
        
    except Exception as e:
        logging.error(f"execute_command error: {e}")
        return jsonify({'error': f'Failed to process command: {str(e)}'}), 500

def execute_commands_on_device(device_info, commands, device_name):
    """
    Execute configuration commands on a single device
    """
    device_type = device_info.get("device_type", "").lower()
    
    try:
        conn_params = get_conn_params(device_info)
        with ConnectHandler(**conn_params) as conn:
            # Enter privileged mode for non-Juniper devices
            if "juniper" not in device_type and "xr" not in device_type:
                try:
                    conn.enable()
                except Exception as enable_err:
                    logging.warning(f"Enable command failed: {enable_err}")

            # Save config before changes for diff
            old_cfg = save_config_for_comparison(conn, device_name, prefix="before_exec")

            # Filter out show commands for actual configuration
            config_commands = [c for c in commands if not c.strip().lower().startswith('show')]
            
            if config_commands:
                if "xr" in device_type:
                    # Enhanced XR handling with proper error handling
                    try:
                        conn.config_mode()
                        
                        # Send commands with delay for XR
                        for cmd in config_commands:
                            result = conn.send_command_timing(cmd, delay_factor=2)
                            if 'error' in result.lower() or 'invalid' in result.lower():
                                logging.warning(f"Possible error in XR command '{cmd}': {result}")
                        
                        # Commit changes
                        commit_result = conn.send_command("commit", read_timeout=30)
                        if 'error' in commit_result.lower() or 'failed' in commit_result.lower():
                            conn.send_command("abort")
                            raise Exception(f"XR commit failed: {commit_result}")
                            
                        conn.exit_config_mode()
                        
                    except Exception as xr_err:
                        try:
                            conn.send_command("abort")
                            conn.exit_config_mode()
                        except:
                            pass
                        raise Exception(f"XR configuration failed: {xr_err}")
                
                elif "juniper" in device_type:
                    try:
                        conn.send_config_set(config_commands)
                        commit_result = conn.send_command("commit")
                        if 'error' in commit_result.lower():
                            raise Exception(f"Juniper commit failed: {commit_result}")
                    except Exception as juniper_err:
                        raise Exception(f"Juniper configuration failed: {juniper_err}")
                
                else:
                    # Standard IOS/EOS configuration
                    try:
                        conn.send_config_set(config_commands)
                        # Try to save config
                        try:
                            conn.save_config()
                        except Exception as save_err:
                            logging.warning(f"Could not save config: {save_err}")
                    except Exception as ios_err:
                        raise Exception(f"IOS configuration failed: {ios_err}")

            # Execute any show commands for verification
            show_commands = [c for c in commands if c.strip().lower().startswith('show')]
            for show_cmd in show_commands:
                try:
                    timeout = 60 if "xr" in device_type else 30
                    output = conn.send_command(show_cmd, read_timeout=timeout)
                    logging.info(f"Show command '{show_cmd}' output length: {len(output)}")
                except Exception as show_err:
                    logging.error(f"Show command failed: {show_err}")

            # Save config after changes for diff
            new_cfg = save_config_for_comparison(conn, device_name, prefix="after_exec")
            
            # Calculate changes
            config_changes = len(config_commands)
            success_msg = f"Successfully executed {config_changes} configuration command(s)"
            
            if show_commands:
                success_msg += f" and {len(show_commands)} show command(s)"
            
            return success_msg

    except exceptions.NetMikoTimeoutException as e:
        raise Exception(f"Connection timeout: {e}")
    except exceptions.NetMikoAuthenticationException as e:
        raise Exception(f"Authentication failed: {e}")
    except exceptions.ConnectionException as e:
        raise Exception(f"Connection failed: {e}")
    except Exception as e:
        raise Exception(f"Command execution failed: {e}")
    
@app.route('/verify_command', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.EXECUTE)
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
                from utils.cohere_parsere import get_action_from_prompt_with_device, extract_config_commands
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

def exec_asis_commands_on_device(device_info, commands, device_name):
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

    except exceptions.NetMikoTimeoutException as e:
        raise Exception(f"Timeout during restore - {e}. Try breaking config into smaller files.")
    except exceptions.NetMikoAuthenticationException as e:
        raise Exception(f"Authentication failed - {e}")
    except Exception as e:
        raise Exception(f"Connection/config error: {e}")
# Add this at the top of flask_code3.py after imports

# Import NETCONF drivers
NETCONF_AVAILABLE = False
IOSXR_DRIVER_AVAILABLE = False
JUNOS_DRIVER_AVAILABLE = False

# Import NETCONF drivers
NETCONF_AVAILABLE = False
IOSXR_DRIVER_AVAILABLE = False
JUNOS_DRIVER_AVAILABLE = False

try:
    from iosxr_netconf1 import IOSXRNETCONFDriver
    IOSXR_DRIVER_AVAILABLE = True
    NETCONF_AVAILABLE = True
    logging.info("✓ IOSXR NETCONF driver loaded successfully")
except ImportError as e:
    IOSXR_DRIVER_AVAILABLE = False
    logging.warning(f"IOSXR NETCONF driver not available: {e}")

try:
    from junos_netconf1 import JunosNetconfDriver
    JUNOS_DRIVER_AVAILABLE = True
    NETCONF_AVAILABLE = True
    logging.info("✓ Junos NETCONF driver loaded successfully")
except ImportError as e:
    JUNOS_DRIVER_AVAILABLE = False
    logging.warning(f"Junos NETCONF driver not available: {e}")

# =====================================================
# NETCONF HELPER CLASS
# =====================================================

class NetconfManager:
    """Manages NETCONF operations for IOS-XR devices"""
    
    @staticmethod
    def get_driver_for_device(device_info, timeout=60):
        """
        Create appropriate NETCONF driver based on device type
        
        Args:
            device_info: dict with device details
            timeout: connection timeout
            
        Returns:
            Driver instance (IOSXRNETCONFDriver or JunosNetconfDriver) or None
        """
        device_type = device_info.get('device_type', '').lower()
        
        try:
            if 'juniper' in device_type or 'junos' in device_type:
                if not JUNOS_DRIVER_AVAILABLE:
                    raise Exception("Juniper NETCONF driver not available - check imports")
                
                logging.info(f"Creating Juniper NETCONF driver for {device_info['ip']}")
                driver = JunosNetconfDriver(
                    hostname=device_info['ip'],
                    username=device_info['username'],
                    password=device_info['password'],
                    timeout=timeout,
                    optional_args={
                        "port": device_info.get('port', 830),
                        "config_lock": False
                    }
                )
            else:
                # Default to IOS-XR
                if not IOSXR_DRIVER_AVAILABLE:
                    raise Exception("IOS-XR NETCONF driver not available - check imports")
                
                logging.info(f"Creating IOS-XR NETCONF driver for {device_info['ip']}")
                driver = IOSXRNETCONFDriver(
                    hostname=device_info['ip'],
                    username=device_info['username'],
                    password=device_info['password'],
                    timeout=timeout,
                    optional_args={
                        "port": device_info.get('port', 2022),
                        "config_lock": False
                    }
                )
            
            logging.info(f"Opening NETCONF connection to {device_info['ip']}...")
            driver.open()
            logging.info(f"✓ NETCONF connection established to {device_info['ip']}")
            return driver
            
        except Exception as e:
            logging.error(f"Failed to connect via NETCONF to {device_info.get('ip')}: {e}")
            import traceback
            logging.error(traceback.format_exc())
            raise  # Re-raise the exception so we know what failed
    
    @staticmethod
    def get_connection(device_info, timeout=60):
        """
        Create NETCONF connection to IOS-XR device
        
        Args:
            device_info: dict with ip, username, password, port
            timeout: connection timeout in seconds
            
        Returns:
            IOSXRNETCONFDriver instance or None
        """
        if not NETCONF_AVAILABLE:
            logging.error("NETCONF driver not available")
            return None
        
        try:
            driver = IOSXRNETCONFDriver(
                hostname=device_info['ip'],
                username=device_info['username'],
                password=device_info['password'],
                timeout=timeout,
                optional_args={
                    "port": device_info.get('port', 2022),
                    "config_lock": False
                }
            )
            driver.open()
            return driver
        except Exception as e:
            logging.error(f"Failed to connect via NETCONF: {e}")
            return None
    
    @staticmethod
    def get_facts(device_info):
        """Retrieve device facts via NETCONF"""
        driver = NetconfManager.get_driver_for_device(device_info)
        if not driver:
            return {"error": "Connection failed"}
        
        try:
            facts = driver.get_facts()
            return {
                "success": True,
                "hostname": facts.get('hostname', 'N/A'),
                "vendor": facts.get('vendor', 'N/A'),
                "os_version": facts.get('os_version', 'N/A'),
                "serial_number": facts.get('serial_number', 'N/A'),
                "uptime": facts.get('uptime', -1),
                "interfaces": len(facts.get('interface_list', []))
            }
        except Exception as e:
            logging.error(f"Failed to get facts: {e}")
            return {"error": str(e)}
        finally:
            try:
                driver.close()
            except:
                pass
    
    @staticmethod
    def get_running_config(device_info):
        """Retrieve running config via NETCONF"""
        driver = NetconfManager.get_driver_for_device(device_info)
        if not driver:
            return {"error": "Connection failed"}
        
        try:
            config = driver.get_config(retrieve='running', format='text')
            running_config = config.get('running', '')
            return {
                "success": True,
                "config": running_config,
                "lines": len(running_config.split('\n'))
            }
        except Exception as e:
            logging.error(f"Failed to get config: {e}")
            return {"error": str(e)}
        finally:
            driver.close()
    
    @staticmethod
    def get_candidate_config(device_info):
        """Retrieve candidate config via NETCONF"""
        driver = NetconfManager.get_driver_for_device(device_info)
        if not driver:
            return {"error": "Connection failed"}
        
        try:
            config = driver.get_config(retrieve='candidate', format='text')
            candidate_config = config.get('candidate', '')
            return {
                "success": True,
                "config": candidate_config,
                "lines": len(candidate_config.split('\n'))
            }
        except Exception as e:
            logging.error(f"Failed to get candidate config: {e}")
            return {"error": str(e)}
        finally:
            driver.close()
    
    @staticmethod
    def compare_configs(device_info):
        """Compare running and candidate configs"""
        driver = NetconfManager.get_driver_for_device(device_info)
        if not driver:
            return {"error": "Connection failed"}
        
        try:
            diff = driver.compare_config()
            return {
                "success": True,
                "diff": diff,
                "has_changes": bool(diff and diff.strip())
            }
        except Exception as e:
            logging.error(f"Failed to compare configs: {e}")
            return {"error": str(e)}
        finally:
            driver.close()
    
    @staticmethod
    def load_merge_config(device_info, config_text):
        """Load configuration in merge mode"""
        driver = NetconfManager.get_driver_for_device(device_info)
        if not driver:
            return {"error": "Connection failed"}
        
        try:
            driver.load_merge_candidate(config=config_text)
            diff = driver.compare_config()
            driver.discard_config()  # Don't commit, just show diff
            
            return {
                "success": True,
                "message": "Configuration loaded in merge mode",
                "diff": diff
            }
        except Exception as e:
            logging.error(f"Failed to load merge config: {e}")
            return {"error": str(e)}
        finally:
            driver.close()
    
    @staticmethod
    def load_replace_config(device_info, config_text):
        """Load configuration in replace mode"""
        driver = NetconfManager.get_driver_for_device(device_info)
        if not driver:
            return {"error": "Connection failed"}
        
        try:
            driver.load_replace_candidate(config=config_text)
            diff = driver.compare_config()
            driver.discard_config()  # Don't commit, just show diff
            
            return {
                "success": True,
                "message": "Configuration loaded in replace mode",
                "diff": diff
            }
        except Exception as e:
            logging.error(f"Failed to load replace config: {e}")
            return {"error": str(e)}
        finally:
            driver.close()
    
    @staticmethod
    def get_interfaces(device_info):
        """Get interface details via NETCONF"""
        driver = NetconfManager.get_driver_for_device(device_info)
        if not driver:
            return {"error": "Connection failed"}
        
        try:
            interfaces = driver.get_interfaces()
            return {
                "success": True,
                "interfaces": interfaces,
                "count": len(interfaces)
            }
        except Exception as e:
            logging.error(f"Failed to get interfaces: {e}")
            return {"error": str(e)}
        finally:
            driver.close()
    
    @staticmethod
    def get_interface_counters(device_info):
        """Get interface statistics via NETCONF"""
        driver = NetconfManager.get_driver_for_device(device_info)
        if not driver:
            return {"error": "Connection failed"}
        
        try:
            counters = driver.get_interfaces_counters()
            return {
                "success": True,
                "counters": counters,
                "count": len(counters)
            }
        except Exception as e:
            logging.error(f"Failed to get interface counters: {e}")
            return {"error": str(e)}
        finally:
            driver.close()



# =====================================================
# FLASK ROUTES FOR NETCONF OPERATIONS
# =====================================================

@app.route('/netconf_facts', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.ACCESS_AUDIT)
def netconf_facts_route():
    """Get device facts via NETCONF"""
    try:
        data = request.get_json()
        device_label = data.get('device')
        
        if not device_label or device_label not in device_map:
            return jsonify({'error': 'Invalid device'}), 400
        
        device_info = device_map[device_label]
        device_type = device_info.get('device_type', '').lower()
        
        if 'xr' not in device_type and 'juniper' not in device_type and 'junos' not in device_type:
            return jsonify({'error': 'NETCONF only supported for IOS-XR, Juniper, and Junos devices'}), 400
        
        result = NetconfManager.get_facts(device_info)
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"netconf_facts error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/netconf_running_config', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.ACCESS_AUDIT)
def netconf_running_config_route():
    """Get running config via NETCONF"""
    try:
        data = request.get_json()
        device_label = data.get('device')
        
        if not device_label or device_label not in device_map:
            return jsonify({'error': 'Invalid device'}), 400
        
        device_info = device_map[device_label]
        device_type = device_info.get('device_type', '').lower()
        
        if 'xr' not in device_type:
            return jsonify({'error': 'NETCONF only for XR'}), 400
        
        result = NetconfManager.get_running_config(device_info)
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"netconf_running_config error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/netconf_candidate_config', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.ACCESS_AUDIT)
def netconf_candidate_config_route():
    """Get candidate config via NETCONF"""
    try:
        data = request.get_json()
        device_label = data.get('device')
        
        if not device_label or device_label not in device_map:
            return jsonify({'error': 'Invalid device'}), 400
        
        device_info = device_map[device_label]
        device_type = device_info.get('device_type', '').lower()
        
        if 'xr' not in device_type:
            return jsonify({'error': 'NETCONF only for XR'}), 400
        
        result = NetconfManager.get_candidate_config(device_info)
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"netconf_candidate_config error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/netconf_compare', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.ACCESS_AUDIT)
def netconf_compare_route():
    """Compare running and candidate configs via NETCONF"""
    try:
        data = request.get_json()
        device_label = data.get('device')
        
        if not device_label or device_label not in device_map:
            return jsonify({'error': 'Invalid device'}), 400
        
        device_info = device_map[device_label]
        device_type = device_info.get('device_type', '').lower()
        
        if 'xr' not in device_type:
            return jsonify({'error': 'NETCONF only for XR'}), 400
        
        result = NetconfManager.compare_configs(device_info)
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"netconf_compare error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/netconf_interfaces', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.ACCESS_AUDIT)
def netconf_interfaces_route():
    """Get interfaces via NETCONF"""
    try:
        data = request.get_json()
        device_label = data.get('device')
        
        if not device_label or device_label not in device_map:
            return jsonify({'error': 'Invalid device'}), 400
        
        device_info = device_map[device_label]
        device_type = device_info.get('device_type', '').lower()
        
        if 'xr' not in device_type:
            return jsonify({'error': 'NETCONF only for XR'}), 400
        
        result = NetconfManager.get_interfaces(device_info)
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"netconf_interfaces error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/netconf_interface_counters', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.ACCESS_AUDIT)
def netconf_interface_counters_route():
    """Get interface counters via NETCONF"""
    try:
        data = request.get_json()
        device_label = data.get('device')
        
        if not device_label or device_label not in device_map:
            return jsonify({'error': 'Invalid device'}), 400
        
        device_info = device_map[device_label]
        device_type = device_info.get('device_type', '').lower()
        
        if 'xr' not in device_type:
            return jsonify({'error': 'NETCONF only for XR'}), 400
        
        result = NetconfManager.get_interface_counters(device_info)
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"netconf_interface_counters error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/netconf_load_merge', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.ACCESS_AUDIT)
def netconf_load_merge_route():
    """Load config in merge mode (preview only)"""
    try:
        data = request.get_json()
        device_label = data.get('device')
        config_text = data.get('config', '')
        
        if not device_label or device_label not in device_map:
            return jsonify({'error': 'Invalid device'}), 400
        
        if not config_text:
            return jsonify({'error': 'No config provided'}), 400
        
        device_info = device_map[device_label]
        device_type = device_info.get('device_type', '').lower()
        
        if 'xr' not in device_type:
            return jsonify({'error': 'NETCONF only for XR'}), 400
        
        result = NetconfManager.load_merge_config(device_info, config_text)
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"netconf_load_merge error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/netconf_load_replace', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.ACCESS_AUDIT)
def netconf_load_replace_route():
    """Load config in replace mode (preview only)"""
    try:
        data = request.get_json()
        device_label = data.get('device')
        config_text = data.get('config', '')
        
        if not device_label or device_label not in device_map:
            return jsonify({'error': 'Invalid device'}), 400
        
        if not config_text:
            return jsonify({'error': 'No config provided'}), 400
        
        device_info = device_map[device_label]
        device_type = device_info.get('device_type', '').lower()
        
        if 'xr' not in device_type:
            return jsonify({'error': 'NETCONF only for XR'}), 400
        
        result = NetconfManager.load_replace_config(device_info, config_text)
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"netconf_load_replace error: {e}")
        return jsonify({'error': str(e)}), 500    
    
@app.route('/run_asis_command', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.EXECUTE)
def run_asis_command():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        selected_devices = data.get('devices', [])
        prompt = data.get('prompt', '').strip()

        if not selected_devices or not prompt:
            return jsonify({'error': 'Please select devices and enter a prompt'}), 400

        # Log the exact command being executed
        logging.info(f"Run As-Is: Command='{prompt}' on {len(selected_devices)} device(s)")

        results = {'commands': [prompt], 'device_results': []}

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
                # Get device type for proper handling
                device_type = info.get("device_type", "").lower()
                
                with ConnectHandler(**get_conn_params(info)) as conn:
                    # Enable mode for non-Juniper/XR devices
                    if "juniper" not in device_type and "xr" not in device_type:
                        try:
                            conn.enable()
                        except Exception as e:
                            logging.warning(f"Enable mode failed for {label}: {e}")

                    # Execute the command with device-specific settings
                    try:
                        # Set timeout based on device type
                        if "xr" in device_type:
                            timeout = 120  # XR devices need more time
                            delay_factor = 4
                        elif "juniper" in device_type or "junos" in device_type:
                            timeout = 90
                            delay_factor = 2
                        else:
                            timeout = 60
                            delay_factor = 2
                        
                        logging.info(f"Executing '{prompt}' on {label} (timeout={timeout}s, delay_factor={delay_factor})")
                        
                        # Use send_command_timing for better reliability with varying output
                        output = conn.send_command_timing(
                            prompt,
                            delay_factor=delay_factor,
                            read_timeout=timeout
                        )
                        
                        # If output seems incomplete, try reading more
                        if output and not output.strip().endswith('#'):
                            logging.info(f"Output may be incomplete, reading more for {label}...")
                            additional = conn.send_command_timing(
                                '\n',
                                delay_factor=1,
                                read_timeout=10
                            )
                            if additional and additional.strip():
                                output += additional
                        
                        # Clean up the output
                        output = output.strip()
                        
                        # Check if output is actually empty or just whitespace
                        if not output:
                            logging.warning(f"Empty output received from {label} for command '{prompt}'")
                            output = (
                                f"Command '{prompt}' executed but returned no output.\n\n"
                                f"Possible reasons:\n"
                                f"- Command may not be valid for this device\n"
                                f"- Command requires additional parameters\n"
                                f"- Device is busy or timing out\n"
                                f"- Privilege level insufficient"
                            )
                            device_result['success'] = False
                            device_result['message'] = 'No output received'
                        else:
                            device_result['success'] = True
                            device_result['message'] = 'Command completed successfully'
                            logging.info(f"✓ Command executed on {label}, output length: {len(output)} characters")
                        
                        device_result['command_outputs'].append({
                            'command': prompt,
                            'output': output
                        })
                        
                    except Exception as cmd_err:
                        error_msg = str(cmd_err)
                        logging.error(f"Command execution failed on {label}: {error_msg}")
                        
                        # Provide helpful error message
                        device_result['command_outputs'].append({
                            'command': prompt,
                            'output': (
                                f"Error: {error_msg}\n\n"
                                f"Possible causes:\n"
                                f"- Command syntax error\n"
                                f"- Insufficient privileges\n"
                                f"- Device timeout (try shorter command)\n"
                                f"- Connection issue"
                            )
                        })
                        device_result['success'] = False
                        device_result['message'] = f'Command failed: {error_msg}'

            except Exception as conn_err:
                error_msg = str(conn_err)
                logging.error(f"Connection failed for {label}: {error_msg}")
                device_result['message'] = f'Connection error: {error_msg}'
                device_result['command_outputs'].append({
                    'command': prompt,
                    'output': f'Connection failed: {error_msg}'
                })

            results['device_results'].append(device_result)

        return jsonify(results)

    except Exception as e:
        logging.error(f"run_asis_command error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to process command: {str(e)}'}), 500
#AI explanation

@app.route('/ai/explain', methods=['POST'])
@login_required
def ai_explain():
    try:
        data = request.get_json(silent=True) or {}
        vendor = data.get('vendor')
        from utils.cohere_parsere import explain_commands, explain_commands_rich

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
@login_required
@role_manager.require_permission(Permission.BACKUP)
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
@login_required
@role_manager.require_permission(Permission.RESTORE)
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
@login_required
@role_manager.require_permission(Permission.BACKUP)
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
@login_required
@role_manager.require_permission(Permission.DOWNLOAD)
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
@login_required
@role_manager.require_permission(Permission.DOWNLOAD)
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
@login_required
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
@login_required
@role_manager.require_permission(Permission.UPLOAD)
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
@login_required
@role_manager.require_permission(Permission.GOLDEN)
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
@login_required
@role_manager.require_permission(Permission.GOLDEN)
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
@login_required
@role_manager.require_permission(Permission.EXECUTE)
@role_manager.require_permission(Permission.CONFIGURE)
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
# -----------------------------
# SNMP Metric Writer
# -----------------------------
def write_snmp_points(points):
    if not write_api:
        logging.warning("InfluxDB write API not available")
        return
    try:
        write_api.write(
            bucket=INFLUX_CONFIG['bucket'],
            org=INFLUX_CONFIG['org'],
            record=points
        )
        logging.info(f"Wrote {len(points)} SNMP metrics to InfluxDB")
    except Exception as e:
        logging.error(f"âŒ Failed to write SNMP metrics: {e}")
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
# --------------------------------------------------------------
#  GLOBAL TELEGRAF MANAGER (singleton)
# --------------------------------------------------------------

def start_snmp_monitor():
    """
    Automatically start SNMP monitoring in a background thread when Flask starts.
    """
    if SNMPMonitor is None:
        logging.warning("SNMPMonitor not available. Skipping SNMP monitoring startup.")
        return

    if app.snmp_monitoring_enabled:
        logging.info("SNMP monitoring already running.")
        return

    try:
        monitor = SNMPMonitor()
        app.snmp_monitoring_enabled = True
        logging.info("ðŸš€ Starting SNMP monitoring background thread...")

        def monitor_loop():
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            while True:
                try:
                    devices = load_devices()
                    logging.info(f"Loaded {len(devices)} devices for SNMP monitoring.")
                    if not devices:
                        logging.warning("No devices found in devices.yaml.")
                        time.sleep(30)
                        continue
                    try:
                        logging.info(f"Starting bulk collection for {len(devices)} devices...")
                        
                        # Pass the entire list of devices to collect_metrics_bulk
                        all_points = loop.run_until_complete(monitor.collect_metrics_bulk(devices))
                        
                        if all_points:
                            logging.info(f"Collected {len(all_points)} total SNMP metrics from {len(devices)} devices")
                            write_snmp_points(all_points)
                        else:
                            logging.warning(f"No SNMP metrics collected from any device")
                    except Exception as bulk_err:
                        logging.error(f"Bulk SNMP collection failed:{bulk_err
                        }")

                    logging.info("SNMP monitoring cycle complete. Waiting 30s...")
                    time.sleep(30)

                except Exception as loop_err:
                    logging.error(f"SNMP monitor loop error: {loop_err}")
                    time.sleep(60)

        threading.Thread(target=monitor_loop, daemon=True).start()
    except Exception as e:
        logging.error(f"Failed to start SNMP monitoring: {e}")
      
@app.route('/download_execute_summary', methods=['POST'])
@login_required
def download_execute_summary():
    """Generate and download PDF summary for execute command results"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        results_data = data.get('results', {})
        user_prompt = data.get('prompt', 'No prompt provided')
        
        # Generate PDF
        pdf_buffer = pdf_generator.generate_execute_summary(results_data, user_prompt)
        
        # Create response
        from flask import send_file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"config_change_summary_{timestamp}.pdf"
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logging.error(f"PDF generation error: {e}")
        return jsonify({'error': f'Failed to generate PDF: {str(e)}'}), 500
@app.route('/download_verify_summary', methods=['POST'])
@login_required
def download_verify_summary():
    """Generate and download PDF summary for verify/as-is command results with AI explanations"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        results_data = data.get('results', {})
        user_prompt = data.get('prompt', 'No prompt provided')
        is_asis = data.get('is_asis', False)
        
        # Get AI explanations for commands with outputs
        from utils.cohere_parsere import explain_commands_rich
        
        # Build items list for explanation (command + output pairs)
        items_to_explain = []
        vendor = None
        
        for device_result in results_data.get('device_results', []):
            # Try to determine vendor from device info
            if not vendor:
                device_label = device_result.get('device', '')
                if device_label in device_map:
                    device_info = device_map[device_label]
                    device_type = device_info.get('device_type', '').lower()
                    if 'cisco' in device_type:
                        vendor = 'cisco'
                    elif 'juniper' in device_type:
                        vendor = 'juniper'
                    elif 'arista' in device_type:
                        vendor = 'arista'
            
            # Extract command outputs
            for cmd_output in device_result.get('command_outputs', []):
                items_to_explain.append({
                    'command': cmd_output.get('command', ''),
                    'output': cmd_output.get('output', '')[:2000]  # Limit output length for AI
                })
        
        # Get explanations from AI
        explanations = {}
        if items_to_explain:
            try:
                explanations_list = explain_commands_rich(items_to_explain, vendor)
                # Convert list to dict keyed by command
                for item, explanation in zip(items_to_explain, explanations_list):
                    explanations[item['command']] = explanation
            except Exception as explain_err:
                logging.warning(f"Failed to get AI explanations: {explain_err}")
                explanations = {}
        
        # Add explanations to results_data
        for device_result in results_data.get('device_results', []):
            for cmd_output in device_result.get('command_outputs', []):
                cmd = cmd_output.get('command', '')
                if cmd in explanations:
                    cmd_output['explanation'] = explanations[cmd]
        
        # Generate PDF with explanations
        pdf_buffer = pdf_generator.generate_verify_summary(results_data, user_prompt, is_asis)
        
        # Create response
        from flask import send_file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"verification_summary_{timestamp}.pdf"
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logging.error(f"PDF generation error: {e}")
        return jsonify({'error': f'Failed to generate PDF: {str(e)}'}), 500
# ---------------------------
# Example Protected Route (homepage)
# ---------------------------
# Add these routes to your flask_code2.py file, before the require_login function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if role_manager.authenticate(username, password):
            user = User(username)
            login_user(user)
            session['username'] = username  # Set session for RBAC
            logging.info(f"User {username} logged in successfully")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            logging.warning(f"Failed login attempt for {username}")
            flash('Invalid username or password')
    
    # Create a proper template string that Flask can render
    login_template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - Network Configuration Manager</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
        <style>
            body {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
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
    session.pop('username', None)
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/')
@login_required
@role_manager.require_permission(Permission.READ_DEVICES)
def index():
    try:
        logging.debug(f"Rendering index for user: {current_user.id}, roles: {[r.value for r in current_user.roles] if current_user.roles else []}")
        logging.debug(f"Devices passed to template: {device_labels}")
        return render_template('aa.html', devices=device_labels, user=current_user.id)
    except Exception as te:
        logging.error(f"Jinja2 template error in aa.html: {te}")
        return jsonify({'error': f"Template error: {str(te)}"}), 500
    except Exception as e:
        logging.error(f"Error rendering index: {e}")
        return jsonify({'error': f"Error loading page: {str(e)}"}), 500

#RBAC Management Route added (Date: 22-10-2025)

@app.route('/rbac', methods=['GET', 'POST'])
@login_required
@role_manager.require_permission(Permission.MANAGE_USERS)
def manage_rbac():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create_user':
            username = request.form.get('username')
            password = request.form.get('password')
            roles = request.form.getlist('roles')
            roles_enum = [Role[r.upper()] for r in roles if r.upper() in Role.__members__]
            if role_manager.create_user(username, password, roles_enum):
                flash(f'User {username} created successfully')
            else:
                flash(f'Failed to create user {username} (may already exist)')
        elif action == 'update_roles':
            username = request.form.get('username')
            roles = request.form.getlist('roles')
            roles_enum = [Role[r.upper()] for r in roles if r.upper() in Role.__members__]
            if username in role_manager.users:
                role_manager.users[username].roles = roles_enum
                flash(f'Roles updated for {username}')
            else:
                flash(f'User {username} not found')
        elif action == 'delete_user':
            username = request.form.get('username')
            if username in role_manager.users and username != 'admin':
                del role_manager.users[username]
                flash(f'User {username} deleted')
            else:
                flash(f'Cannot delete user {username}')
        return redirect(url_for('manage_rbac'))
    
    users_list = []
    for username, user in role_manager.users.items():
        users_list.append({
            'username': username,
            'roles': [role.value for role in user.roles],
            'last_login': user.last_login,
            'failed_attempts': user.failed_attempts,
            'locked_until': user.locked_until
        })
    all_roles = [role.value for role in Role]
    return render_template('rbac.html', users=users_list, all_roles=all_roles, user=current_user.id)

      
@app.route('/create_proper_dashboards', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.MANAGE_ALERTS)
def create_proper_dashboards():
    try:
        result = create_grafana_dashboards()
        
        if result.get("success"):
            return jsonify({
                'success': True,
                'message': 'Dashboards created successfully',
                'results': result.get("results", []),
                'dashboard_urls': result.get("dashboard_urls", [])
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get("error", "Unknown error occurred")
            }), 500
            
    except Exception as e:
        logging.error(f"Dashboard creation endpoint error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False, 
            'error': str(e)
        }), 500
@app.route('/grafana')
def grafana_redirect():
    """Redirect to Grafana dashboard."""
    grafana_url = os.environ.get("GRAFANA_URL", "http://localhost:3000/d/network-device-dashboard")
    return redirect(grafana_url, code=302)

@app.route('/status')
@login_required
@role_manager.require_permission(Permission.VIEW_MONITORING)
def status():
    """Check SNMP monitor and InfluxDB status"""
    status_data = {
        "snmp_monitoring": app.snmp_monitoring_enabled,
        "influxdb_connected": write_api is not None,
        "influxdb_bucket": INFLUX_CONFIG['bucket'],
        "devices_loaded": len(load_devices()),
        "grafana_running": False,
        "grafana_url": os.environ.get('GRAFANA_URL', 'http://localhost:3000')
    }
    
    # Check Grafana
    grafana_url = os.environ.get('GRAFANA_URL', 'http://localhost:3000')
    try:
        response = requests.get(f'{grafana_url}/api/health', timeout=5)
        status_data["grafana_running"] = response.status_code == 200
    except Exception as e:
        logging.error(f"Grafana health check failed: {e}")
        status_data["grafana_running"] = False
    
    return jsonify(status_data)

@app.route('/monitoring')
@login_required
@role_manager.require_permission(Permission.VIEW_MONITORING)
def monitoring_page():
    """Dedicated Grafana monitoring page"""
    return render_template('monitoring.html', user=current_user.id)

@app.route('/tig_status', methods=['GET'])
@login_required
@role_manager.require_permission(Permission.VIEW_MONITORING)
def tig_status():
    """Get TIG stack and metrics status"""
    try:
        status = {
            'influxdb': {'running': False, 'message': 'Not connected'},
            'grafana': {'running': False, 'message': 'Not connected'},
            'telegraf': {'running': False, 'message': 'Not monitored'},
            'metrics': None
        }
        
        # Check InfluxDB
        if influx_client:
            try:
                health = influx_client.health()
                status['influxdb'] = {
                    'running': health.status == 'pass',
                    'message': health.message or 'Connected'
                }
                
                # Get metrics summary
                query_api = influx_client.query_api()
                query = f'''
                from(bucket: "{INFLUX_CONFIG['bucket']}")
                  |> range(start: -24h)
                  |> filter(fn: (r) => r._measurement == "device_health")
                  |> keep(columns: ["_value", "_field", "device_name"])
                '''
                result = query_api.query(query)
                
                cpu_values = []
                mem_values = []
                devices = set()
                
                for table in result:
                    for record in table.records:
                        devices.add(record.values.get('device_name'))
                        if record.get_field() == 'cpu_usage':
                            cpu_values.append(record.get_value())
                        elif record.get_field() == 'memory_usage':
                            mem_values.append(record.get_value())
                
                status['metrics'] = {
                    'device_count': len(devices),
                    'cpu_avg': round(sum(cpu_values) / len(cpu_values), 1) if cpu_values else None,
                    'memory_avg': round(sum(mem_values) / len(mem_values), 1) if mem_values else None,
                    'points_24h': len(cpu_values) + len(mem_values)
                }
                
            except Exception as e:
                logging.error(f"InfluxDB check failed: {e}")
                status['influxdb']['message'] = str(e)
        
        # Check Grafana
        grafana_url = os.environ.get('GRAFANA_URL', 'http://localhost:3000')
        try:
            response = requests.get(f'{grafana_url}/api/health', timeout=5)
            status['grafana'] = {
                'running': response.status_code == 200,
                'message': 'Connected' if response.status_code == 200 else 'Connection failed'
            }
        except Exception as e:
            status['grafana']['message'] = 'Not reachable'
        
        # SNMP monitoring status
        status['telegraf'] = {
            'running': app.snmp_monitoring_enabled,
            'message': 'Active' if app.snmp_monitoring_enabled else 'Not started'
        }
        
        return jsonify(status)
        
    except Exception as e:
        logging.error(f"TIG status check failed: {e}")
        return jsonify({'error': str(e)}), 500

    
@app.route('/get_audit_logs', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.ACCESS_AUDIT)
def get_audit_logs():
    """Fetch configuration change audit logs from devices"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        selected_devices = data.get('devices', [])
        if not selected_devices:
            return jsonify({'error': 'Please select devices'}), 400

        results = []
        
        for label in selected_devices:
            if label not in device_map:
                results.append({
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
                'logs': []
            }
            
            try:
                conn_params = get_conn_params(info)
                with ConnectHandler(**conn_params) as conn:
                    device_type = info.get("device_type", "").lower()
                    
                    # Enable mode for non-Juniper/XR devices
                    if "juniper" not in device_type and "xr" not in device_type:
                        try:
                            conn.enable()
                        except Exception:
                            pass
                    
                    # Get audit logs based on device type
                    if "xr" in device_type:
                        # IOS-XR: show configuration commit list
                        output = conn.send_command("show configuration commit list detail", read_timeout=30)
                        logs = parse_xr_commit_logs(output)
                        
                    elif "juniper" in device_type:
                        # Juniper: show system commit
                        output = conn.send_command("show system commit", read_timeout=30)
                        logs = parse_juniper_commit_logs(output)
                        
                    else:
                        # Cisco IOS: show archive log config all
                        try:
                            output = conn.send_command("show archive log config all", read_timeout=30)
                            logs = parse_ios_archive_logs(output)
                        except Exception:
                            # Fallback: show logging | include CONFIG
                            output = conn.send_command("show logging | include CONFIG", read_timeout=30)
                            logs = parse_ios_syslog_config(output)
                    
                    device_result['logs'] = logs
                    device_result['success'] = True
                    device_result['message'] = f'Retrieved {len(logs)} audit log entries'
                    
            except Exception as e:
                logging.error(f"Audit log fetch failed for {label}: {e}")
                device_result['message'] = f'Failed to fetch logs: {str(e)}'
            
            results.append(device_result)
        
        return jsonify({'results': results})
        
    except Exception as e:
        logging.error(f"get_audit_logs error: {e}")
        return jsonify({'error': f'Failed to fetch audit logs: {str(e)}'}), 500

def parse_xr_commit_logs(output):
    """
    Parse IOS-XR commit history - improved version
    Handles the 'show configuration commit list detail' output format
    """
    logs = []
    lines = output.split('\n')
    
    # Skip header lines and look for actual commit entries
    in_data = False
    current_entry = {}
    
    for line in lines:
        line_stripped = line.strip()
        
        # Detect start of data section
        if 'SNo.' in line_stripped or 'CommitId' in line_stripped:
            in_data = True
            continue
        
        # Skip separator lines
        if '---' in line_stripped or not line_stripped:
            continue
        
        if not in_data:
            continue
        
        # Look for commit entry patterns
        # Format varies, but typically contains: SNo, CommitId, User, Date/Time, Description
        
        # Try to parse structured format first
        if line_stripped.startswith(tuple(str(i) for i in range(10))):
            # This looks like a new entry starting with a number
            parts = line_stripped.split(None, 6)
            
            if len(parts) >= 5:
                try:
                    sno = parts[0] if parts[0].isdigit() else None
                    commit_id = parts[1] if len(parts) > 1 else ''
                    user = parts[2] if len(parts) > 2 else 'unknown'
                    
                    # Date/time can be in various formats
                    # Try to extract date components
                    date_parts = []
                    time_part = ''
                    desc_start = 3
                    
                    # Look for date pattern (Mon DD or similar)
                    for i in range(3, min(len(parts), 7)):
                        part = parts[i]
                        # Check if it looks like a date component
                        if any(month in part for month in ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                                                            'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']):
                            date_parts.append(part)
                            desc_start = i + 1
                        elif ':' in part:  # Time component
                            time_part = part
                            desc_start = i + 1
                        elif part.isdigit() and len(part) == 4:  # Year
                            date_parts.append(part)
                            desc_start = i + 1
                        elif date_parts and part.isdigit():  # Day
                            date_parts.append(part)
                    
                    timestamp_str = ' '.join(date_parts)
                    if time_part:
                        timestamp_str += f" {time_part}"
                    
                    if not timestamp_str:
                        timestamp_str = 'Unknown'
                    
                    # Description is everything after the date/time
                    description = ' '.join(parts[desc_start:]) if desc_start < len(parts) else 'Configuration commit'
                    
                    if sno:  # Only add if we have a valid serial number
                        logs.append({
                            'timestamp': timestamp_str,
                            'user': user,
                            'action': 'commit',
                            'details': description if description else 'Configuration commit',
                            'commit_id': commit_id,
                            'command': line_stripped
                        })
                
                except Exception as e:
                    logging.debug(f"Failed to parse commit line: {line_stripped} - {e}")
                    continue
        
        # Also try to parse "Label:" format entries
        elif 'Label:' in line_stripped:
            parts = line_stripped.split()
            commit_id = parts[1] if len(parts) > 1 else ''
            logs.append({
                'timestamp': 'Unknown',
                'user': 'system',
                'action': 'commit',
                'details': line_stripped,
                'commit_id': commit_id,
                'command': line_stripped
            })
        
        # Parse line-by-line details if in a commit entry
        elif current_entry:
            if 'User:' in line_stripped:
                current_entry['user'] = line_stripped.split('User:', 1)[1].strip()
            elif 'Line:' in line_stripped:
                current_entry['details'] = line_stripped.split('Line:', 1)[1].strip()
            elif 'Time:' in line_stripped or any(month in line_stripped for month in 
                                                  ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                                                   'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']):
                # This might be a timestamp line
                if 'Time:' in line_stripped:
                    current_entry['timestamp'] = line_stripped.split('Time:', 1)[1].strip()
                else:
                    current_entry['timestamp'] = line_stripped
    
    # Remove duplicates and return last 50
    seen = set()
    unique_logs = []
    for log in logs:
        log_key = (log['timestamp'], log['user'], log.get('commit_id', ''))
        if log_key not in seen:
            seen.add(log_key)
            unique_logs.append(log)
    
    return unique_logs[:50]  # Return last 50 entries


def parse_juniper_commit_logs(output):
    """Parse Juniper commit history"""
    logs = []
    lines = output.split('\n')
    
    for line in lines:
        if not line.strip() or 'commit' not in line.lower():
            continue
            
        # Example: 0   2024-01-15 10:30:45 PST by admin via cli
        parts = line.split()
        if len(parts) >= 5:
            try:
                logs.append({
                    'timestamp': ' '.join(parts[1:4]),
                    'user': parts[5] if len(parts) > 5 else 'unknown',
                    'action': 'commit',
                    'details': ' '.join(parts[6:]) if len(parts) > 6 else 'Configuration commit',
                    'command': line.strip()
                })
            except Exception:
                continue
    
    return logs[:50]


def parse_ios_archive_logs(output):
    """Parse IOS archive configuration logs"""
    logs = []
    lines = output.split('\n')
    
    for line in lines:
        if 'logged command' in line.lower() or 'User:' in line:
            parts = line.split('|')
            if len(parts) >= 3:
                try:
                    logs.append({
                        'timestamp': parts[0].strip(),
                        'user': parts[1].replace('User:', '').strip(),
                        'action': 'config',
                        'details': parts[2].strip() if len(parts) > 2 else 'Configuration change',
                        'command': line.strip()
                    })
                except Exception:
                    continue
    
    return logs[:50]


def parse_ios_syslog_config(output):
    """Parse IOS syslog for config changes"""
    logs = []
    lines = output.split('\n')
    
    for line in lines:
        if 'CONFIG_I' in line or 'SYS-5-CONFIG_I' in line:
            try:
                # Extract timestamp and details
                parts = line.split(':', 2)
                if len(parts) >= 3:
                    logs.append({
                        'timestamp': parts[0].strip(),
                        'user': 'system',
                        'action': 'config',
                        'details': parts[2].strip() if len(parts) > 2 else 'Configuration change',
                        'command': line.strip()
                    })
            except Exception:
                continue
    
    return logs[:50]


@app.route('/download_audit_logs', methods=['POST'])
@login_required
@role_manager.require_permission(Permission.ACCESS_AUDIT)
def download_audit_logs():
    """
    Download comprehensive audit logs with real NETCONF data collection
    Saves to audit_logs/<device_name>/<YYYYMMDD>/audit_<device_name>_<timestamp>.txt
    """
    try:
        data = request.get_json()
        if not data or 'audit_data' not in data:
            return jsonify({'error': 'No audit data provided'}), 400
        
        audit_data = data['audit_data']
        results = audit_data.get('results', [])
        
        if not results or len(results) == 0:
            return jsonify({'error': 'No device results provided'}), 400
        
        # Get first device for audit
        device_result = results[0]
        device_label = device_result['device']
        
        if device_label not in device_map:
            return jsonify({'error': 'Device not found in device map'}), 404
        
        device_info = device_map[device_label]
        device_name = device_info.get('name', 'unknown')
        device_type = device_info.get('device_type', '').lower()
        
        # Create device-specific audit folder with date subfolder
        date_folder = datetime.now().strftime("%Y%m%d")
        device_folder = os.path.join(AUDIT_LOGS_ROOT, device_name, date_folder)
        os.makedirs(device_folder, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_{device_name}_{timestamp}.txt"
        filepath = os.path.join(device_folder, filename)
        
        report_lines = []
        
        report_lines.append("!" * 80)
        report_lines.append("! NETWORK DEVICE COMPREHENSIVE AUDIT REPORT")
        report_lines.append("!" * 80)
        report_lines.append(f"! Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"! Device:    {device_label}")
        report_lines.append(f"! Type:      {device_type}")
        report_lines.append("!" * 80)
        report_lines.append("")
        
        # Add original audit log data
        report_lines.append("!" + "=" * 78)
        report_lines.append("! CONFIGURATION AUDIT LOG")
        report_lines.append("!" + "=" * 78)
        report_lines.append(f"! Status: {'Success' if device_result.get('success') else 'Failed'}")
        report_lines.append(f"! Message: {device_result.get('message', 'N/A')}")
        report_lines.append("")
        
        logs = device_result.get('logs', [])
        if logs:
            report_lines.append(f"! Total Configuration Change Entries: {len(logs)}")
            report_lines.append("")
            
            for idx, log in enumerate(logs[:10], 1):  # Show first 10 entries
                report_lines.append(f"! Entry {idx}:")
                report_lines.append(f"!   Timestamp: {log.get('timestamp', 'N/A')}")
                report_lines.append(f"!   User:      {log.get('user', 'N/A')}")
                report_lines.append(f"!   Action:    {log.get('action', 'N/A')}")
                report_lines.append(f"!   Details:   {log.get('details', 'N/A')}")
                if 'commit_id' in log:
                    report_lines.append(f"!   Commit ID: {log.get('commit_id', 'N/A')}")
                report_lines.append("")
            
            if len(logs) > 10:
                report_lines.append(f"! ... and {len(logs) - 10} more entries")
                report_lines.append("")
        else:
            report_lines.append("! No audit logs found for this device")
            report_lines.append("")
        
        # Collect real NETCONF data if supported device
        if ('xr' in device_type or 'juniper' in device_type or 'junos' in device_type):
            # Check if appropriate driver is available
            driver_available = False
            if 'xr' in device_type and IOSXR_DRIVER_AVAILABLE:
                driver_available = True
            elif ('juniper' in device_type or 'junos' in device_type) and JUNOS_DRIVER_AVAILABLE:
                driver_available = True
            
            if driver_available:
                logging.info("=" * 80)
                logging.info(f"Starting NETCONF comprehensive audit for {device_name}")
                logging.info(f"=" * 80)
                
                try:
                    # Use get_driver_for_device method
                    logging.info(f"Step 1: Creating NETCONF driver...")
                    driver = NetconfManager.get_driver_for_device(device_info, timeout=120)
                    
                    if not driver:
                        raise Exception("Failed to create NETCONF driver - returned None")
                    
                    logging.info(f"✓ Step 1 Complete: NETCONF driver created successfully")
                    logging.info(f"Step 2: Collecting comprehensive audit data...")
                    
                    # Collect comprehensive audit data
                    comprehensive_data = driver.get_comprehensive_audit()
                    
                    logging.info(f"✓ Step 2 Complete: Data collection finished")
                    logging.info(f"Step 3: Closing NETCONF connection...")
                    
                    driver.close()
                    
                    logging.info(f"✓ Step 3 Complete: Connection closed")
                    logging.info(f"Step 4: Formatting audit report...")
                    
                    # Format the comprehensive data
                    if comprehensive_data and 'timestamp' in comprehensive_data:
                        netconf_output = format_netconf_output_for_audit({
                            'timestamp': comprehensive_data.get('timestamp'),
                            'device': device_name,
                            'ip': device_info['ip'],
                            'netconf_port': device_info.get('port', 2022),
                            'comprehensive_audit': {
                                'data': comprehensive_data
                            },
                            'methods': {
                                'get_config': {
                                    'output': comprehensive_data.get('running_config', {}).get('running', '')
                                }
                            }
                        })
                        report_lines.extend(netconf_output)
                        logging.info(f"✓ Step 4 Complete: Report formatted successfully")
                        logging.info(f"✓ NETCONF comprehensive audit complete for {device_name}")
                    else:
                        report_lines.append("!" * 80)
                        report_lines.append("! WARNING: NETCONF audit data was empty")
                        report_lines.append("!" * 80)
                        report_lines.append("")
                        logging.warning("NETCONF returned empty data")
                    
                except Exception as netconf_err:
                    logging.error(f"✗ NETCONF comprehensive audit failed: {netconf_err}")
                    import traceback
                    logging.error(traceback.format_exc())
                    report_lines.append("!" * 80)
                    report_lines.append("! NETCONF COMPREHENSIVE AUDIT FAILED")
                    report_lines.append(f"! Error: {str(netconf_err)}")
                    report_lines.append("!" * 80)
                    report_lines.append("")
            else:
                # Driver not available
                report_lines.append("!" * 80)
                if 'xr' in device_type:
                    report_lines.append("! NOTE: IOS-XR NETCONF driver not available")
                    report_lines.append("! Please ensure iosxr_netconf1.py is present")
                else:
                    report_lines.append("! NOTE: Juniper NETCONF driver not available")
                    report_lines.append("! Please ensure junos_netconf1.py is present")
                report_lines.append("!" * 80)
                report_lines.append("")
        else:
            # Device type not supported
            report_lines.append("!" * 80)
            report_lines.append(f"! NOTE: NETCONF not supported for device type: {device_type}")
            report_lines.append("!" * 80)
            report_lines.append("")
        
        # Add footer
        report_lines.append("")
        report_lines.append("!" * 80)
        report_lines.append("! END OF COMPREHENSIVE AUDIT REPORT")
        report_lines.append("!" * 80)
        
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
        
        logging.info(f"✓ Comprehensive audit log saved to: {filepath}")
        logging.info(f"  File size: {os.path.getsize(filepath)} bytes")
        logging.info(f"  Location: audit_logs/{device_name}/{date_folder}/{filename}")
        
        # Return file for download
        report_text = '\n'.join(report_lines)
        response = make_response(report_text)
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # Also return metadata about the saved file
        response.headers['X-Audit-File-Path'] = f"audit_logs/{device_name}/{date_folder}/{filename}"
        response.headers['X-Audit-File-Size'] = str(len(report_text))
        
        return response
        
    except Exception as e:
        logging.error(f"download_audit_logs error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to generate audit log: {str(e)}'}), 500

@app.route('/list_audit_logs/<device_name>', methods=['GET'])
@login_required
@role_manager.require_permission(Permission.ACCESS_AUDIT)
def list_audit_logs(device_name):
    """
    List all saved audit logs for a device
    Returns JSON with file list organized by date
    """
    try:
        from urllib.parse import unquote
        device_name = unquote(device_name)
        
        # Extract clean device name from label format
        clean_device_name = device_name
        if "(" in device_name and ")" in device_name:
            clean_device_name = device_name.split("(")[0].strip()
        
        device_audit_root = os.path.join(AUDIT_LOGS_ROOT, clean_device_name)
        
        if not os.path.exists(device_audit_root):
            return jsonify({'logs': [], 'message': 'No audit logs found'})
        
        audit_logs = {}
        
        # Iterate through date folders
        for date_folder in sorted(os.listdir(device_audit_root), reverse=True):
            date_path = os.path.join(device_audit_root, date_folder)
            
            if not os.path.isdir(date_path):
                continue
            
            audit_logs[date_folder] = []
            
            for filename in sorted(os.listdir(date_path), reverse=True):
                if filename.endswith('.cfg') or filename.endswith('.txt'):
                    filepath = os.path.join(date_path, filename)
                    file_size = os.path.getsize(filepath)
                    file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                    
                    audit_logs[date_folder].append({
                        'filename': filename,
                        'date_folder': date_folder,
                        'size': file_size,
                        'size_kb': round(file_size / 1024, 2),
                        'modified': file_time.isoformat(),
                        'modified_display': file_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'path': f"audit_logs/{clean_device_name}/{date_folder}/{filename}"
                    })
        
        return jsonify({
            'device': clean_device_name,
            'logs': audit_logs,
            'total_dates': len(audit_logs),
            'total_files': sum(len(files) for files in audit_logs.values())
        })
        
    except Exception as e:
        logging.error(f"list_audit_logs error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/download_saved_audit/<device_name>/<date_folder>/<filename>')
@login_required
@role_manager.require_permission(Permission.ACCESS_AUDIT)
def download_saved_audit(device_name, date_folder, filename):
    """
    Download a specific saved audit log file
    """
    try:
        from urllib.parse import unquote
        
        device_name = unquote(device_name)
        clean_device_name = device_name
        if "(" in device_name and ")" in device_name:
            clean_device_name = device_name.split("(")[0].strip()
        
        filepath = os.path.join(AUDIT_LOGS_ROOT, clean_device_name, date_folder, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'Audit log file not found'}), 404
        
        return send_from_directory(
            os.path.join(AUDIT_LOGS_ROOT, clean_device_name, date_folder),
            filename,
            as_attachment=True
        )
        
    except Exception as e:
        logging.error(f"download_saved_audit error: {e}")
        return jsonify({'error': str(e)}), 500
  
# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    app.config['start_time'] = time.time()  # ADD THIS LINE (04-11-2025)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()]
    )
    for folder in (RUNNING_ROOT, BACKUP_ROOT, CURRENT_ROOT, GOLDEN_ROOT, UPLOAD_FOLDER,AUDIT_LOGS_ROOT):
        os.makedirs(folder, exist_ok=True)
    # Auto-create dashboards on startup
    try:
        logging.info("Creating Grafana dashboards...")
        dashboard_result = create_grafana_dashboards()
        if dashboard_result["success"]:
            logging.info("Dashboards created successfully")
        else:
            logging.warning(f"Dashboard creation failed: {dashboard_result.get('error')}")
    except Exception as e:
        logging.warning(f"Dashboard auto-creation failed: {e}")
    start_snmp_monitor()
    app.run(host="0.0.0.0", port=5000, debug=True)
