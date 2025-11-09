import os
import yaml
import time
import subprocess
import threading
import logging
from datetime import datetime
from pathlib import Path

# =============================
# CONFIGURATION
# =============================
TELEGRAF_EXE = Path(__file__).parent / "telegraf" / "telegraf.exe"
CONFIG_PATH = Path(__file__).parent / "telegraf_data" / "telegraf.conf"
METRICS_OUT = Path("telegraf_data") / "telegraf_metrics.out"
DEVICES_YAML = Path("devices.yaml")
CONFIG_AGE_LIMIT = 3600  # 60 minutes
METRICS_OUT.parent.mkdir(parents=True, exist_ok=True)

# Vendor-specific OIDs
VENDOR_OIDS = {
    "juniper_junos": {
        "cpu": "1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0",
        "mem_used": "1.3.6.1.4.1.2636.3.1.13.1.11.9.1.0.0",
        "uptime": "1.3.6.1.2.1.1.3.0",
        "sysDescr": "1.3.6.1.2.1.1.1.0",
    },
    "arista": {
        "cpu": "1.3.6.1.4.1.30065.3.1.1.1.1.0",
        "mem_used": "1.3.6.1.2.1.25.2.3.1.6.100",
        "mem_total": "1.3.6.1.2.1.25.2.3.1.5.100",
        "uptime": "1.3.6.1.2.1.1.3.0",
        "sysDescr": "1.3.6.1.2.1.1.1.0",
    },
    "cisco": {
        "cpu": "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1",
        "mem_used": "1.3.6.1.4.1.9.9.221.1.1.1.1.18",
        "mem_total": "1.3.6.1.4.1.9.9.221.1.1.1.1.20",
        "uptime": "1.3.6.1.2.1.1.3.0",
        "sysDescr": "1.3.6.1.2.1.1.1.0",
    },
    "default": {
        "cpu": "1.3.6.1.2.1.25.3.3.1.2.1",
        "mem_used": "1.3.6.1.2.1.25.2.3.1.6.1",
        "mem_total": "1.3.6.1.2.1.25.2.3.1.5.1",
        "uptime": "1.3.6.1.2.1.1.3.0",
        "sysDescr": "1.3.6.1.2.1.1.1.0",
    }
}

# Interface Table OIDs
INTERFACE_TABLE_OIDS = [
    "1.3.6.1.2.1.2.2.1.1",   # ifIndex
    "1.3.6.1.2.1.2.2.1.2",   # ifDescr
    "1.3.6.1.2.1.2.2.1.3",   # ifType
    "1.3.6.1.2.1.2.2.1.5",   # ifSpeed
    "1.3.6.1.2.1.2.2.1.7",   # ifAdminStatus
    "1.3.6.1.2.1.2.2.1.8",   # ifOperStatus
    "1.3.6.1.2.1.2.2.1.10",  # ifInOctets
    "1.3.6.1.2.1.2.2.1.16",  # ifOutOctets
    "1.3.6.1.2.1.31.1.1.1.6",  # ifHCInOctets
    "1.3.6.1.2.1.31.1.1.1.10", # ifHCOutOctets
    "1.3.6.1.2.1.2.2.1.13",  # ifInDiscards
    "1.3.6.1.2.1.2.2.1.14",  # ifInErrors
    "1.3.6.1.2.1.2.2.1.19",  # ifOutDiscards
    "1.3.6.1.2.1.2.2.1.20",  # ifOutErrors
    "1.3.6.1.2.1.31.1.1.1.15", # ifHighSpeed
    "1.3.6.1.2.1.2.2.1.11",  # ifInUcastPkts
    "1.3.6.1.2.1.2.2.1.17",  # ifOutUcastPkts
]

# =============================
# LOGGING
# =============================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("telegraf_manager.log"),
        logging.StreamHandler()
    ]
)

# =============================
# MAIN CLASS
# =============================
class TelegrafManager:
    def __init__(self, influx_config=None, device_loader=True):
        self.influx_cfg = influx_config
        self.process = None
        self.keepalive_thread = None
        self.devices = device_loader and self._load_devices() or []
        self.config_path = Path("telegraf_data/telegraf.conf")
        self.metrics_file = Path("telegraf_data/telegraf_metrics.out")
        self.log_file = Path("telegraf_data/telegraf.log")

        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.metrics_file.touch(exist_ok=True)
        self.log_file.touch(exist_ok=True)

    def _load_devices(self):
        if not DEVICES_YAML.exists():
            raise FileNotFoundError(f"{DEVICES_YAML} not found")
        with open(DEVICES_YAML, 'r') as f:
            data = yaml.safe_load(f)
        self.devices = data.get("devices", [])
        logging.info(f"Loaded {len(self.devices)} devices from {DEVICES_YAML}")

    def _config_needs_regen(self):
        if not CONFIG_PATH.exists():
            return True
        age = time.time() - CONFIG_PATH.stat().st_mtime
        return age > CONFIG_AGE_LIMIT

    def _generate_config(self):
        lines = [
            "# Telegraf Configuration - Auto-generated",
            "[global_tags]",
            '  environment = "production"',
            "",
            "[agent]",
            '  interval = "1m"',  # Changed to 1m for faster CPU updates
            '  round_interval = true',
            '  metric_batch_size = 10000',
            '  metric_buffer_limit = 50000',
            '  collection_jitter = "0s"',
            '  flush_interval = "10s"',
            '  flush_jitter = "0s"',
            '  debug = false',
            '  quiet = false',
            '  logfile = "telegraf_agent.log"',
            '  omit_hostname = false',
            "",
            "[[outputs.influxdb_v2]]",
            f'  urls = ["{self.influx_cfg["url"]}"]',
            f'  token = "{self.influx_cfg["token"]}"',
            f'  organization = "{self.influx_cfg["org"]}"',
            f'  bucket = "{self.influx_cfg["bucket"]}"',
            '  timeout = "5s"',
            "",
        ]

        for dev in self.devices:
            name = dev["name"]
            ip = dev["ip"]
            port = dev.get("snmp_port", 161)
            comm = dev.get("snmp_community", "public")
            vend = dev.get("vendor", "default").lower().replace(" ", "_")
            v = VENDOR_OIDS.get(vend, VENDOR_OIDS["default"])

            # === SNMP INPUT HEADER ===
            lines.extend([
                "",
                f"[[inputs.snmp]]  # {name}",
                f'  agents = ["{ip}:{port}"]',
                '  version = 2',
                f'  community = "{comm}"',
                '  timeout = "10s"',
                '  retries = 3',
                '  max_repetitions = 50',
                '  name = "device"',
                f'  tags = {{ device = "{name}", host = "{ip}" }}',
                "",
            ])

            # === SYSTEM INFO ===
            lines.extend([
                f'  [[inputs.snmp.field]]',
                f'    oid = "{v["uptime"]}"',
                f'    name = "uptime"',
                "",
                f'  [[inputs.snmp.field]]',
                f'    oid = "{v["sysDescr"]}"',
                f'    name = "sysDescr"',
                "",
            ])

            # === CPU: Use TABLE for Cisco, fallback to single OID ===
            if vend == "cisco":
                # Use cpmCPUTotalTable
                lines.extend([
                    f'  [[inputs.snmp.table]]',
                    f'    name = "cpu"',
                    f'    inherit_tags = ["device", "host"]',
                    f'    [[inputs.snmp.table.field]]',
                    f'      oid = "1.3.6.1.4.1.9.9.109.1.1.1.1.1"  # cpmCPUTotalIndex',
                    f'      name = "cpu_index"',
                    f'      is_tag = true',
                    f'    [[inputs.snmp.table.field]]',
                    f'      oid = "1.3.6.1.4.1.9.9.109.1.1.1.1.3"  # cpmCPUTotalPhysicalIndex',
                    f'      name = "physical_index"',
                    f'      is_tag = false',
                    f'    [[inputs.snmp.table.field]]',
                    f'      oid = "1.3.6.1.4.1.9.9.109.1.1.1.1.8"  # cpmCPUTotal5min',
                    f'      name = "cpu_5min"',
                    f'      is_tag = false',
                    f'    [[inputs.snmp.table.field]]',
                    f'      oid = "1.3.6.1.4.1.9.9.109.1.1.1.1.7"  # cpmCPUTotal1min',
                    f'      name = "cpu_1min"',
                    f'      is_tag = false',
                    "",
                ])
            else:
                # Fallback: single CPU field
                lines.extend([
                    f'  [[inputs.snmp.field]]',
                    f'    oid = "{v["cpu"]}"',
                    f'    name = "cpu_usage"',
                    "",
                ])

            # === MEMORY: Use TABLE for Cisco, fallback ===
            if vend == "cisco":
                lines.extend([
                    f'  [[inputs.snmp.table]]',
                    f'    name = "memory"',
                    f'    inherit_tags = ["device", "host"]',
                    f'    [[inputs.snmp.table.field]]',
                    f'      oid = "1.3.6.1.4.1.9.9.221.1.1.1.1.3"  # ciscoMemoryPoolName',
                    f'      name = "pool_name"',
                    f'      is_tag = true',
                    f'    [[inputs.snmp.table.field]]',
                    f'      oid = "1.3.6.1.4.1.9.9.221.1.1.1.1.7"  # ciscoMemoryPoolUsed',
                    f'      name = "mem_used"',
                    f'    [[inputs.snmp.table.field]]',
                    f'      oid = "1.3.6.1.4.1.9.9.221.1.1.1.1.9"  # ciscoMemoryPoolFree',
                    f'      name = "mem_free"',
                    f'    [[inputs.snmp.table.field]]',
                    f'      oid = "1.3.6.1.4.1.9.9.221.1.1.1.1.18"  # ciscoMemoryPoolLargestFree',
                    f'      name = "mem_largest_free"',
                    "",
                ])
            else:
                if "mem_used" in v:
                    lines.extend([
                        f'  [[inputs.snmp.field]]',
                        f'    oid = "{v["mem_used"]}"',
                        f'    name = "memory_used_raw"',
                        "",
                    ])
                if "mem_total" in v:
                    lines.extend([
                        f'  [[inputs.snmp.field]]',
                        f'    oid = "{v["mem_total"]}"',
                        f'    name = "memory_total_raw"',
                        "",
                    ])

            # === INTERFACE TABLE (unchanged, working) ===
            lines.extend([
                f'  [[inputs.snmp.table]]',
                f'    name = "interfaces"',
                f'    inherit_tags = ["device", "host"]',
                f'    [[inputs.snmp.table.field]]',
                f'      oid = "1.3.6.1.2.1.2.2.1.1"',
                f'      name = "ifIndex"',
                f'      is_tag = true',
            ])
            for oid in INTERFACE_TABLE_OIDS[1:]:
                field_name = self._oid_to_name(oid)
                is_tag = "true" if oid == "1.3.6.1.2.1.2.2.1.2" else "false"  # ifDescr as tag
                lines.extend([
                    f'    [[inputs.snmp.table.field]]',
                    f'      oid = "{oid}"',
                    f'      name = "{field_name}"',
                    f'      is_tag = {is_tag}',
                ])
            lines.append("")

            # === PING ===
            lines.extend([
                f'[[inputs.ping]]',
                f'  urls = ["{ip}"]',
                '  count = 4',
                '  ping_interval = 1.0',
                '  timeout = 2.0',
                f'  tags = {{ device = "{name}", host = "{ip}" }}',
                "",
            ])

        config_content = "\n".join(lines)
        CONFIG_PATH.write_text(config_content, encoding="utf-8")
        logging.info(f"Generated new config: {CONFIG_PATH}")

    def _oid_to_name(self, oid):
        mapping = {
            "1.3.6.1.2.1.2.2.1.2": "ifDescr",
            "1.3.6.1.2.1.2.2.1.3": "ifType",
            "1.3.6.1.2.1.2.2.1.5": "ifSpeed",
            "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
            "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
            "1.3.6.1.2.1.2.2.1.10": "ifInOctets",
            "1.3.6.1.2.1.2.2.1.16": "ifOutOctets",
            "1.3.6.1.2.1.31.1.1.1.6": "ifHCInOctets",
            "1.3.6.1.2.1.31.1.1.1.10": "ifHCOutOctets",
            "1.3.6.1.2.1.2.2.1.13": "ifInDiscards",
            "1.3.6.1.2.1.2.2.1.14": "ifInErrors",
            "1.3.6.1.2.1.2.2.1.19": "ifOutDiscards",
            "1.3.6.1.2.1.2.2.1.20": "ifOutErrors",
            "1.3.6.1.2.1.31.1.1.1.15": "ifHighSpeed",
            "1.3.6.1.2.1.2.2.1.11": "ifInUcastPkts",
            "1.3.6.1.2.1.2.2.1.17": "ifOutUcastPkts",
        }
        return mapping.get(oid, f"field_{oid.split('.')[-1]}")
    def _escape_path(self, path: Path) -> str:
        return str(path).replace("\\", "/")

    def _validate_config(self):
        try:
            result = subprocess.run(
                [str(TELEGRAF_EXE), "--config", str(CONFIG_PATH), "--test", "--test-wait", "120", "--debug",],
                capture_output=True,
                timeout=240,
                text=True,
                encoding='utf-8'
            )
            # Count only critical errors
            error_lines = [line for line in result.stdout.splitlines() if "E! [inputs." in line]
            timeout_count = sum("timeout" in line for line in error_lines)
            total_devices = len(self.devices)

            logging.info(f"SNMP timeouts: {timeout_count}/{total_devices} devices unreachable")

            # Only fail if >80% are unreachable
            if timeout_count > total_devices * 0.8:
                logging.error("Too many devices unreachable — check network/SNMP")
                return False

            logging.info("Telegraf config is valid — starting agent")
            return True

        except Exception as e:
            logging.error(f"Validation failed: {e}")
            return False  # Still try to start

    def start(self):
        if self.process and self.process.poll() is None:
            logging.info("Telegraf already running")
            return True  # ← Already running

        self._load_devices()
        if self._config_needs_regen():
            self._generate_config()

        if not self._validate_config():
            logging.warning("Config validation failed — starting anyway")

        try:
            self.process = subprocess.Popen(
                [str(TELEGRAF_EXE), "--config", str(CONFIG_PATH)],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            logging.info(f"Started Telegraf (PID: {self.process.pid})")

            # Start keepalive thread only once
            if not getattr(self, 'keepalive_thread', None) or not self.keepalive_thread.is_alive():
                self.keepalive_thread = threading.Thread(target=self._keepalive, daemon=True)
                self.keepalive_thread.start()

            return True # ← Started successfully
        except Exception as e:
            logging.error(f"Failed to start Telegraf: {e}")
            return False

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except:
                self.process.kill()
            logging.info("Telegraf stopped")
        self.process = None

    def restart(self):
        logging.info("Restarting Telegraf...")
        self.stop()
        time.sleep(2)
        self.start()

    def _keepalive(self):
        while True:
            time.sleep(30)
            if self.process and self.process.poll() is not None:
                exit_code = self.process.poll()
                logging.error(f"Telegraf exited with code {exit_code}. Restarting in 5s...")
                
                # Check logs for errors
                try:
                    log_path = Path(self.config_path.parent) / "telegraf_agent.log"
                    if log_path.exists():
                        lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                        recent = lines[-30:]  # Get last 30 lines
                        logging.error("=== LAST 30 LINES OF TELEGRAF LOG ===")
                        for line in recent:
                            logging.error(line)
                except Exception as e:
                    logging.error(f"Could not read log: {e}")

                time.sleep(5)
                self.start()
