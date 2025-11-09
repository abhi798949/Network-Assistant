#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Junos NETCONF Driver - Complete Implementation
Mirrors all functionality from iosxr_netconf.py for Juniper devices
"""

from __future__ import unicode_literals

from email.policy import default
import re
import copy
import difflib
import ipaddress
import logging
from datetime import datetime

# Third party imports
from ncclient import manager
from ncclient.xml_ import to_ele, to_xml
from ncclient.operations.rpc import RPCError
from ncclient.operations.errors import TimeoutExpiredError
from lxml import etree as ETREE
from lxml.etree import XMLSyntaxError
from sqlalchemy import values

# NAPALM base imports (if available, otherwise stub)
try:
    from napalm.base.base import NetworkDriver
    import napalm.base.helpers
    from napalm.base.exceptions import (
        ConnectionException,
        MergeConfigException,
        ReplaceConfigException,
    )
except ImportError:
    # Stub implementations if NAPALM not available
    class NetworkDriver:
        pass
    
    class ConnectionException(Exception):
        pass
    
    class MergeConfigException(Exception):
        pass
    
    class ReplaceConfigException(Exception):
        pass

logger = logging.getLogger(__name__)


class JunosNetconfDriver(NetworkDriver):
    """Junos NETCONF driver class: mirrors iosxr_netconf functionality."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialize Junos driver.

        optional_args:
            * config_lock (True/False): lock configuration DB after connection
            * port (int): custom port (default 830)
            * key_file (string): SSH key file path
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.pending_changes = False
        self.replace = False
        self.locked = False
        self.optional_args = optional_args if optional_args else {}
        self.port = self.optional_args.pop("port", 830)
        self.lock_on_connect = self.optional_args.pop("config_lock", False)
        self.key_file = self.optional_args.pop("key_file", None)

        self.platform = "junos_netconf"
        self.device = None

    def open(self):
        """Open the connection with port auto-detection."""
        ports_to_try = [self.port]
        
        # Add fallback ports
        if self.port == 830 and 22 not in ports_to_try:
            ports_to_try.append(22)
        elif self.port == 22 and 830 not in ports_to_try:
            ports_to_try.append(830)
        
        last_error = None
        
        for port in ports_to_try:
            try:
                logger.info(f"Attempting NETCONF connection to {self.hostname}:{port}")
                self.device = manager.connect(
                    host=self.hostname,
                    port=port,
                    username=self.username,
                    password=self.password,
                    key_filename=self.key_file,
                    timeout=self.timeout,
                    device_params={"name": "junos"},
                    hostkey_verify=False,
                    **self.optional_args,
                )
                
                self.port = port
                logger.info(f"Successfully connected to {self.hostname}:{port}")
                
                if self.lock_on_connect:
                    self._lock()
                
                return
                
            except Exception as conn_err:
                last_error = conn_err
                logger.warning(f"Connection failed on port {port}: {conn_err}")
                continue
        
        error_msg = f"Failed to connect to {self.hostname} on ports {ports_to_try}. Last error: {last_error}"
        logger.error(error_msg)
        raise ConnectionException(error_msg)

    def close(self):
        """Close the connection."""
        logger.debug(f"Closing connection with device {self.hostname}")
        self._unlock()
        if self.device:
            self.device.close_session()

    def _lock(self):
        """Lock the config DB."""
        if not self.locked:
            self.device.lock(target="candidate")
            self.locked = True

    def _unlock(self):
        """Unlock the config DB."""
        if self.locked:
            self.device.unlock(target="candidate")
            self.locked = False

    def is_alive(self):
        """Return flag with the state of the connection."""
        if self.device is None:
            return {"is_alive": False}
        return {"is_alive": self.device.connected}

    def _parse_reply(self, reply):
        """Convert NCElement reply to lxml Element."""
        # OLD CODE (BROKEN):
        # xml_str = to_xml(reply)
        # return ETREE.fromstring(xml_str)
        
        # NEW CODE (FIXED):
        if hasattr(reply, 'data_xml'):
            xml_str = reply.data_xml
        elif hasattr(reply, 'xml'):
            xml_str = reply.xml
        else:
            xml_str = ETREE.tostring(reply.data_ele, encoding='unicode')
        
        return ETREE.fromstring(xml_str.encode('utf-8'))

    def _find_text(self, element, xpath, default="", namespaces=None):
        """Extract text from XML element using XPath - FIXED to strip whitespace."""
        try:
            result = element.xpath(xpath, namespaces=namespaces) if namespaces else element.xpath(xpath)
            if result and len(result) > 0:
                if hasattr(result[0], 'text'):
                    text = result[0].text if result[0].text else default
                    # FIX: Strip all whitespace including newlines
                    return text.strip() if isinstance(text, str) else default
                text = str(result[0]) if result[0] else default
                return text.strip() if isinstance(text, str) else default
            return default
        except Exception as e:
            logger.debug(f"XPath '{xpath}' failed: {e}")
            return default

    def _rpc(self, command):
        """Execute RPC command and return parsed tree."""
        try:
            reply = self.device.rpc(to_ele(command))
            return self._parse_reply(reply)
        except Exception as e:
            logger.error(f"RPC failed: {e}")
            raise
    def _get_config_tree(self, source="running"):
        """Get configuration tree - handles different ncclient versions."""
        config_reply = self.device.get_config(source=source)
        
        if hasattr(config_reply, 'data_ele'):
            return config_reply.data_ele
        elif hasattr(config_reply, '_root'):
            return config_reply._root
        elif hasattr(config_reply, 'data'):
            return config_reply.data
        else:
            xml_str = config_reply.data_xml if hasattr(config_reply, 'data_xml') else str(config_reply)
            return ETREE.fromstring(xml_str.encode('utf-8'))
    # =====================================================================
    # CONFIGURATION MANAGEMENT METHODS
    # =====================================================================

    def load_replace_candidate(self, filename=None, config=None):
        """Load replace candidate configuration."""
        self.replace = True
        configuration = self._load_config(filename=filename, config=config)
        
        try:
            self._lock()
            self.device.load_configuration(
                config=configuration,
                action="replace",
                format="text"
            )
            self.pending_changes = True
        except Exception as e:
            self.pending_changes = False
            self.replace = False
            logger.error(f"Load replace failed: {e}")
            raise ReplaceConfigException(e)

    def load_merge_candidate(self, filename=None, config=None):
        """Load merge candidate configuration."""
        self.replace = False
        configuration = self._load_config(filename=filename, config=config)
        
        try:
            self._lock()
            self.device.load_configuration(
                config=configuration,
                action="merge",
                format="text"
            )
            self.pending_changes = True
        except Exception as e:
            self.pending_changes = False
            logger.error(f"Load merge failed: {e}")
            raise MergeConfigException(e)

    def _load_config(self, filename, config):
        """Load configuration from file or string."""
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()
        return configuration

    def compare_config(self):
        """Compare candidate config with running."""
        diff = ""
        
        if self.pending_changes:
            try:
                result = self.device.compare_configuration()
                if result:
                    diff = result.xpath('//configuration-output')[0].text
                    if diff:
                        diff = diff.strip()
            except Exception as e:
                logger.error(f"Compare config failed: {e}")
        
        return diff

    def commit_config(self, message="", revert_in=None):
        """Commit configuration."""
        try:
            if revert_in:
                self.device.commit(confirmed=True, timeout=str(revert_in), comment=message)
            else:
                self.device.commit(comment=message if message else None)
            self.pending_changes = False
            self._unlock()
        except Exception as e:
            logger.error(f"Commit failed: {e}")
            raise

    def discard_config(self):
        """Discard changes."""
        try:
            self.device.discard_changes()
            self.pending_changes = False
            self._unlock()
        except Exception as e:
            logger.error(f"Discard failed: {e}")

    def rollback(self):
        """Rollback to previous commit."""
        try:
            rpc_cmd = "<load-configuration rollback='1'/>"
            self._rpc(rpc_cmd)
            self.device.commit()
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            raise

    # =====================================================================
    # FACTS AND SYSTEM INFORMATION
    # =====================================================================

    def get_facts(self):
        """Return facts of the device."""
        facts = {
            "vendor": "Juniper",
            "os_version": "",
            "hostname": "",
            "uptime": -1.0,
            "serial_number": "",
            "fqdn": "",
            "model": "",
            "interface_list": [],
        }
        
        try:
            # Get software information
            rpc_cmd = "<get-software-information/>"
            tree = self._rpc(rpc_cmd)
            facts["os_version"] = self._find_text(tree, './/junos-version', '')
            
            # Get system information
            rpc_cmd = "<get-system-information/>"
            tree = self._rpc(rpc_cmd)
            facts["hostname"] = self._find_text(tree, './/host-name', '')
            facts["fqdn"] = facts["hostname"]
            facts["model"] = self._find_text(tree, './/product-model', '')
            facts["serial_number"] = self._find_text(tree, './/serial-number', '')
            
            # Get uptime
            # Get uptime - TRY MULTIPLE METHODS
            uptime_found = False
            
            # Method 1: Try 'up-time' field
            uptime_str = self._find_text(tree, './/up-time', '')
            if uptime_str:
                logger.debug(f"Method 1 - Found up-time: '{uptime_str}'")
                uptime = self._parse_uptime(uptime_str)
                if uptime > 0:
                    facts["uptime"] = uptime
                    uptime_found = True
                    logger.info(f"Uptime successfully parsed: {uptime} seconds")
            
            # Method 2: Try 'uptime-information' (some Junos versions)
            if not uptime_found:
                uptime_str = self._find_text(tree, './/uptime-information', '')
                if uptime_str:
                    logger.debug(f"Method 2 - Found uptime-information: '{uptime_str}'")
                    uptime = self._parse_uptime(uptime_str)
                    if uptime > 0:
                        facts["uptime"] = uptime
                        uptime_found = True
                        logger.info(f"Uptime successfully parsed: {uptime} seconds")
            
            # Method 3: Try 'current-time' to calculate uptime
            if not uptime_found:
                try:
                    # Get system uptime via RPC
                    rpc_cmd = "<get-system-uptime-information/>"
                    uptime_tree = self._rpc(rpc_cmd)
                    
                    # Try multiple XPath patterns
                    uptime_patterns = [
                        './/system-uptime-information/uptime-information/up-time',
                        './/uptime-information/up-time',
                        './/up-time',
                        './/current-time/time-length'
                    ]
                    
                    for pattern in uptime_patterns:
                        uptime_str = self._find_text(uptime_tree, pattern, '')
                        if uptime_str:
                            logger.debug(f"Method 3 - Found via pattern '{pattern}': '{uptime_str}'")
                            uptime = self._parse_uptime(uptime_str)
                            if uptime > 0:
                                facts["uptime"] = uptime
                                uptime_found = True
                                logger.info(f"Uptime successfully parsed: {uptime} seconds")
                                break
                except Exception as uptime_err:
                    logger.debug(f"Method 3 failed: {uptime_err}")
            
            if not uptime_found:
                logger.warning("Could not determine device uptime")
                facts["uptime"] = 0.0
            
            # Get interface list
            rpc_cmd = "<get-interface-information><terse/></get-interface-information>"
            tree = self._rpc(rpc_cmd)
            interfaces = []
            for iface in tree.xpath('.//physical-interface/name'):
                if iface.text:
                    iface_name = iface.text.strip().replace('\n', '').replace('\r', '')
                    if iface_name:
                        interfaces.append(iface_name)
            facts["interface_list"] = interfaces
            
        except Exception as e:
            logger.error(f"Failed to get facts: {e}")
        
        return facts

    def _parse_uptime(self, uptime_str):
        """Parse Junos uptime string to seconds - ENHANCED."""
        try:
            logger.debug(f"Parsing uptime string: '{uptime_str}'")
            seconds = 0
            
            # Handle multiple formats:
            # Format 1: "1 day, 2 hours, 30 minutes, 45 seconds"
            # Format 2: "5 days, 3:45:30" (days, hours:minutes:seconds)
            # Format 3: "3:45:30" (hours:minutes:seconds)
            # Format 4: "123 days 4 hrs 56 mins 12 secs"
            
            uptime_lower = uptime_str.lower()
            
            # Try to extract days
            if 'day' in uptime_lower:
                day_match = re.search(r'(\d+)\s*day', uptime_lower)
                if day_match:
                    days = int(day_match.group(1))
                    seconds += days * 86400
                    logger.debug(f"  Days: {days}")
            
            # Try to extract hours (word format)
            if 'hour' in uptime_lower or 'hr' in uptime_lower:
                hour_match = re.search(r'(\d+)\s*(?:hour|hr)', uptime_lower)
                if hour_match:
                    hours = int(hour_match.group(1))
                    seconds += hours * 3600
                    logger.debug(f"  Hours: {hours}")
            
            # Try to extract minutes (word format)
            if 'minute' in uptime_lower or 'min' in uptime_lower:
                min_match = re.search(r'(\d+)\s*(?:minute|min)', uptime_lower)
                if min_match:
                    minutes = int(min_match.group(1))
                    seconds += minutes * 60
                    logger.debug(f"  Minutes: {minutes}")
            
            # Try to extract seconds (word format)
            if 'second' in uptime_lower or 'sec' in uptime_lower:
                sec_match = re.search(r'(\d+)\s*(?:second|sec)', uptime_lower)
                if sec_match:
                    secs = int(sec_match.group(1))
                    seconds += secs
                    logger.debug(f"  Seconds: {secs}")
            
            # Try time format (HH:MM:SS or H:MM:SS)
            time_match = re.search(r'(\d+):(\d+):(\d+)', uptime_str)
            if time_match and seconds == 0:  # Only if we haven't parsed anything yet
                hours = int(time_match.group(1))
                minutes = int(time_match.group(2))
                secs = int(time_match.group(3))
                seconds = hours * 3600 + minutes * 60 + secs
                logger.debug(f"  Time format: {hours}h {minutes}m {secs}s")
            
            logger.debug(f"  Total uptime: {seconds} seconds")
            return float(seconds) if seconds > 0 else 0.0
            
        except Exception as e:
            logger.warning(f"Failed to parse uptime '{uptime_str}': {e}")
            return 0.0

    # =====================================================================
    # INTERFACE METHODS
    # =====================================================================

    def get_interfaces(self):
        """Return interfaces details."""
        interfaces = {}
        
        try:
            rpc_cmd = "<get-interface-information><extensive/></get-interface-information>"
            tree = self._rpc(rpc_cmd)
            
            for iface in tree.xpath('.//physical-interface'):
                name = self._find_text(iface, './/name', '')
                if not name:
                    continue
                
                admin_status = self._find_text(iface, './/admin-status', 'down')
                oper_status = self._find_text(iface, './/oper-status', 'down')
                mac_address = self._find_text(iface, './/hardware-physical-address', '')
                description = self._find_text(iface, './/description', '')
                
                # Parse speed
                speed = -1.0
                speed_text = self._find_text(iface, './/speed', '')
                if speed_text:
                    try:
                        if 'Gbps' in speed_text:
                            speed = float(speed_text.replace('Gbps', '').strip()) * 1000
                        elif 'Mbps' in speed_text:
                            speed = float(speed_text.replace('Mbps', '').strip())
                    except:
                        pass
                
                # Parse MTU
                mtu = 1514
                try:
                    mtu = int(self._find_text(iface, './/mtu', '1514'))
                except:
                    pass
                
                interfaces[name] = {
                    "is_enabled": admin_status.lower() == 'up',
                    "is_up": oper_status.lower() == 'up',
                    "mac_address": mac_address,
                    "description": description,
                    "speed": speed,
                    "mtu": mtu,
                    "last_flapped": -1.0
                }
                
        except Exception as e:
            logger.error(f"Failed to get interfaces: {e}")
        
        return interfaces

    def get_interfaces_counters(self):
        """Return interfaces counters."""
        counters = {}
        
        try:
            rpc_cmd = "<get-interface-information><statistics/></get-interface-information>"
            tree = self._rpc(rpc_cmd)
            
            for iface in tree.xpath('.//physical-interface'):
                name = self._find_text(iface, './/name', '')
                if not name:
                    continue
                
                stats = iface.find('.//traffic-statistics')
                if stats is not None:
                    counters[name] = {
                        "tx_errors": int(self._find_text(stats, './/output-errors', '0')),
                        "rx_errors": int(self._find_text(stats, './/input-errors', '0')),
                        "tx_discards": int(self._find_text(stats, './/output-drops', '0')),
                        "rx_discards": int(self._find_text(stats, './/input-drops', '0')),
                        "tx_octets": int(self._find_text(stats, './/output-bytes', '0')),
                        "rx_octets": int(self._find_text(stats, './/input-bytes', '0')),
                        "tx_unicast_packets": int(self._find_text(stats, './/output-packets', '0')),
                        "rx_unicast_packets": int(self._find_text(stats, './/input-packets', '0')),
                        "tx_multicast_packets": 0,
                        "rx_multicast_packets": 0,
                        "tx_broadcast_packets": 0,
                        "rx_broadcast_packets": 0
                    }
                    
        except Exception as e:
            logger.error(f"Failed to get interface counters: {e}")
        
        return counters

    def get_interfaces_ip(self):
        """Return the configured IP addresses - Version 2 with RPC fallback."""
        interfaces_ip = {}
        
        try:
            logger.info("Starting IP address collection...")
            
            # METHOD 1: Try RPC command first (more reliable)
            try:
                logger.debug("Trying RPC method for IP addresses...")
                rpc_cmd = "<get-interface-information><terse/></get-interface-information>"
                tree = self._rpc(rpc_cmd)
                
                logical_ifaces = tree.xpath('.//logical-interface')
                logger.info(f"Found {len(logical_ifaces)} logical interfaces via RPC")
                
                for liface in logical_ifaces:
                    name_elem = liface.find('.//name')
                    if name_elem is None or name_elem.text is None:
                        continue
                    
                    iface_name = name_elem.text.strip()
                    
                    if iface_name not in interfaces_ip:
                        interfaces_ip[iface_name] = {}
                    
                    # Get address families
                    for addr_family in liface.xpath('.//address-family'):
                        af_name_elem = addr_family.find('.//address-family-name')
                        if af_name_elem is None or af_name_elem.text is None:
                            continue
                        
                        af_name = af_name_elem.text.strip()
                        
                        # Get local addresses
                        for ifa_local in addr_family.xpath('.//ifa-local'):
                            if ifa_local.text is None:
                                continue
                            
                            addr_text = ifa_local.text.strip()
                            
                            if af_name == 'inet' and addr_text:
                                # IPv4
                                if "ipv4" not in interfaces_ip[iface_name]:
                                    interfaces_ip[iface_name]["ipv4"] = {}
                                
                                # Try to get prefix from destination
                                ifa_dest = addr_family.find('.//ifa-destination')
                                if ifa_dest is not None and ifa_dest.text and '/' in ifa_dest.text:
                                    prefix_len = int(ifa_dest.text.strip().split('/')[1])
                                else:
                                    prefix_len = 32
                                
                                interfaces_ip[iface_name]["ipv4"][addr_text] = {
                                    "prefix_length": prefix_len
                                }
                                logger.debug(f"  {iface_name}: IPv4 {addr_text}/{prefix_len}")
                            
                            elif af_name == 'inet6' and addr_text:
                                # IPv6
                                if '/' in addr_text:
                                    ip_addr, prefix = addr_text.split('/', 1)
                                    if "ipv6" not in interfaces_ip[iface_name]:
                                        interfaces_ip[iface_name]["ipv6"] = {}
                                    interfaces_ip[iface_name]["ipv6"][ip_addr] = {
                                        "prefix_length": int(prefix)
                                    }
                                    logger.debug(f"  {iface_name}: IPv6 {ip_addr}/{prefix}")
                
                if interfaces_ip:
                    logger.info(f"RPC method successful: Found IPs on {len(interfaces_ip)} interfaces")
                    return interfaces_ip
            
            except Exception as rpc_err:
                logger.warning(f"RPC method failed: {rpc_err}, trying config method...")
            
            # METHOD 2: Fall back to config parsing
            try:
                logger.debug("Trying config parsing method for IP addresses...")
                config_reply = self.device.get_config(source="running")
                tree = self._get_config_tree(source="running")
                
                interfaces_found = tree.xpath('.//interfaces/interface')
                logger.info(f"Found {len(interfaces_found)} interfaces in config")
                
                for iface in interfaces_found:
                    iface_name_elem = iface.find('.//name')
                    if iface_name_elem is None or iface_name_elem.text is None:
                        continue
                    
                    iface_name = iface_name_elem.text.strip()
                    
                    units = iface.xpath('.//unit')
                    
                    for unit in units:
                        unit_num_elem = unit.find('./name')
                        unit_num = unit_num_elem.text.strip() if unit_num_elem is not None and unit_num_elem.text else '0'
                        
                        if unit_num and unit_num != '0':
                            full_name = f"{iface_name}.{unit_num}"
                        else:
                            full_name = iface_name
                        
                        if full_name not in interfaces_ip:
                            interfaces_ip[full_name] = {}
                        
                        # IPv4
                        inet_family = unit.find('./family/inet')
                        if inet_family is not None:
                            for addr in inet_family.xpath('./address'):
                                addr_name_elem = addr.find('./name')
                                if addr_name_elem is not None and addr_name_elem.text:
                                    addr_text = addr_name_elem.text.strip()
                                    if '/' in addr_text:
                                        ip_addr, prefix = addr_text.split('/', 1)
                                        if "ipv4" not in interfaces_ip[full_name]:
                                            interfaces_ip[full_name]["ipv4"] = {}
                                        interfaces_ip[full_name]["ipv4"][ip_addr.strip()] = {
                                            "prefix_length": int(prefix.strip())
                                        }
                        
                        # IPv6
                        inet6_family = unit.find('./family/inet6')
                        if inet6_family is not None:
                            for addr in inet6_family.xpath('./address'):
                                addr_name_elem = addr.find('./name')
                                if addr_name_elem is not None and addr_name_elem.text:
                                    addr_text = addr_name_elem.text.strip()
                                    if '/' in addr_text:
                                        ip_addr, prefix = addr_text.split('/', 1)
                                        if "ipv6" not in interfaces_ip[full_name]:
                                            interfaces_ip[full_name]["ipv6"] = {}
                                        interfaces_ip[full_name]["ipv6"][ip_addr.strip()] = {
                                            "prefix_length": int(prefix.strip())
                                        }
            
            except Exception as config_err:
                logger.error(f"Config parsing also failed: {config_err}")
            
            logger.info(f"Total interfaces with IPs: {len(interfaces_ip)}")
            
        except Exception as e:
            logger.error(f"Failed to get interface IPs: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return interfaces_ip

    # =====================================================================
    # BGP METHODS
    # =====================================================================

    def get_bgp_neighbors(self):
        """Return BGP neighbors details."""
        bgp_neighbors = {}
        
        try:
            rpc_cmd = "<get-bgp-neighbor-information/>"
            tree = self._rpc(rpc_cmd)
            
            # Get global router ID
            router_id = self._find_text(tree, './/local-id', '0.0.0.0')
            
            bgp_neighbors["global"] = {
                "router_id": router_id,
                "peers": {}
            }
            
            for peer in tree.xpath('.//bgp-peer'):
                peer_address = self._find_text(peer, './/peer-address', '')
                if not peer_address:
                    continue
                
                peer_state = self._find_text(peer, './/peer-state', '')
                peer_as = int(self._find_text(peer, './/peer-as', '0'))
                local_as = int(self._find_text(peer, './/local-as', '0'))
                
                bgp_neighbors["global"]["peers"][peer_address] = {
                    "local_as": local_as,
                    "remote_as": peer_as,
                    "remote_id": self._find_text(peer, './/peer-id', ''),
                    "is_up": peer_state.lower() == 'established',
                    "is_enabled": True,
                    "description": self._find_text(peer, './/description', ''),
                    "uptime": -1,
                    "address_family": {
                        "ipv4": {
                            "received_prefixes": int(self._find_text(peer, './/bgp-rib[@name="inet.0"]/received-prefix-count', '0')),
                            "accepted_prefixes": int(self._find_text(peer, './/bgp-rib[@name="inet.0"]/accepted-prefix-count', '0')),
                            "sent_prefixes": int(self._find_text(peer, './/bgp-rib[@name="inet.0"]/advertised-prefix-count', '0'))
                        }
                    }
                }
                
        except Exception as e:
            logger.error(f"Failed to get BGP neighbors: {e}")
        
        return bgp_neighbors

    def get_bgp_config(self, group="", neighbor=""):
        """Return BGP configuration."""
        bgp_config = {}
        
        try:
            config_reply = self.device.get_config(source="running")
              # Use data_ele instead of data
            config_tree = self._get_config_tree(source="running")
            # Parse BGP configuration from XML
            # This is a simplified implementation
            bgp_config["_"] = {
                "apply_groups": [],
                "description": "",
                "local_as": 0,
                "type": "",
                "import_policy": "",
                "export_policy": "",
                "local_address": "",
                "multipath": False,
                "multihop_ttl": 0,
                "remote_as": 0,
                "remove_private_as": False,
                "prefix_limit": {},
                "neighbors": {}
            }
            
        except Exception as e:
            logger.error(f"Failed to get BGP config: {e}")
        
        return bgp_config

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        """Detailed view of the BGP neighbors operational data."""
        bgp_detail = {"global": {}}
        
        try:
            rpc_cmd = "<get-bgp-neighbor-information/>"
            tree = self._rpc(rpc_cmd)
            
            for peer in tree.xpath('.//bgp-peer'):
                peer_address = self._find_text(peer, './/peer-address', '')
                if neighbor_address and peer_address != neighbor_address:
                    continue
                
                remote_as = int(self._find_text(peer, './/peer-as', '0'))
                
                if remote_as not in bgp_detail["global"]:
                    bgp_detail["global"][remote_as] = []
                
                peer_state = self._find_text(peer, './/peer-state', '')
                
                bgp_detail["global"][remote_as].append({
                    "up": peer_state.lower() == 'established',
                    "local_as": int(self._find_text(peer, './/local-as', '0')),
                    "remote_as": remote_as,
                    "router_id": self._find_text(peer, './/peer-id', ''),
                    "local_address": self._find_text(peer, './/local-address', ''),
                    "remote_address": peer_address,
                    "remote_port": 179,
                    "local_port": 179,
                    "multihop": False,
                    "import_policy": "",
                    "export_policy": "",
                    "connection_state": peer_state.replace('-', ' ').title(),
                    "previous_connection_state": "",
                    "routing_table": "global",
                    "holdtime": 90,
                    "keepalive": 30,
                    "configured_holdtime": 90,
                    "configured_keepalive": 30,
                    "active_prefix_count": int(self._find_text(peer, './/bgp-rib[@name="inet.0"]/active-prefix-count', '0')),
                    "received_prefix_count": int(self._find_text(peer, './/bgp-rib[@name="inet.0"]/received-prefix-count', '0')),
                    "accepted_prefix_count": int(self._find_text(peer, './/bgp-rib[@name="inet.0"]/accepted-prefix-count', '0')),
                    "suppressed_prefix_count": int(self._find_text(peer, './/bgp-rib[@name="inet.0"]/suppressed-prefix-count', '0')),
                    "advertised_prefix_count": int(self._find_text(peer, './/bgp-rib[@name="inet.0"]/advertised-prefix-count', '0')),
                    "flap_count": int(self._find_text(peer, './/flap-count', '0'))
                })
                
        except Exception as e:
            logger.error(f"Failed to get BGP neighbors detail: {e}")
        
        return bgp_detail

    # =====================================================================
    # LLDP METHODS
    # =====================================================================

    def get_lldp_neighbors(self):
        """Return LLDP neighbors details."""
        lldp_neighbors = {}
        
        try:
            rpc_cmd = "<get-lldp-neighbors-information/>"
            tree = self._rpc(rpc_cmd)
            
            for neighbor in tree.xpath('.//lldp-neighbor-information'):
                local_interface = self._find_text(neighbor, './/lldp-local-port-id', '')
                if not local_interface:
                    continue
                
                remote_chassis_id = self._find_text(neighbor, './/lldp-remote-chassis-id', '')
                remote_port_id = self._find_text(neighbor, './/lldp-remote-port-id', '')
                remote_system_name = self._find_text(neighbor, './/lldp-remote-system-name', '')
                
                if local_interface not in lldp_neighbors:
                    lldp_neighbors[local_interface] = []
                
                lldp_neighbors[local_interface].append({
                    "hostname": remote_system_name,
                    "port": remote_port_id
                })
                
        except Exception as e:
            logger.error(f"Failed to get LLDP neighbors: {e}")
        
        return lldp_neighbors

    def get_lldp_neighbors_detail(self, interface=""):
        """Detailed view of the LLDP neighbors."""
        lldp_detail = {}
        
        try:
            rpc_cmd = "<get-lldp-neighbors-information/>"
            tree = self._rpc(rpc_cmd)
            
            for neighbor in tree.xpath('.//lldp-neighbor-information'):
                local_interface = self._find_text(neighbor, './/lldp-local-port-id', '')
                if not local_interface:
                    continue
                if interface and local_interface != interface:
                    continue
                
                if local_interface not in lldp_detail:
                    lldp_detail[local_interface] = []
                
                lldp_detail[local_interface].append({
                    "parent_interface": "",
                    "remote_chassis_id": self._find_text(neighbor, './/lldp-remote-chassis-id', ''),
                    "remote_port": self._find_text(neighbor, './/lldp-remote-port-id', ''),
                    "remote_port_description": self._find_text(neighbor, './/lldp-remote-port-description', ''),
                    "remote_system_name": self._find_text(neighbor, './/lldp-remote-system-name', ''),
                    "remote_system_description": self._find_text(neighbor, './/lldp-remote-system-description', ''),
                    "remote_system_capab": [],
                    "remote_system_enable_capab": []
                })
                
        except Exception as e:
            logger.error(f"Failed to get LLDP neighbors detail: {e}")
        
        return lldp_detail

    # =====================================================================
    # ARP AND MAC TABLE METHODS
    # =====================================================================

    def get_arp_table(self, vrf=""):
        """Return the ARP table."""
        arp_table = []
        
        try:
            rpc_cmd = "<get-arp-table-information/>"
            tree = self._rpc(rpc_cmd)
            
            for entry in tree.xpath('.//arp-table-entry'):
                mac_address = self._find_text(entry, './/mac-address', '')
                ip_address = self._find_text(entry, './/ip-address', '')
                interface_name = self._find_text(entry, './/interface-name', '')
                
                if mac_address and ip_address:
                    arp_table.append({
                        "interface": interface_name,
                        "mac": mac_address,
                        "ip": ip_address,
                        "age": 0.0
                    })
                    
        except Exception as e:
            logger.error(f"Failed to get ARP table: {e}")
        
        return arp_table

    def get_mac_address_table(self):
        """Return the MAC address table."""
        mac_table = []
        
        try:
            # Try layer2 table first
            rpc_cmd = "<get-ethernet-switching-table-information/>"
            tree = self._rpc(rpc_cmd)
            
            for entry in tree.xpath('.//ethernet-switching-table/ethernet-switching-table-entry'):
                mac_address = self._find_text(entry, './/mac-address', '')
                vlan_name = self._find_text(entry, './/vlan-name', '')
                interface_name = self._find_text(entry, './/interface-name', '')
                
                # Extract VLAN ID from name
                vlan = 0
                try:
                    vlan = int(vlan_name.replace('vlan', '').replace('VLAN', ''))
                except:
                    pass
                
                if mac_address:
                    mac_table.append({
                        "mac": mac_address,
                        "interface": interface_name,
                        "vlan": vlan,
                        "active": True,
                        "static": False,
                        "moves": 0,
                        "last_move": 0.0
                    })
                if not mac_table:
                    try:
                        rpc_cmd = "<get-bridge-mac-table/>"
                        tree = self._rpc(rpc_cmd)
                        for entry in tree.xpath('.//l2ng-l2ald-mac-entry-vlan'):
                            mac_address = self._find_text(entry, './/l2ng-l2-mac-address', '')
                            if mac_address:
                                mac_table.append({
                                    "mac": mac_address,
                                    "interface": self._find_text(entry, './/l2ng-l2-mac-logical-interface', ''),
                                    "vlan": int(self._find_text(entry, './/l2ng-l2-vlan-id', '0')),
                                    "active": True,
                                    "static": False,
                                    "moves": 0,
                                    "last_move": 0.0
                                })
                    except:
                        pass
        except Exception as e:
            logger.error(f"Failed to get MAC table: {e}")
        
        return mac_table

    # =====================================================================
    # NTP METHODS
    # =====================================================================

    def get_ntp_peers(self):
        """Return NTP peers - Version 2 with enhanced debug."""
        ntp_peers = {}
        
        try:
            logger.info("Starting NTP peer collection...")
            config_reply = self.device.get_config(source="running")
            tree = self._get_config_tree(source="running")
            
            peer_paths = [
                ('.//ntp/peer', 'ntp/peer'),
                ('.//system/ntp/peer', 'system/ntp/peer'),
                ('.//peer', 'just peer')
            ]
            
            for xpath, desc in peer_paths:
                logger.debug(f"Trying XPath: {xpath} ({desc})")
                peers = tree.xpath(xpath)
                logger.debug(f"  Found {len(peers)} elements")
                
                if peers:
                    for peer_idx, peer in enumerate(peers, 1):
                        peer_name_elem = peer.find('.//name')
                        if peer_name_elem is None:
                            peer_name_elem = peer.find('./name')
                        if peer_name_elem is None:
                            if peer.text:
                                peer_name = peer.text.strip()
                            else:
                                logger.debug(f"  Peer {peer_idx}: No name found")
                                continue
                        else:
                            if peer_name_elem.text:
                                peer_name = peer_name_elem.text.strip()
                            else:
                                continue
                        
                        ntp_peers[peer_name] = {}
                        logger.debug(f"  Found NTP peer: {peer_name}")
                    
                    if ntp_peers:
                        logger.info(f"Success! Found {len(ntp_peers)} NTP peers")
                        break
            
            if not ntp_peers:
                logger.warning("No NTP peers found in configuration")
                            
        except Exception as e:
            logger.error(f"Failed to get NTP peers: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return ntp_peers


    
    def get_ntp_servers(self):
        """Return NTP servers - Version 2 with enhanced debug."""
        ntp_servers = {}
        
        try:
            logger.info("Starting NTP server collection...")
            config_reply = self.device.get_config(source="running")
            tree = self._get_config_tree(source="running")

            
            server_paths = [
                ('.//ntp/server', 'ntp/server'),
                ('.//system/ntp/server', 'system/ntp/server'),
                ('.//server', 'just server')
            ]
            
            for xpath, desc in server_paths:
                logger.debug(f"Trying XPath: {xpath} ({desc})")
                servers = tree.xpath(xpath)
                logger.debug(f"  Found {len(servers)} elements")
                
                if servers:
                    for server_idx, server in enumerate(servers, 1):
                        # Try multiple ways to get server name
                        server_name_elem = server.find('.//name')
                        if server_name_elem is None:
                            server_name_elem = server.find('./name')
                        if server_name_elem is None:
                            # Maybe the text is directly in the server element
                            if server.text:
                                server_name = server.text.strip()
                            else:
                                logger.debug(f"  Server {server_idx}: No name found")
                                continue
                        else:
                            if server_name_elem.text:
                                server_name = server_name_elem.text.strip()
                            else:
                                continue
                        
                        ntp_servers[server_name] = {}
                        logger.debug(f"  Found NTP server: {server_name}")
                    
                    if ntp_servers:
                        logger.info(f"Success! Found {len(ntp_servers)} NTP servers")
                        break
            
            if not ntp_servers:
                logger.warning("No NTP servers found in configuration")
                            
        except Exception as e:
            logger.error(f"Failed to get NTP servers: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return ntp_servers



    def get_ntp_stats(self):
        """Return NTP stats (associations) - FIXED."""
        ntp_stats = []
        
        try:
            rpc_cmd = "<get-ntp-associations-information/>"
            tree = self._rpc(rpc_cmd)
            
            # Junos uses peer elements
            for peer in tree.xpath('.//peer'):
                peer_address = self._find_text(peer, './/peeraddress', '')
                if not peer_address:
                    continue
                
                # Check synchronization status
                condition = self._find_text(peer, './/condition', '')
                synchronized = '*' in condition or 'sys.peer' in condition
                
                ntp_stats.append({
                    "remote": peer_address,
                    "synchronized": synchronized,
                    "referenceid": self._find_text(peer, './/referenceid', ''),
                    "stratum": int(self._find_text(peer, './/stratum', '0')),
                    "type": self._find_text(peer, './/peertype', ''),
                    "when": self._find_text(peer, './/when', ''),
                    "hostpoll": int(self._find_text(peer, './/hostpoll', '0')),
                    "reachability": int(self._find_text(peer, './/reach', '0')),
                    "delay": float(self._find_text(peer, './/delay', '0.0')),
                    "offset": float(self._find_text(peer, './/offset', '0.0')),
                    "jitter": float(self._find_text(peer, './/jitter', '0.0'))
                })
                
        except Exception as e:
            logger.error(f"Failed to get NTP stats: {e}")
        
        return ntp_stats

    # =====================================================================
    # ENVIRONMENT AND HARDWARE
    # =====================================================================

    def get_environment(self):
        """Return environment details - Version 2 with enhanced temperature parsing."""
        environment = {
            "fans": {},
            "temperature": {},
            "power": {},
            "cpu": {},
            "memory": {}
        }
        
        try:
            logger.info("Starting environment data collection...")
            
            # Get chassis environment information
            rpc_cmd = "<get-environment-information/>"
            tree = self._rpc(rpc_cmd)
            
            # Parse fans
            fans = tree.xpath('.//environment-item[class="Fans"]')
            logger.debug(f"Found {len(fans)} fan entries")
            
            for fan in fans:
                name = self._find_text(fan, './/name', '')
                status = self._find_text(fan, './/status', '')
                if name:
                    environment["fans"][name] = {
                        "status": status.lower() == 'ok'
                    }
                    logger.debug(f"  Fan {name}: {status}")
            
            # Parse temperature sensors - ENHANCED
            # Parse temperature sensors - ENHANCED
            temp_sensors = tree.xpath('.//environment-item[class="Temp"]')
            logger.debug(f"Found {len(temp_sensors)} temperature sensors")

            for temp_idx, temp in enumerate(temp_sensors, 1):
                name = self._find_text(temp, './/name', '')
                temp_reading = self._find_text(temp, './/temperature', '')  # Changed default from '0' to ''
                status = self._find_text(temp, './/status', '')
                
                logger.debug(f"  Sensor {temp_idx}: name='{name}', temp_reading='{temp_reading}', status='{status}'")
                
                # Enhanced temperature parsing
                temp_value = 0.0
                
                # Skip if status indicates sensor is absent
                if status and status.lower() in ['absent', 'not present', 'n/a']:
                    logger.debug(f"    Sensor {name} is {status}, skipping")
                    # Don't add absent sensors to the environment dict
                    continue
                
                if temp_reading and temp_reading.strip():
                    try:
                        # Clean up the temperature string
                        temp_clean = temp_reading.strip()
                        
                        # Handle "36 degrees C / 96 degrees F" format
                        if 'degrees C' in temp_clean or 'degrees F' in temp_clean:
                            # Extract just the Celsius value (first number before "degrees C")
                            if 'degrees C' in temp_clean:
                                celsius_part = temp_clean.split('degrees C')[0].strip()
                                # Remove any leading text, keep just the number
                                import re
                                match = re.search(r'(\d+\.?\d*)', celsius_part)
                                if match:
                                    temp_value = float(match.group(1))
                                    logger.debug(f"    Parsed from 'degrees C' format: {temp_value}°C")
                        else:
                            # Try other formats
                            # Remove various suffixes
                            suffixes = ['°C', '°C', 'C', ' C', 'degrees', 'Degrees']
                            for suffix in suffixes:
                                temp_clean = temp_clean.replace(suffix, '')
                            
                            temp_clean = temp_clean.strip()
                            
                            # Try to parse as float
                            if temp_clean and temp_clean.lower() not in ['ok', 'absent', 'n/a', 'na', 'not present']:
                                # Extract just numbers
                                import re
                                match = re.search(r'(\d+\.?\d*)', temp_clean)
                                if match:
                                    temp_value = float(match.group(1))
                                    logger.debug(f"    Parsed temperature: {temp_value}°C")
                        
                    except (ValueError, AttributeError) as parse_err:
                        logger.debug(f"    Failed to parse '{temp_reading}': {parse_err}")
                        
                        # Try alternate fields
                        try:
                            alt_temp = self._find_text(temp, './/temp', '')
                            if alt_temp and alt_temp.strip():
                                temp_value = float(alt_temp)
                                logger.debug(f"    Used alternate field: {temp_value}°C")
                        except:
                            pass
                
                # Only add sensors that have a name and are not absent
                if name and name.strip():
                    # Determine alert status based on status field
                    is_alert = False
                    is_critical = False
                    
                    if status:
                        status_lower = status.lower()
                        # "OK" or empty = normal, anything else = alert
                        is_alert = status_lower not in ['ok', '']
                        is_critical = status_lower in ['critical', 'check', 'failure', 'fail']
                    
                    environment["temperature"][name] = {
                        "temperature": temp_value,
                        "is_alert": is_alert,
                        "is_critical": is_critical
                    }
                    
                    logger.debug(f"    Final: {temp_value}°C, alert={is_alert}, critical={is_critical}")
            
            # Parse power supplies
            power_supplies = tree.xpath('.//environment-item[class="Power"]')
            logger.debug(f"Found {len(power_supplies)} power supplies")
            
            for psu in power_supplies:
                name = self._find_text(psu, './/name', '')
                status = self._find_text(psu, './/status', '')
                if name:
                    environment["power"][name] = {
                        "status": status.lower() == 'ok',
                        "capacity": -1.0,
                        "output": -1.0
                    }
                    logger.debug(f"  PSU {name}: {status}")
            
            # Get CPU and memory information
            logger.debug("Getting CPU and memory info...")
            rpc_cmd = "<get-system-information/>"
            tree = self._rpc(rpc_cmd)
            
            # CPU usage
            route_engines = tree.xpath('.//route-engine')
            logger.debug(f"Found {len(route_engines)} route engines")
            
            for re_node in route_engines:
                re_slot_elem = re_node.find('.//slot')
                if re_slot_elem is None:
                    re_slot_elem = re_node.find('./slot')
                re_name = re_slot_elem.text.strip() if re_slot_elem is not None and re_slot_elem.text else 'RE0'
                
                cpu_idle_elem = re_node.find('.//cpu-idle')
                if cpu_idle_elem is None:
                    cpu_idle_elem = re_node.find('./cpu-idle')
                cpu_idle = cpu_idle_elem.text.strip() if cpu_idle_elem is not None and cpu_idle_elem.text else '0'
                
                try:
                    cpu_usage = 100 - float(cpu_idle)
                except (ValueError, TypeError):
                    cpu_usage = 0.0
                
                environment["cpu"][re_name] = {
                    "%usage": cpu_usage
                }
                logger.debug(f"  {re_name} CPU: {cpu_usage}%")
                
                # Memory - Enhanced parsing
                memory_total_elem = re_node.find('.//memory-dram-size')
                if memory_total_elem is None:
                    memory_total_elem = re_node.find('./memory-dram-size')
                
                memory_used_elem = re_node.find('.//memory-buffer-utilization')
                if memory_used_elem is None:
                    memory_used_elem = re_node.find('./memory-buffer-utilization')
                
                try:
                    if memory_total_elem is not None and memory_total_elem.text:
                        total_text = memory_total_elem.text.strip()
                        # Handle formats like "2048" or "2048 MB" or "2048MB"
                        total_parts = total_text.split()
                        total = int(total_parts[0])
                        
                        used = 0
                        if memory_used_elem is not None and memory_used_elem.text:
                            used_text = memory_used_elem.text.strip()
                            used_parts = used_text.split()
                            used = int(used_parts[0])
                        
                        environment["memory"] = {
                            "available_ram": total,
                            "used_ram": used
                        }
                        logger.debug(f"  Memory: {used}/{total} MB")
                except (ValueError, AttributeError, IndexError) as mem_err:
                    logger.warning(f"Memory parsing failed: {mem_err}")
            
            # Generate temperature alarms
            environment["alarms_from_temp"] = []
            for sensor, temp_info in environment["temperature"].items():
                if temp_info.get('is_alert') or temp_info.get('is_critical'):
                    environment["alarms_from_temp"].append({
                        'description': f'Temperature sensor {sensor} alert',
                        'severity': 'critical' if temp_info.get('is_critical') else 'minor',
                        'location': sensor,
                        'timestamp': datetime.now().isoformat(),
                        'type': 'temperature'
                    })
            
            logger.info(f"Environment data collected: {len(environment['fans'])} fans, "
                    f"{len(environment['temperature'])} temp sensors, "
                    f"{len(environment['power'])} PSUs, "
                    f"{len(environment['cpu'])} CPUs")
                    
        except Exception as e:
            logger.error(f"Failed to get environment: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return environment
    def get_hardware_inventory(self):
        """Return detailed hardware inventory - chassis, modules, FPCs, PICs."""
        hardware = {
            "chassis": {},
            "modules": []
        }
        
        try:
            logger.info("Collecting hardware inventory...")
            rpc_cmd = "<get-chassis-inventory/>"
            tree = self._rpc(rpc_cmd)
            
            # Get chassis info
            chassis_elem = tree.find('.//chassis')
            if chassis_elem is not None:
                hardware["chassis"] = {
                    "name": self._find_text(chassis_elem, './/name', ''),
                    "serial_number": self._find_text(chassis_elem, './/serial-number', ''),
                    "description": self._find_text(chassis_elem, './/description', ''),
                }
                logger.debug(f"Chassis: {hardware['chassis']}")
            
            # Get all modules (PEM, RE, FPC, MIC, etc.)
            for item in tree.xpath('.//chassis-module'):
                module = {
                    "name": self._find_text(item, './/name', ''),
                    "version": self._find_text(item, './/version', ''),
                    "part_number": self._find_text(item, './/part-number', ''),
                    "serial_number": self._find_text(item, './/serial-number', ''),
                    "description": self._find_text(item, './/description', ''),
                    "clei_code": self._find_text(item, './/clei-code', ''),
                    "model_number": self._find_text(item, './/model-number', ''),
                }
                
                # Only add if has meaningful data
                if module["name"]:
                    hardware["modules"].append(module)
                    logger.debug(f"  Module: {module['name']} - {module['description']}")
                
                # Check for sub-modules
                for sub_item in item.xpath('.//chassis-sub-module'):
                    sub_module = {
                        "name": self._find_text(sub_item, './/name', ''),
                        "version": self._find_text(sub_item, './/version', ''),
                        "part_number": self._find_text(sub_item, './/part-number', ''),
                        "serial_number": self._find_text(sub_item, './/serial-number', ''),
                        "description": self._find_text(sub_item, './/description', ''),
                        "parent": module["name"]
                    }
                    
                    if sub_module["name"]:
                        hardware["modules"].append(sub_module)
                        logger.debug(f"    Sub-module: {sub_module['name']} - {sub_module['description']}")
                    
                    # Check for sub-sub-modules (like transceivers)
                    for subsub_item in sub_item.xpath('.//chassis-sub-sub-module'):
                        subsub_module = {
                            "name": self._find_text(subsub_item, './/name', ''),
                            "version": self._find_text(subsub_item, './/version', ''),
                            "part_number": self._find_text(subsub_item, './/part-number', ''),
                            "serial_number": self._find_text(subsub_item, './/serial-number', ''),
                            "description": self._find_text(subsub_item, './/description', ''),
                            "parent": sub_module["name"]
                        }
                        
                        if subsub_module["name"]:
                            hardware["modules"].append(subsub_module)
                            logger.debug(f"      Sub-sub-module: {subsub_module['name']}")
            
            logger.info(f"✓ Hardware inventory collected: {len(hardware['modules'])} modules")
                    
        except Exception as e:
            logger.error(f"Failed to get hardware inventory: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return hardware


    def get_alarms(self):
        """Return active alarms on the device - FIXED."""
        alarms = []
        
        try:
            rpc_cmd = "<get-alarm-information/>"
            tree = self._rpc(rpc_cmd)
            
            # Try multiple possible alarm element names
            alarm_paths = [
                './/alarm-detail',
                './/alarm',
                './/alarm-information/alarm-detail',
                './/alarm-summary/alarm-detail'
            ]
            
            for xpath in alarm_paths:
                alarm_elements = tree.xpath(xpath)
                if alarm_elements:
                    for alarm in alarm_elements:
                        alarm_dict = {
                            'description': self._find_text(alarm, './/alarm-description | .//description', ''),
                            'severity': self._find_text(alarm, './/alarm-class | .//severity', ''),
                            'location': self._find_text(alarm, './/alarm-location | .//location', ''),
                            'timestamp': self._find_text(alarm, './/alarm-time | .//time', ''),
                            'type': self._find_text(alarm, './/alarm-type | .//type', ''),
                        }
                        if alarm_dict['description']:  # Only add if has description
                            alarms.append(alarm_dict)
                    break  # Exit after finding alarms
            
            # Add temperature alarms
            try:
                env_data = self.get_environment()
                temp_alarms = env_data.get("alarms_from_temp", [])
                alarms.extend(temp_alarms)
            except:
                pass
                    
        except Exception as e:
            logger.error(f"Failed to get alarms: {e}")
        
        return alarms
    # =====================================================================
    # ROUTING METHODS
    # =====================================================================

    def get_route_to(self, destination="", protocol="", longer=False):
        """Return route details to a specific destination."""
        routes = {}
        
        if not destination:
            return routes
        
        try:
            # Determine IP version
            try:
                ip_obj = ipaddress.ip_network(destination, strict=False)
                table = "inet.0" if ip_obj.version == 4 else "inet6.0"
            except:
                table = "inet.0"
            
            rpc_cmd = f"<get-route-information><table>{table}</table><destination>{destination}</destination></get-route-information>"
            tree = self._rpc(rpc_cmd)
            
            for route in tree.xpath('.//rt'):
                route_dest = self._find_text(route, './/rt-destination', '')
                if not route_dest:
                    continue
                
                if route_dest not in routes:
                    routes[route_dest] = []
                
                protocol_name = self._find_text(route, './/protocol-name', '')
                if protocol and protocol_name.lower() != protocol.lower():
                    continue
                
                for nh in route.xpath('.//rt-entry'):
                    next_hop = self._find_text(nh, './/nh/to', '')
                    preference = int(self._find_text(nh, './/preference', '0'))
                    age = self._find_text(nh, './/age', '')
                    
                    routes[route_dest].append({
                        "current_active": self._find_text(nh, './/current-active', '') == 'true',
                        "last_active": False,
                        "age": self._parse_age(age),
                        "next_hop": next_hop,
                        "protocol": protocol_name,
                        "outgoing_interface": self._find_text(nh, './/nh/via', ''),
                        "preference": preference,
                        "selected_next_hop": False,
                        "inactive_reason": "",
                        "routing_table": table,
                        "protocol_attributes": {}
                    })
                    
        except Exception as e:
            logger.error(f"Failed to get route to {destination}: {e}")
        
        return routes

    def _parse_age(self, age_str):
        """Parse Junos age string to seconds."""
        try:
            if 'w' in age_str:
                weeks = int(age_str.split('w')[0])
                return weeks * 604800
            elif 'd' in age_str:
                days = int(age_str.split('d')[0])
                return days * 86400
            elif ':' in age_str:
                parts = age_str.split(':')
                if len(parts) == 3:
                    return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
            return 0
        except:
            return 0
        
    def get_isis_neighbors(self):
        """Return ISIS neighbors details."""
        isis_neighbors = {}
        
        try:
            rpc_cmd = "<get-isis-adjacency-information/>"
            tree = self._rpc(rpc_cmd)
            
            for adj in tree.xpath('.//isis-adjacency'):
                interface = self._find_text(adj, './/interface-name', '')
                if not interface:
                    continue
                
                if interface not in isis_neighbors:
                    isis_neighbors[interface] = []
                
                isis_neighbors[interface].append({
                    "system_name": self._find_text(adj, './/system-name', ''),
                    "level": self._find_text(adj, './/level', ''),
                    "state": self._find_text(adj, './/adjacency-state', ''),
                    "holdtime": int(self._find_text(adj, './/holdtime', '0')),
                    "snpa": self._find_text(adj, './/snpa', '')
                })
                
        except Exception as e:
            logger.error(f"Failed to get ISIS neighbors: {e}")
        
        return isis_neighbors
    
    def get_route_summary(self, protocol=''):
        """Get routing table summary - ENHANCED VERSION."""
        route_summary = {
            'ipv4': {},
            'ipv6': {}
        }
        
        try:
            rpc_cmd = "<get-route-summary-information/>"
            tree = self._rpc(rpc_cmd)
            
            # Handle both table-name formats
            ipv4_tables = tree.xpath('.//route-table[contains(table-name, "inet.0")]')
            ipv6_tables = tree.xpath('.//route-table[contains(table-name, "inet6.0")]')
            
            # If above doesn't work, try without namespace
            if not ipv4_tables:
                ipv4_tables = tree.xpath('.//route-table[contains(., "inet.0")]')
            if not ipv6_tables:
                ipv6_tables = tree.xpath('.//route-table[contains(., "inet6.0")]')
            
            # Process IPv4
            for route_table in ipv4_tables:
                # Try multiple XPath patterns
                protos = route_table.xpath('.//protocol') or route_table.xpath('.//protocols/protocol')
                
                for proto in protos:
                    proto_name = self._find_text(proto, './/protocol-name', '')
                    route_count = int(self._find_text(proto, './/protocol-route-count', '0'))
                    
                    if proto_name:
                        route_summary['ipv4'][proto_name.lower()] = route_count
                
                # Get totals
                total = int(self._find_text(route_table, './/total-route-count', '0'))
                active = int(self._find_text(route_table, './/active-route-count', '0'))
                if total > 0:
                    route_summary['ipv4']['total'] = total
                    route_summary['ipv4']['active'] = active
            
            # Process IPv6
            for route_table in ipv6_tables:
                protos = route_table.xpath('.//protocol') or route_table.xpath('.//protocols/protocol')
                
                for proto in protos:
                    proto_name = self._find_text(proto, './/protocol-name', '')
                    route_count = int(self._find_text(proto, './/protocol-route-count', '0'))
                    
                    if proto_name:
                        route_summary['ipv6'][proto_name.lower()] = route_count
                
                total = int(self._find_text(route_table, './/total-route-count', '0'))
                active = int(self._find_text(route_table, './/active-route-count', '0'))
                if total > 0:
                    route_summary['ipv6']['total'] = total
                    route_summary['ipv6']['active'] = active
            
            logger.info(f"Route summary: IPv4={len(route_summary['ipv4'])} protocols, IPv6={len(route_summary['ipv6'])} protocols")
                    
        except Exception as e:
            logger.error(f"Failed to get route summary: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return route_summary

    # =====================================================================
    # SNMP AND USERS
    # =====================================================================

    def get_snmp_information(self):
        """Return SNMP configuration - Version 2 with enhanced debug."""
        snmp_info = {
            "chassis_id": "",
            "contact": "",
            "location": "",
            "community": {}
        }
        
        try:
            logger.info("Starting SNMP collection...")
            config_reply = self.device.get_config(source="running")
            #tree = config_reply.data_ele
            tree = self._get_config_tree(source="running")
            
            snmp_paths = [
                ('.//snmp', 'just snmp'),
                ('.//system/snmp', 'system/snmp'),
            ]
            
            for xpath, desc in snmp_paths:
                logger.debug(f"Trying XPath: {xpath} ({desc})")
                snmp_nodes = tree.xpath(xpath)
                logger.debug(f"  Found {len(snmp_nodes)} elements")
                
                if snmp_nodes:
                    snmp_node = snmp_nodes[0]
                    logger.info(f"Success with XPath: {xpath}")
                    
                    # Get contact
                    contact_elem = snmp_node.find('.//contact')
                    if contact_elem is None:
                        contact_elem = snmp_node.find('./contact')
                    if contact_elem is not None and contact_elem.text:
                        snmp_info["contact"] = contact_elem.text.strip()
                        logger.debug(f"  Contact: {snmp_info['contact']}")
                    
                    # Get location
                    location_elem = snmp_node.find('.//location')
                    if location_elem is None:
                        location_elem = snmp_node.find('./location')
                    if location_elem is not None and location_elem.text:
                        snmp_info["location"] = location_elem.text.strip()
                        logger.debug(f"  Location: {snmp_info['location']}")
                    
                    # Get communities
                    communities = snmp_node.xpath('.//community')
                    if not communities:
                        communities = snmp_node.xpath('./community')
                    
                    logger.debug(f"  Found {len(communities)} communities")
                    
                    for comm_idx, community in enumerate(communities, 1):
                        name_elem = community.find('.//name')
                        if name_elem is None:
                            name_elem = community.find('./name')
                        
                        if name_elem is not None and name_elem.text:
                            comm_name = name_elem.text.strip()
                            
                            auth_elem = community.find('.//authorization')
                            if auth_elem is None:
                                auth_elem = community.find('./authorization')
                            
                            authorization = auth_elem.text.strip() if auth_elem is not None and auth_elem.text else 'read-only'
                            
                            snmp_info["community"][comm_name] = {
                                "mode": "ro" if authorization == "read-only" else "rw",
                                "acl": ""
                            }
                            logger.debug(f"  Community {comm_idx}: {comm_name} ({authorization})")
                    
                    if snmp_info["contact"] or snmp_info["location"] or snmp_info["community"]:
                        logger.info(f"SNMP config found: {len(snmp_info['community'])} communities")
                        break
            
            if not snmp_info["contact"] and not snmp_info["location"] and not snmp_info["community"]:
                logger.warning("No SNMP configuration found")
                            
        except Exception as e:
            logger.error(f"Failed to get SNMP information: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return snmp_info



    def get_users(self):
        """Return user configuration - Version 2 with enhanced debug."""
        users = {}
        
        _CLASS_TO_LEVEL = {
            "super-user": 15,
            "superuser": 15,
            "tier3": 10, 
            "operator": 5,
            "read-only": 1,
            "unauthorized": 0
        }
        
        try:
            logger.info("Starting user collection...")
            config_reply = self.device.get_config(source="running")
            tree = self._get_config_tree(source="running")
            
            # Try multiple XPath patterns
            user_paths = [
                './/login/user',
                './/system/login/user',
                './/user'
            ]
            
            for xpath_idx, xpath in enumerate(user_paths, 1):
                logger.debug(f"Trying XPath {xpath_idx}/{len(user_paths)}: {xpath}")
                users_found = tree.xpath(xpath)
                logger.debug(f"  Found {len(users_found)} elements")
                
                if users_found:
                    logger.info(f"Success with XPath: {xpath}")
                    
                    for user_idx, user in enumerate(users_found, 1):
                        username_elem = user.find('.//name')
                        
                        # Try alternate path if .//name doesn't work
                        if username_elem is None:
                            username_elem = user.find('./name')
                        
                        if username_elem is None or username_elem.text is None:
                            logger.debug(f"  User {user_idx}: No name found, skipping")
                            continue
                        
                        username = username_elem.text.strip()
                        logger.debug(f"  Found user: {username}")
                        
                        # Get user class
                        class_elem = user.find('.//class')
                        if class_elem is None:
                            class_elem = user.find('./class')
                        
                        user_class = class_elem.text.strip() if class_elem is not None and class_elem.text else 'unauthorized'
                        level = _CLASS_TO_LEVEL.get(user_class.lower(), 0)
                        
                        users[username] = {
                            "level": level,
                            "password": "",
                            "sshkeys": []
                        }
                        
                        # Get SSH keys
                        auth_node = user.find('.//authentication')
                        if auth_node is None:
                            auth_node = user.find('./authentication')
                        
                        if auth_node is not None:
                            key_types = ['ssh-rsa', 'ssh-dsa', 'ssh-ecdsa', 'ssh-ed25519']
                            for key_type in key_types:
                                for key in auth_node.xpath(f'.//{key_type}'):
                                    key_name_elem = key.find('.//name')
                                    if key_name_elem is None:
                                        key_name_elem = key.find('./name')
                                    
                                    if key_name_elem is not None and key_name_elem.text:
                                        users[username]["sshkeys"].append(key_name_elem.text.strip())
                        
                        logger.debug(f"    Level: {level}, SSH keys: {len(users[username]['sshkeys'])}")
                    
                    if users:
                        break
            
            logger.info(f"Total users found: {len(users)}")
            
            if not users:
                logger.warning("No users found - this is unusual. The device likely has users.")
                logger.warning("Consider running the diagnostic script to examine XML structure.")
                            
        except Exception as e:
            logger.error(f"Failed to get users: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return users

    # =====================================================================
    # PROBES/SLA METHODS
    # =====================================================================

    def get_probes_config(self):
        """Return the configuration of the probes."""
        # Junos uses RPM (Real-time Performance Monitoring
        # )
        probes_config = {}
        
        try:
            config_reply = self.device.get_config(source="running")
            
            config_tree = self._get_config_tree(source="running")
            
            for probe in config_tree.xpath('.//services/rpm/probe'):
                probe_name = self._find_text(probe, './/name', '')
                if not probe_name:
                    continue
                
                probes_config[probe_name] = {}
                
                for test in probe.xpath('.//test'):
                    test_name = self._find_text(test, './/name', '')
                    if not test_name:
                        continue
                    
                    probes_config[probe_name][test_name] = {
                        "probe_type": self._find_text(test, './/probe-type', ''),
                        "target": self._find_text(test, './/target/address', ''),
                        "source": self._find_text(test, './/source-address', ''),
                        "probe_count": int(self._find_text(test, './/probe-count', '0')),
                        "test_interval": int(self._find_text(test, './/test-interval', '0'))
                    }
                    
        except Exception as e:
            logger.error(f"Failed to get probes config: {e}")
        
        return probes_config

    def get_probes_results(self):
        """Return the results of the probes."""
        probes_results = {}
        
        try:
            rpc_cmd = "<get-probe-results/>"
            tree = self._rpc(rpc_cmd)
            
            for probe in tree.xpath('.//probe-test-results'):
                owner = self._find_text(probe, './/owner', '')
                test_name = self._find_text(probe, './/test-name', '')
                
                if not owner or not test_name:
                    continue
                
                if owner not in probes_results:
                    probes_results[owner] = {}
                
                probes_results[owner][test_name] = {
                    "target": self._find_text(probe, './/target-address', ''),
                    "source": self._find_text(probe, './/source-address', ''),
                    "probe_type": "",
                    "probe_count": int(self._find_text(probe, './/probe-count', '0')),
                    "rtt": float(self._find_text(probe, './/rtt-average', '0.0')),
                    "round_trip_jitter": float(self._find_text(probe, './/rtt-jitter', '0.0')),
                    "last_test_loss": float(self._find_text(probe, './/probe-loss-percentage', '0.0')),
                    "current_test_min_delay": float(self._find_text(probe, './/rtt-minimum', '0.0')),
                    "current_test_max_delay": float(self._find_text(probe, './/rtt-maximum', '0.0')),
                    "current_test_avg_delay": float(self._find_text(probe, './/rtt-average', '0.0')),
                    "last_test_min_delay": float(self._find_text(probe, './/last-rtt-minimum', '0.0')),
                    "last_test_max_delay": float(self._find_text(probe, './/last-rtt-maximum', '0.0')),
                    "last_test_avg_delay": float(self._find_text(probe, './/last-rtt-average', '0.0')),
                    "global_test_min_delay": float(self._find_text(probe, './/global-rtt-minimum', '0.0')),
                    "global_test_max_delay": float(self._find_text(probe, './/global-rtt-maximum', '0.0')),
                    "global_test_avg_delay": float(self._find_text(probe, './/global-rtt-average', '0.0'))
                }
                
        except Exception as e:
            logger.error(f"Failed to get probes results: {e}")
        
        return probes_results

    # =====================================================================
    # TRACEROUTE
    # =====================================================================

    def traceroute(self, destination, source="", ttl=30, timeout=5, vrf=""):
        """Execute traceroute and return results."""
        traceroute_result = {"success": {}}
        
        try:
            # Build traceroute command
            rpc_cmd = f"<traceroute><host>{destination}</host>"
            if source:
                rpc_cmd += f"<source>{source}</source>"
            if ttl:
                rpc_cmd += f"<ttl>{ttl}</ttl>"
            if timeout:
                rpc_cmd += f"<wait>{timeout}</wait>"
            if vrf:
                rpc_cmd += f"<routing-instance>{vrf}</routing-instance>"
            rpc_cmd += "</traceroute>"
            
            tree = self._rpc(rpc_cmd)
            
            for hop in tree.xpath('.//hop'):
                hop_number = int(self._find_text(hop, './/hop-number', '0'))
                if hop_number == 0:
                    continue
                
                traceroute_result["success"][hop_number] = {"probes": {}}
                
                for idx, probe in enumerate(hop.xpath('.//probe-result'), 1):
                    ip_address = self._find_text(probe, './/ip-address', '*')
                    hostname = self._find_text(probe, './/host', ip_address)
                    rtt_str = self._find_text(probe, './/rtt', '0')
                    
                    try:
                        rtt = float(rtt_str)
                    except:
                        rtt = timeout * 1000.0
                    
                    traceroute_result["success"][hop_number]["probes"][idx] = {
                        "ip_address": ip_address,
                        "host_name": hostname,
                        "rtt": rtt
                    }
                    
        except TimeoutExpiredError:
            return {"error": "Timed out while waiting for reply"}
        except Exception as e:
            logger.error(f"Traceroute failed: {e}")
            return {"error": str(e)}
        
        return traceroute_result

    # =====================================================================
    # PING
    # =====================================================================

    def ping(self, destination, source="", ttl=255, timeout=2, size=100, count=5, vrf=""):
        """Execute ping and return results."""
        ping_result = {
            "success": {
                "probes_sent": 0,
                "packet_loss": 0,
                "rtt_min": 0.0,
                "rtt_max": 0.0,
                "rtt_avg": 0.0,
                "rtt_stddev": 0.0,
                "results": []
            }
        }
        
        try:
            # Build ping command
            rpc_cmd = f"<ping><host>{destination}</host><count>{count}</count>"
            if source:
                rpc_cmd += f"<source>{source}</source>"
            if ttl:
                rpc_cmd += f"<ttl>{ttl}</ttl>"
            if timeout:
                rpc_cmd += f"<wait>{timeout}</wait>"
            if size:
                rpc_cmd += f"<size>{size}</size>"
            if vrf:
                rpc_cmd += f"<routing-instance>{vrf}</routing-instance>"
            rpc_cmd += "</ping>"
            
            tree = self._rpc(rpc_cmd)
            
            probes_sent = int(self._find_text(tree, './/probe-results-summary/probes-sent', '0'))
            responses = int(self._find_text(tree, './/probe-results-summary/responses-received', '0'))
            
            packet_loss = 0
            if probes_sent > 0:
                packet_loss = int(((probes_sent - responses) / probes_sent) * 100)
            
            rtt_min = float(self._find_text(tree, './/probe-results-summary/rtt-minimum', '0'))
            rtt_max = float(self._find_text(tree, './/probe-results-summary/rtt-maximum', '0'))
            rtt_avg = float(self._find_text(tree, './/probe-results-summary/rtt-average', '0'))
            rtt_stddev = float(self._find_text(tree, './/probe-results-summary/rtt-stddev', '0'))
            
            ping_result["success"] = {
                "probes_sent": probes_sent,
                "packet_loss": packet_loss,
                "rtt_min": rtt_min,
                "rtt_max": rtt_max,
                "rtt_avg": rtt_avg,
                "rtt_stddev": rtt_stddev,
                "results": []
            }
            
            for probe in tree.xpath('.//probe-result'):
                result = {
                    "ip_address": self._find_text(probe, './/ip-address', ''),
                    "rtt": float(self._find_text(probe, './/rtt', '0'))
                }
                ping_result["success"]["results"].append(result)
                
        except Exception as e:
            logger.error(f"Ping failed: {e}")
            return {"error": str(e)}
        
        return ping_result

    # =====================================================================
    # CONFIG RETRIEVAL
    # =====================================================================

    def get_config(self, retrieve="all", full=False, sanitized=False, format="text"):
        """Return device configuration."""
        config = {"startup": "", "running": "", "candidate": ""}
        
        if full:
            raise NotImplementedError("'full' argument not implemented for Junos NETCONF driver")
        
        if sanitized:
            raise NotImplementedError("'sanitized' argument not implemented for Junos NETCONF driver")
        
        try:
            if retrieve in ["running", "all"]:
                if format == "text":
                    rpc_cmd = '<get-configuration format="text"/>'
                    reply = self.device.rpc(to_ele(rpc_cmd))
                    tree = self._parse_reply(reply)
                    config_text = self._find_text(tree, './/configuration-text', '')
                    config["running"] = config_text
                else:
                    reply = self.device.get_config(source="running")
                    config["running"] = ETREE.tostring(
                        reply.data_ele,
                        encoding='unicode',
                        pretty_print=True
                    )
            
            if retrieve in ["candidate", "all"]:
                if format == "text":
                    rpc_cmd = '<get-configuration format="text" database="candidate"/>'
                    reply = self.device.rpc(to_ele(rpc_cmd))
                    tree = self._parse_reply(reply)
                    config_text = self._find_text(tree, './/configuration-text', '')
                    config["candidate"] = config_text
                else:
                    reply = self.device.get_config(source="candidate")
                    config["candidate"] = ETREE.tostring(
                        reply.data_ele,
                        encoding='unicode',
                        pretty_print=True
                    )
                    
        except Exception as e:
            logger.error(f"Failed to get config: {e}")
        
        return config

    # =====================================================================
    # CLI METHOD
    # =====================================================================

    def cli(self, commands, encoding="text"):
        """Execute CLI commands and return output."""
        cli_output = {}
        
        if not isinstance(commands, list):
            commands = [commands]
        
        for command in commands:
            try:
                if encoding == "text":
                    rpc_cmd = f'<command format="text">{command}</command>'
                else:
                    rpc_cmd = f'<command format="xml">{command}</command>'
                
                reply = self.device.rpc(to_ele(rpc_cmd))
                tree = self._parse_reply(reply)
                
                if encoding == "text":
                    output = self._find_text(tree, './/output', '')
                else:
                    output = ETREE.tostring(tree, encoding='unicode', pretty_print=True)
                
                cli_output[command] = output
                
            except Exception as e:
                logger.error(f"CLI command '{command}' failed: {e}")
                cli_output[command] = f"Error: {str(e)}"
        
        return cli_output
    
    def _get_sample_routes(self):
        """Get sample routes from routing table for audit."""
        sample_routes = {}
        try:
            # Get some common destinations
            destinations = ["0.0.0.0/0", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            
            for dest in destinations:
                try:
                    routes = self.get_route_to(destination=dest)
                    if routes:
                        sample_routes.update(routes)
                except:
                    continue
                    
            # Limit to first 10 entries
            return dict(list(sample_routes.items())[:10])
        except Exception as e:
            logger.error(f"Failed to get sample routes: {e}")
            return {}

    # =====================================================================
    # COMPREHENSIVE AUDIT METHOD
    # =====================================================================

    def get_comprehensive_audit(self):
        """
        Perform comprehensive device audit - matches IOS-XR implementation.
        Returns dict with ALL device information.
        """
        audit_results = {
            "timestamp": datetime.now().isoformat(),
            "device": self.hostname,
            "port": self.port,
            "collection_started": datetime.now().isoformat(),
        }
        
        # Define audit sections
        audit_sections = {
            # Core device info
            "facts": self.get_facts,
            
            "hardware_inventory": self.get_hardware_inventory,
            
            # Interface information
            "interfaces": self.get_interfaces,
            "interface_counters": self.get_interfaces_counters,
            "interfaces_ip": self.get_interfaces_ip,
            
            # BGP routing
            "bgp_neighbors": self.get_bgp_neighbors,
            "bgp_config": lambda: self.get_bgp_config(),
            
            # Hardware & environment
            "environment": self.get_environment,
            
            # Layer 2 discovery
            "lldp_neighbors": self.get_lldp_neighbors,
            "lldp_neighbors_detail": lambda: self.get_lldp_neighbors_detail(),
            
            # ISIS routing protocol
            "isis_neighbors": self.get_isis_neighbors,
            
            # Layer 2/3 tables
            "arp_table": lambda: self.get_arp_table(),
            "mac_table": self.get_mac_address_table,
            
            # Time synchronization
            "ntp_peers": self.get_ntp_peers,
            "ntp_servers": self.get_ntp_servers,
            "ntp_stats": self.get_ntp_stats,
            
            # System management
            "users": self.get_users,
            "snmp_info": self.get_snmp_information,
            
            # Monitoring & alarms
            "alarms": self.get_alarms,
            
            # Routing information
            "route_summary": lambda: self.get_route_summary(),
            
            "sample_routes": lambda: self._get_sample_routes(),
            
            # Configuration
            "running_config": lambda: self.get_config(retrieve='running'),
        }
        
        total_sections = len(audit_sections)
        successful_sections = 0
        failed_sections = []
        
        logger.info(f"Starting comprehensive audit of {self.hostname}")
        logger.info(f"Total sections to collect: {total_sections}")
        
        for idx, (section_name, method) in enumerate(audit_sections.items(), 1):
            try:
                logger.info(f"[{idx}/{total_sections}] Collecting {section_name}...")
                
                result = method()
                audit_results[section_name] = result
                
                # Log success
                if isinstance(result, dict):
                    item_count = len(result)
                elif isinstance(result, list):
                    item_count = len(result)
                else:
                    item_count = 1
                
                logger.info(f"[SUCCESS] {section_name} collected successfully ({item_count} items)")
                successful_sections += 1
                
            except Exception as e:
                logger.error(f"✗ Failed to collect {section_name}: {e}")
                audit_results[section_name] = {"error": str(e)}
                failed_sections.append(section_name)
        
        # Grouped data sections
        audit_results["inventory"] = {
            "facts": audit_results.get("facts", {}),
            "hardware": {
                "fans": audit_results.get("environment", {}).get("fans", {}),
                "power_supplies": audit_results.get("environment", {}).get("power", {}),
                "temperature": audit_results.get("environment", {}).get("temperature", {}),
            },
            "modules": []
        }
        
        audit_results["performance"] = {
            "cpu": audit_results.get("environment", {}).get("cpu", {}),
            "memory": audit_results.get("environment", {}).get("memory", {}),
        }
        
        audit_results["routing"] = {
            "route_summary": audit_results.get("route_summary", {}),
            "bgp_neighbors": audit_results.get("bgp_neighbors", {}),
            "bgp_config": audit_results.get("bgp_config", {}),
        }
        
        # Summary statistics
        try:
            interfaces = audit_results.get("interfaces", {})
            bgp_neighbors = audit_results.get("bgp_neighbors", {})
            
            audit_results["summary"] = {
                "collection_status": {
                    "total_sections": total_sections,
                    "successful": successful_sections,
                    "failed": len(failed_sections),
                    "failed_sections": failed_sections,
                    "success_rate": f"{(successful_sections/total_sections)*100:.1f}%"
                },
                "interface_summary": {
                    "total": len(interfaces),
                    "up": sum(1 for i in interfaces.values() if i.get('is_up')),
                    "down": sum(1 for i in interfaces.values() if not i.get('is_up')),
                    "enabled": sum(1 for i in interfaces.values() if i.get('is_enabled')),
                    "disabled": sum(1 for i in interfaces.values() if not i.get('is_enabled')),
                },
                "bgp_summary": {
                    "total_vrfs": len(bgp_neighbors),
                    "total_peers": sum(len(v.get('peers', {})) for v in bgp_neighbors.values()),
                    "peers_up": sum(
                        sum(1 for p in v.get('peers', {}).values() if p.get('is_up'))
                        for v in bgp_neighbors.values()
                    ),
                },
                "alarm_summary": {
                    "active_alarms": len(audit_results.get("alarms", [])),
                },
                "table_summary": {
                    "arp_entries": len(audit_results.get("arp_table", [])),
                    "mac_entries": len(audit_results.get("mac_table", [])),
                    "lldp_neighbors": sum(len(v) for v in audit_results.get("lldp_neighbors", {}).values()),
                },
                "ntp_summary": {
                    "peers": len(audit_results.get("ntp_peers", {})),
                    "servers": len(audit_results.get("ntp_servers", {})),
                    "synchronized": sum(1 for s in audit_results.get("ntp_stats", []) 
                                    if s.get('synchronized')),
                },
                "system_summary": {
                    "users": len(audit_results.get("users", {})),
                    "uptime_seconds": audit_results.get("facts", {}).get("uptime", 0),
                    "uptime_days": round(audit_results.get("facts", {}).get("uptime", 0) / 86400, 2),
                }
            }
        except Exception as summary_err:
            logger.warning(f"Failed to generate summary statistics: {summary_err}")
            audit_results["summary"] = {"error": str(summary_err)}
        
        # Completion timestamp
        audit_results["collection_completed"] = datetime.now().isoformat()
        
        # Calculate total collection time
        try:
            from datetime import datetime as dt
            start = dt.fromisoformat(audit_results["collection_started"])
            end = dt.fromisoformat(audit_results["collection_completed"])
            duration = (end - start).total_seconds()
            audit_results["collection_duration_seconds"] = round(duration, 2)
        except:
            pass
        
        # Final log
        logger.info("=" * 80)
        logger.info(f"✓ Comprehensive audit completed for {self.hostname}")
        logger.info(f"  Successful sections: {successful_sections}/{total_sections}")
        if failed_sections:
            logger.warning(f"  Failed sections: {', '.join(failed_sections)}")
        logger.info(f"  Duration: {audit_results.get('collection_duration_seconds', 'N/A')} seconds")
        logger.info("=" * 80)
        
        return audit_results
    
    def _format_table_header(self, headers, widths):
        """Format table header with proper spacing."""
        header_line = "! " + " ".join(f"{h:<{w}}" for h, w in zip(headers, widths))
        separator = "! " + "-" * (sum(widths) + len(widths) - 1)
        return f"{separator}\n{header_line}\n{separator}"

    def _format_table_row(self, values, widths):
        """Format table row with proper spacing."""
        return "! " + " ".join(f"{str(v):<{w}}" for v, w in zip(values, widths))

    
    def export_audit_to_text(self, audit_results, filename=None):
        """Export comprehensive audit to detailed .cfg format matching Cisco XR style."""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"audit_{audit_results.get('facts', {}).get('hostname', 'junos')}_{timestamp}.cfg"
        
        with open(filename, 'w', encoding='utf-8') as f:
            # Header
            f.write("!" * 80 + "\n")
            f.write("! NETWORK DEVICE COMPREHENSIVE AUDIT REPORT\n")
            f.write("!" * 80 + "\n")
            f.write(f"! Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            facts = audit_results.get('facts', {})
            f.write(f"! Device:    {facts.get('hostname', 'Unknown')} ({self.hostname})\n")
            f.write(f"! Type:      junos_netconf\n")
            f.write("!" * 80 + "\n\n")
            
            # Section 1: Device Facts & Inventory
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 1: DEVICE FACTS & INVENTORY\n")
            f.write("!" + "=" * 78 + "\n!\n")
            f.write(f"! Hostname:          {facts.get('hostname', 'N/A')}\n")
            f.write(f"! Vendor:            {facts.get('vendor', 'N/A')}\n")
            f.write(f"! Model:             {facts.get('model', 'N/A')}\n")
            f.write(f"! OS Version:        {facts.get('os_version', 'N/A')}\n")
            f.write(f"! Serial Number:     {facts.get('serial_number', 'N/A')}\n")
            f.write(f"! FQDN:              {facts.get('fqdn', 'N/A')}\n")
            
            uptime = facts.get('uptime', 0)
            uptime_days = uptime / 86400 if uptime > 0 else 0
            f.write(f"! Uptime:            {uptime} seconds ({uptime_days:.1f} days)\n")
            
            iface_list = facts.get('interface_list', [])
            f.write(f"! Interface Count:   {len(iface_list)}\n!\n")
            
            if iface_list:
                f.write("! Interface List:\n")
                for idx, iface in enumerate(iface_list, 1):
                    f.write(f"!    {idx:2d}. {iface}\n")
            f.write("\n\n")
            
            # Section 2: Active Alarms
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 2: ACTIVE ALARMS\n")
            f.write("!" + "=" * 78 + "\n")
            alarms = audit_results.get('alarms', [])
            if alarms:
                for alarm in alarms:
                    f.write(f"!\n! Alarm:\n")
                    f.write(f"!   Severity:     {alarm.get('severity', 'N/A')}\n")
                    f.write(f"!   Description:  {alarm.get('description', 'N/A')}\n")
                    f.write(f"!   Location:     {alarm.get('location', 'N/A')}\n")
                    f.write(f"!   Timestamp:    {alarm.get('timestamp', 'N/A')}\n")
            else:
                f.write("! No active alarms\n")
            f.write("\n\n")
            
            # Section 3: Detailed Interface Information
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 3: DETAILED INTERFACE INFORMATION\n")
            f.write("!" + "=" * 78 + "\n")
            interfaces = audit_results.get('interfaces', {})
            summary = audit_results.get('summary', {}).get('interface_summary', {})
            f.write(f"! Total Interfaces: {summary.get('total', 0)}\n")
            f.write(f"! Up:               {summary.get('up', 0)}\n")
            f.write(f"! Down:             {summary.get('down', 0)}\n!\n")

            # Table format
            headers = ["Interface", "Status", "Admin", "Speed", "MTU", "MAC Address"]
            widths = [20, 8, 8, 10, 6, 17]

            f.write(self._format_table_header(headers, widths) + "\n")

            for iface_name, iface_data in sorted(interfaces.items()):
                status = "Up" if iface_data.get('is_up') else "Down"
                admin = "Enabled" if iface_data.get('is_enabled') else "Disabled"
                speed = f"{iface_data.get('speed', 0):.0f}" if iface_data.get('speed', -1) > 0 else "N/A"
                mtu = str(iface_data.get('mtu', 0))
                mac = iface_data.get('mac_address', 'N/A')
                
                values = [iface_name[:19], status, admin, speed, mtu, mac]
                f.write(self._format_table_row(values, widths) + "\n")

            f.write("! " + "-" * (sum(widths) + len(widths) - 1) + "\n\n")

            
            # Section 4: Interface Statistics & Counters
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 4: INTERFACE STATISTICS & COUNTERS\n")
            f.write("!" + "=" * 78 + "\n!\n")

            headers = ["Interface", "RX Packets", "TX Packets", "RX Bytes", "TX Bytes", "RX Err", "TX Err"]
            widths = [20, 15, 15, 15, 15, 8, 8]

            f.write(self._format_table_header(headers, widths) + "\n")

            counters = audit_results.get('interface_counters', {})
            for iface_name, stats in sorted(counters.items()):
                rx_pkts = stats.get('rx_unicast_packets', 0)
                tx_pkts = stats.get('tx_unicast_packets', 0)
                rx_bytes = stats.get('rx_octets', 0)
                tx_bytes = stats.get('tx_octets', 0)
                rx_err = stats.get('rx_errors', 0)
                tx_err = stats.get('tx_errors', 0)
                
                values = [
                    iface_name[:19],
                    f"{rx_pkts:,}",
                    f"{tx_pkts:,}",
                    f"{rx_bytes:,}",
                    f"{tx_bytes:,}",
                    str(rx_err),
                    str(tx_err)
                ]
                f.write(self._format_table_row(values, widths) + "\n")

            f.write("! " + "-" * (sum(widths) + len(widths) - 1) + "\n\n")
            
            # Section 5: IP Address Configuration
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 5: IP ADDRESS CONFIGURATION\n")
            f.write("!" + "=" * 78 + "\n!\n")

            headers = ["Interface", "IP Version", "IP Address", "Prefix"]
            widths = [25, 10, 40, 6]

            f.write(self._format_table_header(headers, widths) + "\n")

            interfaces_ip = audit_results.get('interfaces_ip', {})
            for iface_name, ip_data in sorted(interfaces_ip.items()):
                # IPv4 addresses
                ipv4_addrs = ip_data.get('ipv4', {})
                for ip, details in ipv4_addrs.items():
                    prefix = details.get('prefix_length', 32)
                    values = [iface_name[:24], "IPv4", ip, str(prefix)]
                    f.write(self._format_table_row(values, widths) + "\n")
                
                # IPv6 addresses
                ipv6_addrs = ip_data.get('ipv6', {})
                for ip, details in ipv6_addrs.items():
                    prefix = details.get('prefix_length', 128)
                    values = [iface_name[:24], "IPv6", ip[:39], str(prefix)]
                    f.write(self._format_table_row(values, widths) + "\n")

            f.write("! " + "-" * (sum(widths) + len(widths) - 1) + "\n\n")
            
            # Section 6: Hardware & Environment Status
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 6: HARDWARE & ENVIRONMENT STATUS\n")
            f.write("!" + "=" * 78 + "\n!\n")
            env = audit_results.get('environment', {})
            
            # Hardware Inventory
            hw_inventory = audit_results.get('hardware_inventory', {})
            if hw_inventory:
                chassis = hw_inventory.get('chassis', {})
                modules = hw_inventory.get('modules', [])
                
                if chassis:
                    f.write("! Chassis Information:\n")
                    f.write(f"!   Model:         {chassis.get('description', 'N/A')}\n")
                    f.write(f"!   Serial:        {chassis.get('serial_number', 'N/A')}\n!\n")
                
                if modules:
                    f.write("! Hardware Inventory:\n")
                    for module in modules:
                        name = module.get('name', '')
                        version = module.get('version', '')
                        part_num = module.get('part_number', '')
                        serial = module.get('serial_number', '')
                        desc = module.get('description', '')
                        parent = module.get('parent', '')
                        
                        # Determine indentation based on parent
                        if parent:
                            if 'MIC' in parent or 'PIC' in parent:
                                indent = "!       "  # Sub-sub-module
                            else:
                                indent = "!     "    # Sub-module
                        else:
                            indent = "!   "          # Top-level module
                        
                        f.write(f"{indent}{name:20s} ")
                        if version:
                            f.write(f"v{version:6s} ")
                        if part_num:
                            f.write(f"{part_num:15s} ")
                        if serial:
                            f.write(f"{serial:15s} ")
                        if desc:
                            f.write(f"{desc}")
                        f.write("\n")
                    f.write("!\n")
            
            env = audit_results.get('environment', {})
            

            
            # CPU
            cpu_data = env.get('cpu', {})
            if cpu_data:
                f.write("! CPU Utilization:\n")
                for cpu_name, cpu_info in cpu_data.items():
                    usage = cpu_info.get('%usage', 0)
                    status = "Normal" if usage < 80 else "High"
                    f.write(f"!   {cpu_name:30s} {usage:>6.2f}%  [{status}]\n")
                f.write("!\n")
            
            # Memory
            mem_data = env.get('memory', {})
            if mem_data:
                avail = mem_data.get('available_ram', 0)
                used = mem_data.get('used_ram', 0)
                usage_pct = (used / avail * 100) if avail > 0 else 0
                status = "Normal" if usage_pct < 80 else "High"
                f.write("! Memory Status:\n")
                f.write(f"!   Available RAM:     {avail:>15,} KB\n")
                f.write(f"!   Used RAM:          {used:>15,} KB\n")
                f.write(f"!   Usage:              {usage_pct:>5.2f}%  [{status}]\n!\n")
            
            # Temperature
            temp_data = env.get('temperature', {})
            if temp_data:
                f.write("! Temperature Sensors:\n")
                for sensor, temp_info in temp_data.items():
                    temp_val = temp_info.get('temperature', 0)
                    is_crit = temp_info.get('is_critical', False)
                    is_alert = temp_info.get('is_alert', False)
                    status = "Critical" if is_crit else ("Alert" if is_alert else "Normal")
                    f.write(f"!   {sensor:30s} {temp_val:>6.1f}°C  [{status}]\n")
                f.write("!\n")
            
            # Power Supplies
            power_data = env.get('power', {})
            if power_data:
                f.write("! Power Supplies:\n")
                for psu, psu_info in power_data.items():
                    psu_status = "OK" if psu_info.get('status') else "Failed"
                    output = psu_info.get('output', -1)
                    capacity = psu_info.get('capacity', -1)
                    f.write(f"!   {psu:30s} [{psu_status}]\n")
                    if output > 0:
                        f.write(f"!     Output:    {output:.2f}W\n")
                    if capacity > 0:
                        f.write(f"!     Capacity:  {capacity:.1f}W\n")
                f.write("!\n")
            
            # Fans
            fan_data = env.get('fans', {})
            if fan_data:
                f.write("! Fan Status:\n")
                for fan, fan_info in fan_data.items():
                    fan_status = "OK" if fan_info.get('status') else "Failed"
                    f.write(f"!   {fan:30s} [{fan_status}]\n")
                f.write("!\n")
            f.write("\n")
            
            # Section 7: BGP Configuration & Neighbors
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 7: BGP CONFIGURATION & NEIGHBORS\n")
            f.write("!" + "=" * 78 + "\n!\n")
            f.write("! BGP Neighbor Summary:\n!\n")
            
            bgp_neighbors = audit_results.get('bgp_neighbors', {})
            for vrf, vrf_data in bgp_neighbors.items():
                peers = vrf_data.get('peers', {})
                total_peers = len(peers)
                established = sum(1 for p in peers.values() if p.get('is_up'))
                down = total_peers - established
                
                f.write(f"!   VRF: {vrf}\n")
                f.write(f"!   Router ID:        {vrf_data.get('router_id', 'N/A')}\n")
                f.write(f"!   Total Peers:      {total_peers}\n")
                f.write(f"!   Established:      {established}\n")
                f.write(f"!   Down:             {down}\n!\n")
                
                if peers:
                    f.write(f"!   Peer Details for VRF {vrf}:\n!\n")
                    for peer_ip, peer_data in peers.items():
                        state = "Up" if peer_data.get('is_up') else "Down"
                        f.write(f"!     Peer IP:          {peer_ip}\n")
                        f.write(f"!     Remote AS:        {peer_data.get('remote_as', 0)}\n")
                        f.write(f"!     Local AS:         {peer_data.get('local_as', 0)}\n")
                        f.write(f"!     State:            {state}\n")
                        f.write(f"!     Uptime:           {peer_data.get('uptime', -1)} seconds\n")
                        f.write(f"!     Description:      {peer_data.get('description', '')}\n")
                        
                        af = peer_data.get('address_family', {})
                        for af_name, af_data in af.items():
                            f.write(f"!     Address Family:   {af_name}\n")
                            f.write(f"!       Received:       {af_data.get('received_prefixes', 0)}\n")
                            f.write(f"!       Accepted:       {af_data.get('accepted_prefixes', 0)}\n")
                            f.write(f"!       Sent:           {af_data.get('sent_prefixes', 0)}\n")
                        f.write("!\n")
            f.write("\n")
            
            # Section 8: Routing Table Information
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 8: ROUTING TABLE INFORMATION\n")
            f.write("!" + "=" * 78 + "\n!\n")

            route_summary = audit_results.get('route_summary', {})

            # IPv4 Routes
            ipv4_routes = route_summary.get('ipv4', {})
            if ipv4_routes:
                f.write("! IPv4 Routing Table Summary:\n!\n")
                headers = ["Protocol", "Route Count"]
                widths = [30, 15]
                f.write(self._format_table_header(headers, widths) + "\n")
                
                total_routes = 0
                for proto, count in sorted(ipv4_routes.items()):
                    if proto not in ['total', 'active']:
                        total_routes += count
                    values = [proto.upper(), f"{count:,}"]
                    f.write(self._format_table_row(values, widths) + "\n")
                
                f.write("! " + "-" * (sum(widths) + len(widths) - 1) + "\n")
                f.write(f"! Total IPv4 Routes: {total_routes:,}\n!\n")
            else:
                f.write("! No IPv4 routing information available\n!\n")

            # IPv6 Routes
            ipv6_routes = route_summary.get('ipv6', {})
            if ipv6_routes:
                f.write("! IPv6 Routing Table Summary:\n!\n")
                headers = ["Protocol", "Route Count"]
                widths = [30, 15]
                f.write(self._format_table_header(headers, widths) + "\n")
                
                total_routes = 0
                for proto, count in sorted(ipv6_routes.items()):
                    if proto not in ['total', 'active']:
                        total_routes += count
                    values = [proto.upper(), f"{count:,}"]
                    f.write(self._format_table_row(values, widths) + "\n")
                
                f.write("! " + "-" * (sum(widths) + len(widths) - 1) + "\n")
                f.write(f"! Total IPv6 Routes: {total_routes:,}\n!\n")
            else:
                f.write("! No IPv6 routing information available\n!\n")
            
            # Section 9: LLDP Neighbors
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 9: LLDP NEIGHBORS\n")
            f.write("!" + "=" * 78 + "\n!\n!\n")
            
            lldp_detail = audit_results.get('lldp_neighbors_detail', {})
            for local_iface, neighbors in lldp_detail.items():
                for neighbor in neighbors:
                    f.write(f"! Local Interface: {local_iface}\n")
                    f.write(f"!   Neighbor:\n")
                    f.write(f"!     System Name:       {neighbor.get('remote_system_name', 'N/A')}\n")
                    f.write(f"!     Chassis ID:        {neighbor.get('remote_chassis_id', 'N/A')}\n")
                    f.write(f"!     Remote Port:       {neighbor.get('remote_port', 'N/A')}\n")
                    f.write(f"!     Port Description:  {neighbor.get('remote_port_description', 'N/A')}\n")
                    f.write(f"!     System Desc:       {neighbor.get('remote_system_description', 'N/A')}\n")
                    f.write("!\n")
            f.write("\n")
            
            f.write("\n")

            # Section 10: ISIS NEIGHBORS
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 10: ISIS NEIGHBORS\n")
            f.write("!" + "=" * 78 + "\n!\n")

            isis_neighbors = audit_results.get('isis_neighbors', {})
            if isis_neighbors:
                for interface, neighbors in isis_neighbors.items():
                    for neighbor in neighbors:
                        f.write(f"! Interface: {interface}\n")
                        f.write(f"!   System Name:  {neighbor.get('system_name', 'N/A')}\n")
                        f.write(f"!   Level:        {neighbor.get('level', 'N/A')}\n")
                        f.write(f"!   State:        {neighbor.get('state', 'N/A')}\n")
                        f.write(f"!   Holdtime:     {neighbor.get('holdtime', 0)}s\n")
                        f.write(f"!   SNPA:         {neighbor.get('snpa', 'N/A')}\n!\n")
            else:
                f.write("! No ISIS neighbors configured or found\n")
            f.write("\n\n")

            # Section 11: ARP Table (renumber from 10)
            
            # Section 10: ARP Table
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 10: ARP TABLE\n")
            f.write("!" + "=" * 78 + "\n")
            arp_table = audit_results.get('arp_table', [])
            f.write(f"! Total Entries: {len(arp_table)}\n!\n")

            if arp_table:
                f.write("! " + "-" * 76 + "\n")
                f.write("! IP Address          MAC Address        Interface              Age\n")
                f.write("! " + "-" * 76 + "\n")
                
                # Sort by IP address for better readability
                sorted_arp = sorted(arp_table, key=lambda x: x.get('ip', ''))
                
                for entry in sorted_arp:
                    ip = entry.get('ip', 'N/A').strip()
                    mac = entry.get('mac', 'N/A').strip()
                    iface = entry.get('interface', 'N/A').strip()
                    age = entry.get('age', 0.0)
                    f.write(f"! {ip:<19s} {mac:<18s} {iface:<22s} {age:>6.1f}s\n")
                f.write("! " + "-" * 76 + "\n")
            else:
                f.write("! No ARP entries found\n")
            
            # Section 11: NTP Configuration & Status
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 11: NTP CONFIGURATION & STATUS\n")
            f.write("!" + "=" * 78 + "\n!\n")

            ntp_servers = audit_results.get('ntp_servers', {})
            ntp_peers = audit_results.get('ntp_peers', {})

            if ntp_servers or ntp_peers:
                f.write("! Configured NTP Sources:\n")
                if ntp_servers:
                    f.write("!   Servers:\n")
                    for server in sorted(ntp_servers.keys()):
                        f.write(f"!     - {server}\n")
                if ntp_peers:
                    f.write("!   Peers:\n")
                    for peer in sorted(ntp_peers.keys()):
                        f.write(f"!     - {peer}\n")
                f.write("!\n")
            else:
                f.write("! No NTP servers configured\n!\n")

            ntp_stats = audit_results.get('ntp_stats', [])
            if ntp_stats:
                f.write("! NTP Association Statistics:\n!\n")
                
                headers = ["Remote", "Synced", "Stratum", "Delay", "Offset", "Jitter"]
                widths = [25, 6, 7, 10, 10, 10]
                f.write(self._format_table_header(headers, widths) + "\n")
                
                for stat in ntp_stats:
                    synced = "Yes" if stat.get('synchronized', False) else "No"
                    values = [
                        stat.get('remote', 'N/A')[:24],
                        synced,
                        str(stat.get('stratum', 0)),
                        f"{stat.get('delay', 0.0):.3f}",
                        f"{stat.get('offset', 0.0):.3f}",
                        f"{stat.get('jitter', 0.0):.3f}"
                    ]
                    f.write(self._format_table_row(values, widths) + "\n")
                
                f.write("! " + "-" * (sum(widths) + len(widths) - 1) + "\n")
            else:
                f.write("! No NTP statistics available\n")

            f.write("\n")
            
            # Section 12: User Accounts
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 12: USER ACCOUNTS\n")
            f.write("!" + "=" * 78 + "\n")
            users = audit_results.get('users', {})
            f.write(f"! Total Users: {len(users)}\n!\n")

            if users:
                headers = ["Username", "Privilege Level", "SSH Keys"]
                widths = [25, 16, 35]
                f.write(self._format_table_header(headers, widths) + "\n")
                
                for username, user_data in sorted(users.items()):
                    level = user_data.get('level', 0)
                    ssh_key_count = len(user_data.get('sshkeys', []))
                    ssh_info = f"{ssh_key_count} keys" if ssh_key_count > 0 else "No keys"
                    
                    values = [username[:24], str(level), ssh_info]
                    f.write(self._format_table_row(values, widths) + "\n")
                
                f.write("! " + "-" * (sum(widths) + len(widths) - 1) + "\n")
            else:
                f.write("! No user accounts found\n")

            f.write("\n\n")
            
            # Section 13: SNMP Configuration
            f.write("!" + "=" * 78 + "\n")
            f.write("! SECTION 13: SNMP CONFIGURATION\n")
            f.write("!" + "=" * 78 + "\n!\n")

            snmp_info = audit_results.get('snmp_info', {})
            f.write(f"! Contact:     {snmp_info.get('contact', 'Not configured')}\n")
            f.write(f"! Location:    {snmp_info.get('location', 'Not configured')}\n!\n")

            communities = snmp_info.get('community', {})
            if communities:
                f.write("! SNMP Communities:\n!\n")
                headers = ["Community", "Access Mode", "ACL"]
                widths = [25, 15, 35]
                f.write(self._format_table_header(headers, widths) + "\n")
                
                for comm_name, comm_data in sorted(communities.items()):
                    mode = comm_data.get('mode', 'ro').upper()
                    acl = comm_data.get('acl', 'None')
                    values = [comm_name[:24], mode, acl[:34]]
                    f.write(self._format_table_row(values, widths) + "\n")
                
                f.write("! " + "-" * (sum(widths) + len(widths) - 1) + "\n")
            else:
                f.write("! No SNMP communities configured\n")

            f.write("\n\n")

    # =====================================================================
    # ADDITIONAL HELPER METHODS
    # =====================================================================
    def debug_xml_structure(self, source="running"):
        """Debug helper to see the actual XML structure."""
        try:
            config_reply = self.device.get_config(source=source)
            tree = config_reply.data_ele
            
            # Print the full XML
            xml_str = ETREE.tostring(tree, encoding='unicode', pretty_print=True)
            print("="*80)
            print("XML STRUCTURE:")
            print("="*80)
            print(xml_str[:5000])  # Print first 5000 characters
            print("="*80)
            
            # Print all unique tag names to understand structure
            tags = set()
            for elem in tree.iter():
                tags.add(elem.tag)
            
            print("\nAll XML tags found:")
            for tag in sorted(tags):
                print(f"  - {tag}")
            
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
    def get_optics(self):
        """Return optical transceiver information."""
        optics = {}
        
        try:
            rpc_cmd = "<get-interface-optics-diagnostics-information/>"
            tree = self._rpc(rpc_cmd)
            
            for iface in tree.xpath('.//physical-interface'):
                name = self._find_text(iface, './/name', '')
                if not name:
                    continue
                
                optics[name] = {
                    "physical_channels": {
                        "channel": [{
                            "index": 0,
                            "state": {
                                "input_power": {
                                    "instant": float(self._find_text(iface, './/laser-rx-power-dbm', '0.0')),
                                    "avg": 0.0,
                                    "min": 0.0,
                                    "max": 0.0
                                },
                                "output_power": {
                                    "instant": float(self._find_text(iface, './/laser-output-power-dbm', '0.0')),
                                    "avg": 0.0,
                                    "min": 0.0,
                                    "max": 0.0
                                },
                                "laser_bias_current": {
                                    "instant": float(self._find_text(iface, './/laser-bias-current', '0.0')),
                                    "avg": 0.0,
                                    "min": 0.0,
                                    "max": 0.0
                                }
                            }
                        }]
                    }
                }
                
        except Exception as e:
            logger.error(f"Failed to get optics: {e}")
        
        return optics

    def get_vlans(self):
        """Return VLAN configuration."""
        vlans = {}
        
        try:
            rpc_cmd = "<get-vlan-information/>"
            tree = self._rpc(rpc_cmd)
            
            for vlan in tree.xpath('.//vlan'):
                vlan_name = self._find_text(vlan, './/vlan-name', '')
                vlan_id = self._find_text(vlan, './/vlan-id', '')
                
                if vlan_id:
                    vlans[vlan_id] = {
                        "name": vlan_name,
                        "interfaces": []
                    }
                    
                    for member in vlan.xpath('.//vlan-member-list/vlan-member'):
                        iface = self._find_text(member, './/interface-name', '')
                        if iface:
                            vlans[vlan_id]["interfaces"].append(iface)
                            
        except Exception as e:
            logger.error(f"Failed to get VLANs: {e}")
        
        return vlans

    def get_network_instances(self, name=""):
        """Return network instances (VRFs) configuration."""
        instances = {}
        
        try:
            rpc_cmd = "<get-instance-information/>"
            tree = self._rpc(rpc_cmd)
            
            for instance in tree.xpath('.//instance-core'):
                inst_name = self._find_text(instance, './/instance-name', '')
                if name and inst_name != name:
                    continue
                
                if inst_name:
                    instances[inst_name] = {
                        "name": inst_name,
                        "type": self._find_text(instance, './/instance-type', ''),
                        "state": {
                            "route_distinguisher": self._find_text(instance, './/route-distinguisher', '')
                        },
                        "interfaces": {
                            "interface": []
                        }
                    }
                    
                    for iface in instance.xpath('.//instance-interface'):
                        iface_name = self._find_text(iface, './/interface-name', '')
                        if iface_name:
                            instances[inst_name]["interfaces"]["interface"].append({
                                "name": iface_name
                            })
                            
        except Exception as e:
            logger.error(f"Failed to get network instances: {e}")
        
        return instances

    def get_ipv6_neighbors_table(self):
        """Return IPv6 neighbors table (NDP)."""
        ipv6_neighbors = []
        
        try:
            rpc_cmd = "<get-ipv6-nd-information/>"
            tree = self._rpc(rpc_cmd)
            
            for neighbor in tree.xpath('.//ipv6-nd-entry'):
                ipv6_address = self._find_text(neighbor, './/ipv6-nd-neighbor-address', '')
                mac_address = self._find_text(neighbor, './/ipv6-nd-neighbor-l2-address', '')
                interface = self._find_text(neighbor, './/ipv6-nd-interface-name', '')
                state = self._find_text(neighbor, './/ipv6-nd-state', '')
                
                if ipv6_address and mac_address:
                    ipv6_neighbors.append({
                        "interface": interface,
                        "mac": mac_address,
                        "ip": ipv6_address,
                        "age": 0.0,
                        "state": state
                    })
                    
        except Exception as e:
            logger.error(f"Failed to get IPv6 neighbors: {e}")
        
        return ipv6_neighbors

    def get_firewall_policies(self):
        """Return firewall policies/filters."""
        policies = {}
        
        try:
            config_reply = self.device.get_config(source="running")
            config_tree = config_reply.data_element
            
            for filter_elem in config_tree.xpath('.//firewall/filter'):
                filter_name = self._find_text(filter_elem, './/name', '')
                if not filter_name:
                    continue
                
                policies[filter_name] = {
                    "terms": []
                }
                
                for term in filter_elem.xpath('.//term'):
                    term_name = self._find_text(term, './/name', '')
                    
                    term_data = {
                        "name": term_name,
                        "from": {},
                        "then": {}
                    }
                    
                    # Parse 'from' conditions
                    from_elem = term.find('.//from')
                    if from_elem is not None:
                        for child in from_elem:
                            tag = child.tag.replace('{*}', '')
                            term_data["from"][tag] = child.text if child.text else ""
                    
                    # Parse 'then' actions
                    then_elem = term.find('.//then')
                    if then_elem is not None:
                        for child in then_elem:
                            tag = child.tag.replace('{*}', '')
                            term_data["then"][tag] = child.text if child.text else "true"
                    
                    policies[filter_name]["terms"].append(term_data)
                    
        except Exception as e:
            logger.error(f"Failed to get firewall policies: {e}")
        
        return policies


