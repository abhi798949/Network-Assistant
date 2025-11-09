import asyncio
from json.tool import main
import logging
from typing import Dict, List, Optional
from datetime import datetime
import threading
import time
import yaml
import os
from pysnmp.hlapi.v3arch.asyncio import (
    next_cmd, SnmpEngine, CommunityData, UdpTransportTarget, 
    ContextData, ObjectType, ObjectIdentity, get_cmd, bulk_cmd
)

class SNMPMonitor:
    """SNMP monitoring with concurrent bulk collection support"""

    def __init__(self, max_concurrent_devices: Optional[int] = None, max_concurrent_interfaces: Optional[int] = None):
        self.logger = logging.getLogger(__name__)
        self.max_concurrent_devices = max_concurrent_devices
        self.max_concurrent_interfaces = max_concurrent_interfaces
        
        # Semaphores to limit concurrent operations
        self.device_semaphore = asyncio.Semaphore(max_concurrent_devices) if max_concurrent_devices else asyncio.Semaphore()
        self.interface_semaphore = asyncio.Semaphore(max_concurrent_interfaces) if max_concurrent_interfaces else asyncio.Semaphore()

        # Standard SNMP OIDs
        self.standard_oids = {
            'ifNumber': '1.3.6.1.2.1.2.1.0',
            'ifDescr': '1.3.6.1.2.1.2.2.1.2',
            'ifAlias': '1.3.6.1.2.1.31.1.1.1.18',
            'ifHCInOctets': '1.3.6.1.2.1.31.1.1.1.6',
            'ifHCOutOctets': '1.3.6.1.2.1.31.1.1.1.10',
            'ifInUcastPkts': '1.3.6.1.2.1.2.2.1.11',
            'ifOutUcastPkts': '1.3.6.1.2.1.2.2.1.17',
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysUpTime': '1.3.6.1.2.1.1.3.0',
            'ifInOctets': '1.3.6.1.2.1.2.2.1.10',
            'ifOutOctets': '1.3.6.1.2.1.2.2.1.16',
            'ifSpeed': '1.3.6.1.2.1.2.2.1.5',  # Interface speed in bps
            'ifHighSpeed': '1.3.6.1.2.1.31.1.1.1.15',  # Interface speed in Mbps
            'ifInDiscards': '1.3.6.1.2.1.2.2.1.13',
            'ifOutDiscards': '1.3.6.1.2.1.2.2.1.19',
            'ifInErrors': '1.3.6.1.2.1.2.2.1.14',
            'ifOutErrors': '1.3.6.1.2.1.2.2.1.20',
            'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',  # Operational status
            'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7',  # Administrative status
        }
        
        # Vendor-specific OIDs (simplified for single CPU and memory used)
        self.vendor_oids = {
            'cisco': {
                'cpu_usage': '1.3.6.1.4.1.9.9.109.1.1.1.1.8',  # CPU usage table
                'memory_free': '1.3.6.1.4.1.9.9.221.1.1.1.1.20',  # Memory used table
                'memory_used' : '1.3.6.1.4.1.9.9.221.1.1.1.1.18',
            },
            'cisco_xr': {
                'cpu_usage': '1.3.6.1.4.1.9.9.109.1.1.1.1.8',
                'memory_free': '1.3.6.1.4.1.9.9.221.1.1.1.1.20',  # Memory used table
                'memory_used' : '1.3.6.1.4.1.9.9.221.1.1.1.1.18',
            },
            'juniper': {
                'cpu_usage': '1.3.6.1.4.1.2636.3.1.13.1.8',
                'memory_used':'1.3.6.1.4.1.2636.3.1.13.1.16',
                
            },
            'arista': {
                'cpu_usage': '1.3.6.1.4.1.30065.3.1.1.1.1',
                'memory_used': '1.3.6.1.2.1.47.1.1.1.1.4',
            }
        }
    
    async def collect_metrics_bulk(self, devices: List[Dict]) -> List[Dict]:
        """
        Collect metrics from multiple devices concurrently
        
        Args:
            devices: List of device configurations
            
        Returns:
            List of all collected metric points from all devices
        """
        self.logger.info(f"Starting bulk collection for {len(devices)} devices")
        start_time = datetime.utcnow()
        
        # Create tasks for all devices
        tasks = [self.collect_metrics(device) for device in devices]
        
        # Run all tasks concurrently and gather results
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten results and handle exceptions
        all_points = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                device_name = devices[i].get('name', 'unknown')
                self.logger.error(f"Failed to collect from {device_name}: {result}")
            else:
                all_points.extend(result)

        elapsed = (datetime.utcnow() - start_time).total_seconds()
        self.logger.info(f"Bulk collection completed: {len(all_points)} points from {len(devices)} devices in {elapsed:.2f}s")
        
        return all_points
    
    async def collect_metrics(self, device_config: Dict) -> List[Dict]:
        """Collect SNMP metrics from a single device with rate limiting"""
        async with self.device_semaphore:
            return await self._collect_metrics_internal(device_config)
    
    async def _collect_metrics_internal(self, device_config: Dict) -> List[Dict]:
        """Internal method to collect SNMP metrics"""
        points = []
        
        try:
            community = device_config['snmp_community']
            port = device_config.get('snmp_port', 161)
            device_name = device_config['name']
            device_ip = device_config.get('ip')
            vendor = device_config.get('vendor', '').lower()
            
            self.logger.info(f"Starting collection for {device_name} ({device_ip})")
            
            # Test connectivity
            reachable = await self._test_connectivity(device_ip, community, port)
            
            # Collect device health metrics
            health_points = await self._collect_device_health(
                device_ip, community, port, device_name, vendor, reachable
            )
            points.extend(health_points)
            
            if not reachable:
                self.logger.warning(f"Device {device_name} is not reachable")
                return points
            
            # Get interface count using bulk GET
            num_interfaces = await self._snmp_get(device_ip, community, self.standard_oids['ifNumber'], port)
            if not num_interfaces or num_interfaces == 'None':
                self.logger.warning(f"Could not get interface count for {device_name}")
                return points
            
            try:
                if_count = int(num_interfaces)
                self.logger.info(f"Device {device_name} has {if_count} interfaces")
                points.append({
                    'measurement': 'device_health',
                    'tags': {'device_name': device_name, 'device_ip': device_ip},
                    'fields': {'ifNumber': if_count},
                    'time': datetime.utcnow()
                })
            except ValueError:
                if_count = 50
                self.logger.warning(f"Invalid interface count for {device_name}, defaulting to {if_count}")
            
            max_interfaces = min(if_count, 200)
            
            # Collect interface metrics using BULK operations
            interface_points = await self._collect_all_interfaces_bulk(
                device_ip, community, port, device_name, max_interfaces
            )
            points.extend(interface_points)
            
            self.logger.info(f"Collected {len(points)} metrics for {device_name}")
            return points
            
        except Exception as e:
            self.logger.error(f"SNMP collection failed for {device_name}: {e}", exc_info=True)
            return points
    
    async def _collect_all_interfaces_bulk(self, device_ip: str, community: str, port: int,
                                          device_name: str, max_interfaces: int) -> List[Dict]:
        """
        Collect interface metrics using SNMP BULK operations
        Much faster than collecting interface by interface
        """
        points = []
        timestamp = datetime.utcnow()
        
        try:
            transport = await UdpTransportTarget.create((device_ip, port), timeout=5, retries=1)
            
            # Bulk collect interface descriptions first
            interface_data = {}
            
            # Collect ifDescr table
            descr_oid = self.standard_oids['ifDescr']
            async for oid, value in self._walk_table_bulk(device_ip, community, descr_oid, transport, max_interfaces):
                if_index = oid.split('.')[-1]
                if if_index not in interface_data:
                    interface_data[if_index] = {}
                interface_data[if_index]['ifDescr'] = str(value)
            
            # Collect ifAlias table
            alias_oid = self.standard_oids['ifAlias']
            async for oid, value in self._walk_table_bulk(device_ip, community, alias_oid, transport, max_interfaces):
                if_index = oid.split('.')[-1]
                if if_index in interface_data:
                    interface_data[if_index]['ifAlias'] = str(value) if value != 'None' else interface_data[if_index]['ifDescr']
            
            # Collect ifOperStatus table
            oper_status_oid = self.standard_oids['ifOperStatus']
            async for oid, value in self._walk_table_bulk(device_ip, community, oper_status_oid, transport, max_interfaces):
                if_index = oid.split('.')[-1]
                if if_index in interface_data:
                    try:
                        interface_data[if_index]['ifOperStatus'] = int(value)
                    except (ValueError, TypeError):
                        pass
            
            # Collect ifAdminStatus table
            admin_status_oid = self.standard_oids['ifAdminStatus']
            async for oid, value in self._walk_table_bulk(device_ip, community, admin_status_oid, transport, max_interfaces):
                if_index = oid.split('.')[-1]
                if if_index in interface_data:
                    try:
                        interface_data[if_index]['ifAdminStatus'] = int(value)
                    except (ValueError, TypeError):
                        pass

            # Collect ifHighSpeed table (for interface speed)
            speed_oid = self.standard_oids['ifHighSpeed']
            async for oid, value in self._walk_table_bulk(device_ip, community, speed_oid, transport, max_interfaces):
                if_index = oid.split('.')[-1]
                if if_index in interface_data:
                    try:
                        speed_value = int(value) * 1000000  # Convert from Mbps to bps
                        interface_data[if_index]['ifHighSpeed'] = speed_value
                    except (ValueError, TypeError):
                        # Fallback to ifSpeed if ifHighSpeed fails
                        speed_fallback = await self._snmp_get(device_ip, community, self.standard_oids['ifSpeed'] + '.' + if_index, port)
                        if speed_fallback and speed_fallback != 'None':
                            interface_data[if_index]['ifHighSpeed'] = int(speed_fallback)
            # Collect traffic metrics for all interfaces with valid descriptions
            metric_oids = {
                'ifHCInOctets': self.standard_oids['ifHCInOctets'],
                'ifHCOutOctets': self.standard_oids['ifHCOutOctets'],
                'ifInUcastPkts': self.standard_oids['ifInUcastPkts'],
                'ifOutUcastPkts': self.standard_oids['ifOutUcastPkts'],
                'ifInOctets': self.standard_oids['ifInOctets'],
                'ifOutOctets': self.standard_oids['ifOutOctets'],
                'ifInDiscards': self.standard_oids['ifInDiscards'],
                'ifOutDiscards': self.standard_oids['ifOutDiscards'],
                'ifInErrors': self.standard_oids['ifInErrors'],
                'ifOutErrors': self.standard_oids['ifOutErrors'],
                'ifOperStatus': self.standard_oids['ifOperStatus'],
                'ifAdminStatus': self.standard_oids['ifAdminStatus'],
            }
            
            # Collect each metric table in bulk
            for metric_name, base_oid in metric_oids.items():
                async for oid, value in self._walk_table_bulk(device_ip, community, base_oid, transport, max_interfaces):
                    if_index = oid.split('.')[-1]
                    
                    if if_index not in interface_data:
                        continue
                    
                    if_info = interface_data[if_index]
                    if 'ifDescr' not in if_info:
                        continue
                    
                    try:
                        int_value = int(value)
                        base_tags = {
                            'device_name': device_name,
                            'device_ip': device_ip,
                            'ifDescr': if_info['ifDescr'],
                            'ifAlias': if_info.get('ifAlias', if_info['ifDescr']),
                            'ifIndex': if_index
                        }
                        
                        # Include speed if available
                        if 'ifHighSpeed' in if_info:
                            base_tags['ifHighSpeed'] = if_info['ifHighSpeed']

                        # Include operational and administrative status
                        if 'ifOperStatus' in if_info:
                            base_tags['ifOperStatus'] = if_info['ifOperStatus']
                        if 'ifAdminStatus' in if_info:
                            base_tags['ifAdminStatus'] = if_info['ifAdminStatus']

                        points.append({
                            'measurement': 'snmp_data',
                            'tags': {**base_tags, 'metric': metric_name},
                            'fields': {'value': int_value},
                            'time': timestamp
                        })
                    except (ValueError, TypeError):
                        continue
            
            self.logger.info(f"Bulk collected {len(points)} interface metrics for {device_name}")
            
        except Exception as e:
            self.logger.error(f"Bulk interface collection failed for {device_name}: {e}", exc_info=True)
        
        return points
    
    async def _walk_table_bulk(self, device_ip: str, community: str, base_oid: str,
                               transport, max_rows: int = 200):
        """
        Walk an SNMP table using BULK operations for better performance
        Yields (oid, value) tuples
        """
        try:
            current_oid = base_oid
            rows_collected = 0
            max_repetitions = 20  # Fetch 20 rows at a time
            
            while rows_collected < max_rows:
                errorIndication, errorStatus, errorIndex, varBinds = await bulk_cmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=1),
                    transport,
                    ContextData(),
                    0,  # non-repeaters
                    max_repetitions,  # max-repetitions
                    ObjectType(ObjectIdentity(current_oid)),
                    lexicographicMode=False
                )
                
                if errorIndication or errorStatus:
                    break
                
                if not varBinds:
                    break
                
                found_valid = False
                for varBind in varBinds:
                    oid_str = str(varBind[0])
                    value_str = str(varBind[1])
                    
                    # Check if still in the target table
                    if not oid_str.startswith(base_oid + '.'):
                        return
                    
                    if value_str and value_str != 'None':
                        yield oid_str, value_str
                        found_valid = True
                        rows_collected += 1
                        current_oid = oid_str
                        
                        if rows_collected >= max_rows:
                            return
                
                if not found_valid:
                    break
                    
        except Exception as e:
            self.logger.debug(f"Bulk walk error for {base_oid}: {e}")
    
    async def _test_connectivity(self, device_ip: str, community: str, port: int) -> bool:
        """Enhanced with retry + jitter"""
        for attempt in range(3):  # Retry 3x
            result = await self._snmp_get(device_ip, community, '1.3.6.1.2.1.1.1.0', port)
            if result and result != 'None':
                self.logger.debug(f"✓ {device_ip} reachable (attempt {attempt+1})")
                return True
            await asyncio.sleep(0.5 * (2 ** attempt))  # Backoff: 0.5s, 1s, 2s
        self.logger.warning(f"✗ {device_ip} UNREACHABLE after 3 retries")
        return False
    
    async def _collect_device_health(self, device_ip: str, community: str, port: int, 
                                    device_name: str, vendor: str, 
                                    reachable: bool) -> List[Dict]:
        """Collect device health metrics (CPU, Memory Used, Reachability, Uptime)"""
        points = []
        base_tags = {'device_name': device_name, 'device_ip': device_ip}
        timestamp = datetime.utcnow()

        # Add reachability metric
        points.append({
            'measurement': 'device_health',
            'tags': base_tags,
            'fields': {'reachable': 1 if reachable else 0},
            'time': timestamp
        })

        if not reachable:
            return points

        # Normalize vendor name
        if 'xr' in vendor or 'ios-xr' in vendor:
            vendor = 'cisco_xr'
        elif 'cisco' in vendor:
            vendor = 'cisco'
        elif 'juniper' in vendor or 'junos' in vendor:
            vendor = 'juniper'
        elif 'arista' in vendor:
            vendor = 'arista'
        else:
            vendor = 'cisco'

        # Get vendor-specific OIDs
        oids = self.vendor_oids.get(vendor, self.vendor_oids['cisco'])

        # Collect system info concurrently
        sys_descr_task = self._snmp_get(device_ip, community, self.standard_oids.get('sysDescr'), port)
        sys_uptime_task = self._snmp_get(device_ip, community, self.standard_oids.get('sysUpTime'), port)
        
        sys_descr, sys_uptime = await asyncio.gather(sys_descr_task, sys_uptime_task)

        if sys_descr and sys_descr != 'None':
            points.append({
                'measurement': 'device_health',
                'tags': base_tags,
                'fields': {'sysDescr': sys_descr},
                'time': timestamp
            })

        if sys_uptime and sys_uptime != 'None':
            try:
                uptime_ticks = int(sys_uptime)
                uptime_seconds = uptime_ticks / 100
                points.append({
                    'measurement': 'device_health',
                    'tags': base_tags,
                    'fields': {'uptime_seconds': uptime_seconds},
                    'time': timestamp
                })
            except ValueError:
                pass

        # Collect CPU and Memory using bulk operations
        try:
            transport = await UdpTransportTarget.create((device_ip, port), timeout=5, retries=1)
            
            # Collect CPU metrics (average across all CPUs)
            cpu_oid = oids.get('cpu_usage')
            if cpu_oid:
                cpu_values = []
                async for oid, value in self._walk_table_bulk(device_ip, community, cpu_oid, transport):
                    try:
                        cpu_value = float(value)
                        cpu_values.append(cpu_value)
                    except (ValueError, TypeError):
                        continue
                if cpu_values:
                    avg_cpu_usage = sum(cpu_values) / len(cpu_values) if cpu_values else 0.0
                    points.append({
                        'measurement': 'device_health',
                        'tags': base_tags,
                        'fields': {'cpu_usage': avg_cpu_usage},
                        'time': timestamp
                    })
                else:
                    self.logger.warning(f"No valid CPU usage data collected for {device_name}")

           # Collect Memory - different approach for Juniper vs others
            if vendor == 'juniper':
                # Juniper reports memory usage as percentage directly
                mem_used_oid = oids.get('memory_used')
                if mem_used_oid:
                    mem_percent_values = []
                    async for oid, value in self._walk_table_bulk(device_ip, community, mem_used_oid, transport):
                        try:
                            mem_percent = float(value)
                            mem_percent_values.append(mem_percent)
                        except (ValueError, TypeError):
                            continue
                    
                    if mem_percent_values:
                        avg_memory_percent = sum(mem_percent_values) / len(mem_percent_values)
                        points.append({
                            'measurement': 'device_health',
                            'tags': base_tags,
                            'fields': {'memory_usage_percent': round(avg_memory_percent, 2)},
                            'time': timestamp
                        })
                    else:
                        self.logger.warning(f"No valid memory data collected for {device_name}")
            else:
                # Cisco, Arista and others - calculate from used and free
                mem_used_oid = oids.get('memory_used')
                mem_free_oid = oids.get('memory_free')
                
                if mem_used_oid and mem_free_oid:
                    mem_used_values = []
                    mem_free_values = []
                    
                    # Collect memory used
                    async for oid, value in self._walk_table_bulk(device_ip, community, mem_used_oid, transport):
                        try:
                            mem_value = float(value)
                            mem_used_values.append(mem_value)
                        except (ValueError, TypeError):
                            continue
                    
                    # Collect memory free
                    async for oid, value in self._walk_table_bulk(device_ip, community, mem_free_oid, transport):
                        try:
                            mem_value = float(value)
                            mem_free_values.append(mem_value)
                        except (ValueError, TypeError):
                            continue
                    
                    if mem_used_values and mem_free_values:
                        total_mem_used = sum(mem_used_values)
                        total_mem_free = sum(mem_free_values)
                        total_memory = total_mem_used + total_mem_free
                        
                        if total_memory > 0:
                            memory_usage_percent = (total_mem_used / total_memory) * 100
                            points.append({
                                'measurement': 'device_health',
                                'tags': base_tags,
                                'fields': {'memory_usage_percent': round(memory_usage_percent, 2)},
                                'time': timestamp
                            })
                        else:
                            self.logger.warning(f"Total memory is zero for {device_name}")
                    else:
                        self.logger.warning(f"No valid memory data collected for {device_name}")

                    
                else:
                    self.logger.warning(f"No valid memory used data collected for {device_name}")
                        
        except Exception as e:
            self.logger.error(f"Health metrics collection failed for {device_name}: {e}")
 
        return points
    
    async def _snmp_get(self, device_ip: str, community: str, oid: str, port: int = 161):
        """Enhanced SNMP GET with FULL error logging"""
        try:
            transport = await UdpTransportTarget.create((device_ip, port), timeout=8, retries=3)  # ↑ Timeout/Retries
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            
            # **NEW: Detailed Logging**
            if errorIndication:
                self.logger.warning(f"SNMP ERR {device_ip}:{oid} - Indication: {errorIndication}")
                return None
            if errorStatus:
                self.logger.warning(f"SNMP ERR {device_ip}:{oid} - Status: {errorStatus.prettyPrint()} (Index: {errorIndex})")
                return None
            if not varBinds:
                self.logger.debug(f"SNMP EMPTY {device_ip}:{oid}")
                return None
                
            return str(varBinds[0][1])
        except Exception as e:
            self.logger.error(f"SNMP EXCEPTION {device_ip}:{oid} - {e}")
            return None
