# -*- coding: utf-8 -*-
# Copyright 2020 CISCO. All rights reserved.
# Copyright 2021 Kirk Byers. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""NETCONF Driver for IOSXR devices."""

from __future__ import unicode_literals

# import stdlib
import re
import copy
import difflib
import ipaddress
import logging
import datetime

# import third party lib
from ncclient import manager
from ncclient.xml_ import to_ele
from ncclient.operations.rpc import RPCError
from ncclient.operations.errors import TimeoutExpiredError
from lxml import etree as ETREE
from lxml.etree import XMLSyntaxError

# import NAPALM base
from napalm.iosxr_netconf import constants as C
from napalm.iosxr.utilities import strip_config_header
from napalm.base.base import NetworkDriver
import napalm.base.helpers
from napalm.base.exceptions import ConnectionException
from napalm.base.exceptions import MergeConfigException
from napalm.base.exceptions import ReplaceConfigException

# Add these to the C.NS dictionary or constants section
ALARM_RPC_REQ_FILTER = """
<alarms xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-alarmgr-server-oper">
    <brief><brief-card><brief-locations><brief-location/></brief-locations></brief-card></brief>
    <detail><detail-card><detail-locations><detail-location/></detail-locations></detail-card></detail>
</alarms>
"""

ROUTE_IPV4_RPC_REQ_FILTER = """
<rib xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ip-rib-ipv4-oper">
    <vrfs><vrf><afs><af><safs><saf><ip-rib-route-table-names>
    <ip-rib-route-table-name><routes><route>
        <prefix>{network}</prefix><prefix-length-xr>{prefix_length}</prefix-length-xr>
    </route></routes></ip-rib-route-table-name>
    </ip-rib-route-table-names></saf></safs></af></afs></vrf></vrfs>
</rib>
"""

ROUTE_IPV6_RPC_REQ_FILTER = """
<ipv6-rib xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ip-rib-ipv6-oper">
    <vrfs><vrf><afs><af><safs><saf><ip-rib-route-table-names>
    <ip-rib-route-table-name><routes><route>
        <prefix>{network}</prefix><prefix-length-xr>{prefix_length}</prefix-length-xr>
    </route></routes></ip-rib-route-table-name>
    </ip-rib-route-table-names></saf></safs></af></afs></vrf></vrfs>
</ipv6-rib>
"""
# Add after the existing ROUTE filters
ENV_RPC_REQ_FILTER = """
<environment xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-sysadmin-envmon-ui">
    <oper>
        <temperatures/>
        <power-supply/>
        <fan/>
    </oper>
</environment>
"""

# Verify ALARM_RPC_REQ_FILTER exists - if not, add it:
ALARM_RPC_REQ_FILTER = """
<alarms xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-alarmgr-server-oper">
    <brief>
        <brief-card>
            <brief-locations>
                <brief-location/>
            </brief-locations>
        </brief-card>
    </brief>
    <detail>
        <detail-card>
            <detail-locations>
                <detail-location/>
            </detail-locations>
        </detail-card>
    </detail>
</alarms>
"""

logger = logging.getLogger(__name__)

NS = {
    "if": "http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-cfg",
    "ipv4": "http://cisco.com/ns/yang/Cisco-IOS-XR-ipv4-io-cfg",
    "alm": "http://cisco.com/ns/yang/Cisco-IOS-XR-alarmgr-oper",
}


class IOSXRNETCONFDriver(NetworkDriver):
    """IOS-XR NETCONF driver class: inherits NetworkDriver from napalm.base."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialize IOSXR driver.

        optional_args:
            * config_lock (True/False): lock configuration DB after the
                connection is established.
            * port (int): custom port
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
        self.port = self.optional_args.pop("port", 2022)
        self.lock_on_connect = self.optional_args.pop("config_lock", False)
        self.key_file = self.optional_args.pop("key_file", None)
        self.config_encoding = self.optional_args.pop("config_encoding", "cli")
        if self.config_encoding not in C.CONFIG_ENCODINGS:
            raise ValueError(f"config encoding must be one of {C.CONFIG_ENCODINGS}")

        self.platform = "iosxr_netconf"
        self.device = None
        self.module_set_ns = []

    def open(self):
        """Open the connection with the device with port auto-detection."""
        ports_to_try = [self.port]  # Try configured port first
        
        # Add fallback port
        if self.port == 2022 and 830 not in ports_to_try:
            ports_to_try.append(830)
        elif self.port == 830 and 2022 not in ports_to_try:
            ports_to_try.append(2022)
        
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
                    device_params={"name": "iosxr"},
                    **self.optional_args,
                )
                
                # If successful, update the port and proceed
                self.port = port
                logger.info(f"Successfully connected to {self.hostname}:{port}")
                
                if self.lock_on_connect:
                    self._lock()
                
                # Retrieve module-set namespaces based on yang library model
                for capability in self.device.server_capabilities:
                    if C.NS["ylib"] in capability:
                        rpc_reply = self.device.get(
                            filter=(
                                "subtree",
                                C.YANG_LIB_RPC_REQ_FILTER.format(module_set=C.MODULE_SET),
                            )
                        ).xml
                        rpc_reply_etree = ETREE.fromstring(rpc_reply)
                        module_set_tree = rpc_reply_etree.xpath(
                            ".//ylib:yang-library/ylib:module-set/ylib:module/ylib:namespace",
                            namespaces=C.NS,
                        )
                        self.module_set_ns = [n.text for n in module_set_tree]
                        break
                
                return  # Successful connection
                
            except Exception as conn_err:
                last_error = conn_err
                logger.warning(f"Connection failed on port {port}: {conn_err}")
                continue
        
        # If all ports failed
        error_msg = f"Failed to connect to {self.hostname} on ports {ports_to_try}. Last error: {last_error}"
        logger.error(error_msg)
        raise ConnectionException(error_msg)

    def close(self):
        """Close the connection."""
        logger.debug("Closed connection with device %s" % (self.hostname))
        self._unlock()
        self.device.close_session()

    def _lock(self):
        """Lock the config DB."""
        if not self.locked:
            self.device.lock()
            self.locked = True

    def _unlock(self):
        """Unlock the config DB."""
        if self.locked:
            self.device.unlock()
            self.locked = False

    def _load_config(self, filename, config):
        """Edit Configuration."""
        if filename is None:
            configuration = config
        else:
            with open(filename) as f:
                configuration = f.read()
        self.pending_changes = True
        self._lock()
        return configuration

    def _filter_config_tree(self, tree):
        """Return filtered config etree based on YANG module set."""
        if self.module_set_ns:

            def unexpected(n):
                return n not in self.module_set_ns

        else:

            def unexpected(n):
                return n.startswith("http://openconfig.net/yang")

        for subtree in tree:
            if unexpected(subtree.tag[1:].split("}")[0]):
                tree.remove(subtree)
        return tree

    def _unexpected_modules(self, tree):
        """Return list of unexpected modules based on YANG module set."""
        modules = []
        if self.module_set_ns:

            def unexpected(n):
                return n not in self.module_set_ns

        else:

            def unexpected(n):
                return n.startswith("http://openconfig.net/yang")

        for subtree in tree:
            namespace = subtree.tag[1:].split("}")[0]
            if unexpected(namespace):
                modules.append(namespace)
        return modules

    def is_alive(self):
        """Return flag with the state of the connection."""
        if self.device is None:
            return {"is_alive": False}
        return {"is_alive": self.device._session.transport.is_active()}

    def load_replace_candidate(self, filename=None, config=None):
        """Open the candidate config and replace."""
        self.replace = True
        configuration = self._load_config(filename=filename, config=config)
        if self.config_encoding == "cli":
            configuration = (
                '<config><cli xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-cli-cfg">'
                + configuration
                + "</cli></config>"
            )
        elif self.config_encoding == "xml":
            parser = ETREE.XMLParser(remove_blank_text=True)
            unexpected_modules = self._unexpected_modules(
                ETREE.XML(configuration, parser=parser)
            )
            if unexpected_modules:
                raise ReplaceConfigException(
                    f'{C.INVALID_MODEL_REFERENCE} ({", ".join(unexpected_modules)})'
                )

        configuration = "<source>" + configuration + "</source>"
        try:
            self.device.copy_config(source=configuration, target="candidate")
        except (RPCError, XMLSyntaxError) as e:
            self.pending_changes = False
            self.replace = False
            logger.error(e.args[0])
            raise ReplaceConfigException(e)

    def load_merge_candidate(self, filename=None, config=None):
        """Open the candidate config and merge."""
        self.replace = False
        configuration = self._load_config(filename=filename, config=config)
        if self.config_encoding == "cli":
            configuration = (
                '<config><cli xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-cli-cfg">'
                + configuration
                + "</cli></config>"
            )
        elif self.config_encoding == "xml":
            parser = ETREE.XMLParser(remove_blank_text=True)
            unexpected_modules = self._unexpected_modules(
                ETREE.XML(configuration, parser=parser)
            )
            if unexpected_modules:
                raise MergeConfigException(
                    f'{C.INVALID_MODEL_REFERENCE} ({", ".join(unexpected_modules)})'
                )

        try:
            self.device.edit_config(
                config=configuration, error_option="rollback-on-error"
            )
        except (RPCError, XMLSyntaxError) as e:
            self.pending_changes = False
            logger.error(e.args[0])
            raise MergeConfigException(e)

    def compare_config(self):
        """Compare candidate config with running."""

        diff = ""
        encoding = self.config_encoding
        if encoding not in C.CLI_DIFF_RPC_REQ:
            raise NotImplementedError(
                f"config encoding must be one of {C.CONFIG_ENCODINGS}"
            )

        if self.pending_changes:
            parser = ETREE.XMLParser(remove_blank_text=True)
            if encoding == "cli":
                diff = self.device.dispatch(to_ele(C.CLI_DIFF_RPC_REQ)).xml
                diff = ETREE.XML(diff, parser=parser)[0].text.strip()
                diff = strip_config_header(diff)
            elif encoding == "xml":
                run_conf = self.device.get_config("running").xml
                can_conf = self.device.get_config("candidate").xml
                run_conf = ETREE.tostring(
                    self._filter_config_tree(ETREE.XML(run_conf, parser=parser)[0]),
                    pretty_print=True,
                ).decode()
                can_conf = ETREE.tostring(
                    self._filter_config_tree(ETREE.XML(can_conf, parser=parser)[0]),
                    pretty_print=True,
                ).decode()
                for line in difflib.unified_diff(
                    run_conf.splitlines(1), can_conf.splitlines(1)
                ):
                    diff += line

        return diff

    def commit_config(self, message="", revert_in=None):
        """Commit configuration."""
        if revert_in is not None:
            raise NotImplementedError(
                "Commit confirm has not been implemented on this platform."
            )
        if message:
            raise NotImplementedError(
                "Commit message not implemented for this platform"
            )
        self.device.commit()
        self.pending_changes = False
        self._unlock()

    def discard_config(self):
        """Discard changes."""
        self.device.discard_changes()
        self.pending_changes = False
        self._unlock()

    def rollback(self):
        """Rollback to previous commit."""
        self.device.dispatch(to_ele(C.ROLLBACK_RPC_REQ))

    def _find_txt(self, xml_tree, path, default=None, namespaces=None):
        """
        Extract the text value from a leaf in an XML tree using XPath.

        Will return a default value if leaf path not matched.
        :param xml_tree:the XML Tree object. <type'lxml.etree._Element'>.
        :param path: XPath to be applied in order to extract the desired data.
        :param default:  Value to be returned in case of a no match.
        :param namespaces: namespace dictionary.
        :return: a str value or None if leaf path not matched.
        """

        value = None
        xpath_applied = xml_tree.xpath(path, namespaces=namespaces)
        if xpath_applied:
            if not len(xpath_applied[0]):
                if xpath_applied[0].text is not None:
                    value = xpath_applied[0].text.strip()
                else:
                    value = ""
        else:
            value = default

        return value
    
    def _rpc(self, rpc_command):
        """
        Execute an RPC command and return the result tree.
        
        Args:
            rpc_command: RPC command string
            
        Returns:
            lxml.etree._Element: Parsed XML tree
        """
        try:
            rpc_reply = self.device.dispatch(to_ele(rpc_command))
            return ETREE.fromstring(rpc_reply.xml)
        except Exception as e:
            logger.error(f"RPC execution failed: {e}")
            raise

    def _find_text(self, tree, xpath, default=''):
        """
        Find text content using XPath (alias for _find_txt for compatibility).
        
        Args:
            tree: XML tree element
            xpath: XPath expression
            default: Default value if not found
            
        Returns:
            str: Text content or default
        """
        try:
            elements = tree.xpath(xpath)
            if elements and len(elements) > 0:
                elem = elements[0]
                if hasattr(elem, 'text') and elem.text:
                    return elem.text.strip()
            return default
        except Exception as e:
            logger.debug(f"XPath query failed: {xpath} - {e}")
            return default

    def get_facts(self):
        """Return facts of the device."""
        facts = {
            "vendor": "Cisco",
            "os_version": "",
            "hostname": "",
            "uptime": -1.0,
            "serial_number": "",
            "fqdn": "",
            "model": "",
            "interface_list": [],
        }
        interface_list = []

        facts_rpc_reply = self.device.dispatch(to_ele(C.FACTS_RPC_REQ)).xml

        # Converts string to etree
        facts_rpc_reply_etree = ETREE.fromstring(facts_rpc_reply)

        # Retrieves hostname
        hostname = napalm.base.helpers.convert(
            str,
            self._find_txt(
                facts_rpc_reply_etree,
                ".//suo:system-time/\
            suo:uptime/suo:host-name",
                default="",
                namespaces=C.NS,
            ),
        )

        # Retrieves uptime
        uptime = napalm.base.helpers.convert(
            float,
            self._find_txt(
                facts_rpc_reply_etree,
                ".//suo:system-time/\
            suo:uptime/suo:uptime",
                default="",
                namespaces=C.NS,
            ),
            -1.0,
        )

        # Retrieves interfaces name
        interface_tree = facts_rpc_reply_etree.xpath(
            ".//int:interfaces/int:interfaces/int:interface", namespaces=C.NS
        )
        for interface in interface_tree:
            name = self._find_txt(
                interface, "./int:interface-name", default="", namespaces=C.NS
            )
            interface_list.append(name)
        # Retrieves os version, model, serial number
        basic_info_tree = facts_rpc_reply_etree.xpath(
            ".//imo:inventory/imo:entities/imo:entity/imo:attributes/\
                        imo:inv-basic-bag",
            namespaces=C.NS,
        )
        if basic_info_tree:
            os_version = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    basic_info_tree[0],
                    "./imo:software-revision",
                    default="",
                    namespaces=C.NS,
                ),
            )
            model = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    basic_info_tree[0], "./imo:model-name", default="", namespaces=C.NS
                ),
            )
            serial = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    basic_info_tree[0],
                    "./imo:serial-number",
                    default="",
                    namespaces=C.NS,
                ),
            )
        else:
            os_version = ""
            model = ""
            serial = ""

        facts.update(
            {
                "os_version": os_version,
                "hostname": hostname,
                "model": model,
                "uptime": uptime,
                "serial_number": serial,
                "fqdn": hostname,
                "interface_list": interface_list,
            }
        )

        return facts

    def get_interfaces(self):
        """Return interfaces details."""
        interfaces = {}

        INTERFACE_DEFAULTS = {
            "is_enabled": False,
            "is_up": False,
            "mac_address": "",
            "description": "",
            "speed": -1.0,
            "last_flapped": -1.0,
        }

        interfaces_rpc_reply = self.device.get(
            filter=("subtree", C.INT_RPC_REQ_FILTER)
        ).xml
        # Converts string to etree
        interfaces_rpc_reply_etree = ETREE.fromstring(interfaces_rpc_reply)

        # Retrieves interfaces details
        for interface_tree, description_tree in zip(
            interfaces_rpc_reply_etree.xpath(
                ".//int:interfaces/int:interface-xr/int:interface", namespaces=C.NS
            ),
            interfaces_rpc_reply_etree.xpath(
                ".//int:interfaces/int:interfaces/int:interface", namespaces=C.NS
            ),
        ):
            interface_name = self._find_txt(
                interface_tree, "./int:interface-name", default="", namespaces=C.NS
            )
            if not interface_name:
                continue
            is_up = (
                self._find_txt(
                    interface_tree, "./int:line-state", default="", namespaces=C.NS
                )
                == "im-state-up"
            )
            enabled = (
                self._find_txt(
                    interface_tree, "./int:state", default="", namespaces=C.NS
                )
                != "im-state-admin-down"
            )
            raw_mac = self._find_txt(
                interface_tree,
                "./int:mac-address/int:address",
                default="",
                namespaces=C.NS,
            )
            mac_address = napalm.base.helpers.convert(
                napalm.base.helpers.mac, raw_mac, raw_mac
            )
            speed = napalm.base.helpers.convert(
                float,
                napalm.base.helpers.convert(
                    float,
                    self._find_txt(interface_tree, "./int:bandwidth", namespaces=C.NS),
                    0,
                )
                * 1e-3,
            )
            mtu = int(
                self._find_txt(interface_tree, "./int:mtu", default="", namespaces=C.NS)
            )
            description = self._find_txt(
                description_tree, "./int:description", default="", namespaces=C.NS
            )
            interfaces[interface_name] = copy.deepcopy(INTERFACE_DEFAULTS)
            interfaces[interface_name].update(
                {
                    "is_up": is_up,
                    "speed": speed,
                    "mtu": mtu,
                    "is_enabled": enabled,
                    "mac_address": mac_address,
                    "description": description,
                }
            )

        return interfaces

    def get_interfaces_counters(self):
        """Return interfaces counters."""
        rpc_reply = self.device.get(
            filter=("subtree", C.INT_COUNTERS_RPC_REQ_FILTER)
        ).xml
        # Converts string to tree
        rpc_reply_etree = ETREE.fromstring(rpc_reply)

        interface_counters = {}

        # Retrieves interfaces counters details
        interface_xr_tree = rpc_reply_etree.xpath(
            ".//int:interfaces/int:interface-xr/int:interface", namespaces=C.NS
        )
        for interface in interface_xr_tree:
            interface_name = self._find_txt(
                interface, "./int:interface-name", default="", namespaces=C.NS
            )
            if interface_name[:8] == "Loopback" and interface_name[8:].isdigit():
                continue
            interface_stats = {}
            if (
                self._find_txt(
                    interface,
                    "./int:interface-statistics/int:stats-type",
                    default="",
                    namespaces=C.NS,
                )
                == "basic"
            ):
                interface_stats["tx_multicast_packets"] = ""
                interface_stats["tx_discards"] = ""
                interface_stats["tx_octets"] = ""
                interface_stats["tx_errors"] = ""
                interface_stats["rx_octets"] = ""
                interface_stats["tx_unicast_packets"] = ""
                interface_stats["rx_errors"] = ""
                interface_stats["tx_broadcast_packets"] = ""
                interface_stats["rx_multicast_packets"] = ""
                interface_stats["rx_broadcast_packets"] = ""
                interface_stats["rx_discards"] = ""
                interface_stats["rx_unicast_packets"] = ""
            else:
                int_stats_xpath = "./int:interface-statistics/int:full-interface-stats/"
                interface_stats["tx_multicast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath + "int:multicast-packets-sent",
                        "0",
                        namespaces=C.NS,
                    ),
                )
                interface_stats["tx_discards"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath + "int:output-drops",
                        "0",
                        namespaces=C.NS,
                    ),
                )
                interface_stats["tx_octets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath + "int:bytes-sent",
                        "0",
                        namespaces=C.NS,
                    ),
                )
                interface_stats["tx_errors"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath + "int:output-errors",
                        "0",
                        namespaces=C.NS,
                    ),
                )
                interface_stats["rx_octets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath + "int:bytes-received",
                        "0",
                        namespaces=C.NS,
                    ),
                )
                interface_stats["tx_unicast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath + "int:packets-sent",
                        "0",
                        namespaces=C.NS,
                    ),
                )
                interface_stats["rx_errors"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath + "int:input-errors",
                        "0",
                        namespaces=C.NS,
                    ),
                )
                interface_stats["tx_broadcast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath + "int:broadcast-packets-sent",
                        "0",
                        namespaces=C.NS,
                    ),
                )
                interface_stats["rx_multicast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath + "int:multicast-packets-received",
                        "0",
                        namespaces=C.NS,
                    ),
                )
                interface_stats["rx_broadcast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath + "int:broadcast-packets-received",
                        "0",
                        namespaces=C.NS,
                    ),
                )
                interface_stats["rx_discards"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath + "int:input-drops",
                        "0",
                        namespaces=C.NS,
                    ),
                )
                interface_stats["rx_unicast_packets"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        interface,
                        int_stats_xpath + "int:packets-received",
                        "0",
                        namespaces=C.NS,
                    ),
                )

            interface_counters[interface_name] = interface_stats

        return interface_counters

    def get_bgp_neighbors(self):
        """Return BGP neighbors details."""

        def get_vrf_neighbors(rpc_reply_etree, xpath):
            """Return BGP neighbors details for a given VRF."""
            neighbors = {}

            for neighbor in rpc_reply_etree.xpath(xpath, namespaces=C.NS):
                this_neighbor = {}
                this_neighbor["local_as"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor, "./bgp:local-as", default="", namespaces=C.NS
                    ),
                )
                this_neighbor["remote_as"] = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor, "./bgp:remote-as", default="", namespaces=C.NS
                    ),
                )
                this_neighbor["remote_id"] = napalm.base.helpers.convert(
                    str,
                    self._find_txt(
                        neighbor, "./bgp:router-id", default="", namespaces=C.NS
                    ),
                )
                try:
                    this_neighbor["description"] = napalm.base.helpers.convert(
                        str,
                        self._find_txt(
                            neighbor, "./bgp:description", default="", namespaces=C.NS
                        ),
                    )
                except AttributeError:
                    logger.debug(
                        "No attribute 'description' for neighbor %s"
                        % (this_neighbor["remote_as"])
                    )
                    this_neighbor["description"] = ""

                this_neighbor["is_enabled"] = not (
                    self._find_txt(
                        neighbor,
                        "./bgp:is-administratively-shut-down",
                        default="",
                        namespaces=C.NS,
                    )
                    == "true"
                )
                if (
                    str(
                        self._find_txt(
                            neighbor,
                            "./bgp:connection-state",
                            default="",
                            namespaces=C.NS,
                        )
                    )
                    == "bgp-st-estab"
                ):
                    this_neighbor["is_up"] = True
                    this_neighbor["uptime"] = napalm.base.helpers.convert(
                        int,
                        self._find_txt(
                            neighbor,
                            "./bgp:connection-established-time",
                            default="",
                            namespaces=C.NS,
                        ),
                    )
                else:
                    this_neighbor["is_up"] = False
                    this_neighbor["uptime"] = -1

                this_neighbor["address_family"] = {}

                if (
                    self._find_txt(
                        neighbor,
                        "./bgp:connection-remote-address/\
                     bgp:afi",
                        default="",
                        namespaces=C.NS,
                    )
                    == "ipv4"
                ):
                    this_afi = "ipv4"
                elif (
                    self._find_txt(
                        neighbor,
                        "./bgp:connection-remote-address/bgp:afi",
                        default="",
                        namespaces=C.NS,
                    )
                    == "ipv6"
                ):
                    this_afi = "ipv6"
                else:
                    this_afi = self._find_txt(
                        neighbor,
                        "./bgp:connection-remote-address/bgp:afi",
                        default="",
                        namespaces=C.NS,
                    )

                this_neighbor["address_family"][this_afi] = {}

                try:
                    this_neighbor["address_family"][this_afi][
                        "received_prefixes"
                    ] = napalm.base.helpers.convert(
                        int,
                        self._find_txt(
                            neighbor,
                            "./bgp:af-data/bgp:prefixes-accepted",
                            default="",
                            namespaces=C.NS,
                        ),
                        0,
                    ) + napalm.base.helpers.convert(
                        int,
                        self._find_txt(
                            neighbor,
                            "./bgp:af-data/bgp:prefixes-denied",
                            default="",
                            namespaces=C.NS,
                        ),
                        0,
                    )
                    this_neighbor["address_family"][this_afi]["accepted_prefixes"] = (
                        napalm.base.helpers.convert(
                            int,
                            self._find_txt(
                                neighbor,
                                "./bgp:af-data/bgp:prefixes-accepted",
                                default="",
                                namespaces=C.NS,
                            ),
                            0,
                        )
                    )
                    this_neighbor["address_family"][this_afi]["sent_prefixes"] = (
                        napalm.base.helpers.convert(
                            int,
                            self._find_txt(
                                neighbor,
                                "./bgp:af-data/\
                            bgp:prefixes-advertised",
                                default="",
                                namespaces=C.NS,
                            ),
                            0,
                        )
                    )
                except AttributeError:
                    this_neighbor["address_family"][this_afi]["received_prefixes"] = -1
                    this_neighbor["address_family"][this_afi]["accepted_prefixes"] = -1
                    this_neighbor["address_family"][this_afi]["sent_prefixes"] = -1

                neighbor_ip = napalm.base.helpers.ip(
                    self._find_txt(
                        neighbor, "./bgp:neighbor-address", default="", namespaces=C.NS
                    )
                )

                neighbors[neighbor_ip] = this_neighbor

            return neighbors

        rpc_reply = self.device.get(filter=("subtree", C.BGP_NEIGHBOR_REQ_FILTER)).xml
        # Converts string to tree
        rpc_reply_etree = ETREE.fromstring(rpc_reply)
        result = {}
        this_vrf = {}
        this_vrf["peers"] = {}

        # get neighbors and router id from default(global) VRF
        default_vrf_xpath = """.//bgp:bgp/bgp:instances/bgp:instance/
          bgp:instance-active/bgp:default-vrf/"""
        this_vrf["router_id"] = napalm.base.helpers.convert(
            str,
            self._find_txt(
                rpc_reply_etree,
                default_vrf_xpath
                + "bgp:global-process-info/\
                    bgp:vrf/bgp:router-id",
                default="",
                namespaces=C.NS,
            ),
        )
        this_vrf["peers"] = get_vrf_neighbors(
            rpc_reply_etree, default_vrf_xpath + "bgp:neighbors/bgp:neighbor"
        )
        result["global"] = this_vrf

        # get neighbors and router id from other VRFs
        vrf_xpath = """.//bgp:bgp/bgp:instances/
                    bgp:instance/bgp:instance-active/bgp:vrfs"""
        for vrf in rpc_reply_etree.xpath(vrf_xpath + "/bgp:vrf", namespaces=C.NS):
            this_vrf = {}
            this_vrf["peers"] = {}
            this_vrf["router_id"] = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    vrf,
                    "./bgp:global-process-info/bgp:vrf/\
                                    bgp:router-id",
                    default="",
                    namespaces=C.NS,
                ),
            )
            vrf_name = self._find_txt(
                vrf, "./bgp:vrf-name", default="", namespaces=C.NS
            )
            this_vrf["peers"] = get_vrf_neighbors(
                rpc_reply_etree,
                vrf_xpath
                + "/bgp:vrf[bgp:vrf-name='"
                + vrf_name
                + "']\
                        /bgp:neighbors/bgp:neighbor",
            )
            result[vrf_name] = this_vrf

        return result

    def get_environment(self):
        """Return complete hardware & environment details with CPU, Memory, and modules - ENHANCED."""
        environment = {
            "hardware": {},
            "fans": {},
            "temperature": {},
            "power": {},
            "cpu": {},
            "memory": {}
        }

        logger.info("=" * 80)
        logger.info("ENVIRONMENT COLLECTION STARTING (FULL HARDWARE + METRICS)")
        logger.info("=" * 80)

        try:
            # =====================================================
            # 1️⃣ HARDWARE INVENTORY (Modules, Line Cards, Power)
            # =====================================================
            try:
                logger.info("Step 1: Collecting hardware inventory...")
                hw_rpc = """
                <inventory xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-invmgr-oper">
                    <entities>
                        <entity/>
                    </entities>
                </inventory>
                """
                hw_reply = self.device.get(filter=("subtree", hw_rpc)).xml
                hw_tree = ETREE.fromstring(hw_reply)
                
                count = 0
                for entity in hw_tree.xpath(".//imo:inventory/imo:entities/imo:entity", namespaces=C.NS):
                    name_elem = entity.find('./imo:name', namespaces=C.NS)
                    name = name_elem.text.strip() if name_elem is not None and name_elem.text else None
                    
                    if not name:
                        continue
                    
                    attrs = entity.find('.//imo:attributes/imo:inv-basic-bag', namespaces=C.NS)
                    if attrs is not None:
                        model = self._find_txt(attrs, "./imo:model-name", "", namespaces=C.NS)
                        desc = self._find_txt(attrs, "./imo:description", "", namespaces=C.NS)
                        serial = self._find_txt(attrs, "./imo:serial-number", "", namespaces=C.NS)
                        hw_rev = self._find_txt(attrs, "./imo:hardware-revision", "", namespaces=C.NS)
                        sw_rev = self._find_txt(attrs, "./imo:software-revision", "", namespaces=C.NS)

                        environment["hardware"][name] = {
                            "model": model,
                            "description": desc,
                            "serial_number": serial,
                            "hw_revision": hw_rev,
                            "sw_revision": sw_rev,
                        }
                        count += 1
                logger.info(f"  ✓ Hardware: {count} components collected")

            except Exception as hw_err:
                logger.warning(f"  ✗ Hardware inventory failed: {hw_err}")

            
            # =====================================================# =====================================================
            # 2️⃣ ENVIRONMENT SENSORS - ENHANCED WITH CLI FALLBACK
            # =====================================================
            try:
                logger.info("Step 2: Collecting environment sensors...")
                
                # Try NETCONF methods first (keep existing code)
                env_filters = [
                    """
                    <environment xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-sysadmin-envmon-ui">
                        <oper>
                            <temperatures/>
                            <power/>
                            <fan/>
                        </oper>
                    </environment>
                    """,
                ]
                
                env_data_found = False
                
                for env_filter in env_filters:
                    try:
                        rpc_reply = self.device.get(filter=("subtree", env_filter), timeout=15).xml
                        tree = ETREE.fromstring(rpc_reply)
                        
                        if tree.find('.//*') is not None:
                            ns_variants = [
                                {'env': 'http://cisco.com/ns/yang/Cisco-IOS-XR-sysadmin-envmon-ui'},
                            ]
                            
                            # Temperature
                            for ns in ns_variants:
                                temp_xpath = ".//env:environment/env:oper/env:temperatures/env:location"
                                locations = tree.xpath(temp_xpath, namespaces=ns)
                                if locations:
                                    for location in locations:
                                        for sensor in location.xpath('.//env:sensor-attributes', namespaces=ns):
                                            sensor_name = self._find_txt(sensor, './env:sensor', '', namespaces=ns)
                                            temp_value = self._find_txt(sensor, './env:sensor-current-reading', '0', namespaces=ns)
                                            if sensor_name and temp_value:
                                                try:
                                                    temp_float = float(temp_value)
                                                    environment["temperature"][sensor_name] = {
                                                        "temperature": temp_float,
                                                        "is_alert": temp_float > 70,
                                                        "is_critical": temp_float > 85
                                                    }
                                                    env_data_found = True
                                                except (ValueError, TypeError):
                                                    pass
                            
                            # Power
                            for ns in ns_variants:
                                power_xpath = ".//env:environment/env:oper/env:power/env:location"
                                locations = tree.xpath(power_xpath, namespaces=ns)
                                if locations:
                                    for location in locations:
                                        for psu in location.xpath('.//env:pem-attributes', namespaces=ns):
                                            psu_name = self._find_txt(psu, './env:pem', '', namespaces=ns)
                                            if psu_name:
                                                environment["power"][psu_name] = {
                                                    "status": True,
                                                    "capacity": -1.0,
                                                    "output": -1.0
                                                }
                                                env_data_found = True
                            
                            # Fans
                            for ns in ns_variants:
                                fan_xpath = ".//env:environment/env:oper/env:fan/env:location"
                                locations = tree.xpath(fan_xpath, namespaces=ns)
                                if locations:
                                    for location in locations:
                                        for fan in location.xpath('.//env:fan-attributes', namespaces=ns):
                                            fan_name = self._find_txt(fan, './env:fan', '', namespaces=ns)
                                            if fan_name:
                                                environment["fans"][fan_name] = {"status": True}
                                                env_data_found = True
                            
                            if env_data_found:
                                break
                    except Exception:
                        continue
                
                # CLI FALLBACK for environment data
                if not env_data_found:
                    logger.info("  NETCONF failed, trying CLI for environment data...")
                    
                    # Try show environment
                    try:
                        env_cli_rpc = """
                        <action xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-action">
                            <cli-exec-action-xr>
                                <cmd>show environment</cmd>
                            </cli-exec-action-xr>
                        </action>
                        """
                        env_reply = self.device.dispatch(to_ele(env_cli_rpc), timeout=30).xml
                        env_tree = ETREE.fromstring(env_reply)
                        
                        env_output = ""
                        for elem in env_tree.iter():
                            if elem.text:
                                env_output += str(elem.text) + "\n"
                        
                        if env_output and len(env_output) > 50:
                            import re
                            
                            # Parse temperatures
                            temp_matches = re.findall(r'([\w\s/\-]+)\s+(\d+)\s+Celsius', env_output, re.IGNORECASE)
                            for sensor_name, temp_str in temp_matches:
                                sensor_name = sensor_name.strip()
                                temp_float = float(temp_str)
                                environment["temperature"][sensor_name] = {
                                    "temperature": temp_float,
                                    "is_alert": temp_float > 70,
                                    "is_critical": temp_float > 85
                                }
                                env_data_found = True
                            
                            # Parse power supplies
                            psu_matches = re.findall(r'(Power\s+\w+|PEM\s+\d+|PS\d+)\s+(OK|Active|On)', env_output, re.IGNORECASE)
                            for psu_name, status in psu_matches:
                                psu_name = psu_name.strip()
                                environment["power"][psu_name] = {
                                    "status": True,
                                    "capacity": -1.0,
                                    "output": -1.0
                                }
                                env_data_found = True
                            
                            # Parse fans
                            fan_matches = re.findall(r'(Fan[\s\w/\-]+|FAN\s+\d+)\s+(OK|Active|On)', env_output, re.IGNORECASE)
                            for fan_name, status in fan_matches:
                                fan_name = fan_name.strip()
                                environment["fans"][fan_name] = {"status": True}
                                env_data_found = True
                            
                            if env_data_found:
                                logger.info(f"  ✓ Environment (CLI): {len(environment['temperature'])} temp, {len(environment['power'])} PSUs, {len(environment['fans'])} fans")
                            
                    except Exception as cli_env_err:
                        logger.debug(f"  CLI environment parsing failed: {cli_env_err}")
                
                if not env_data_found:
                    logger.warning("  ⚠ No environment sensor data available")
                else:
                    logger.info(f"  ✓ Environment collected successfully")

            except Exception as env_err:
                logger.warning(f"  ✗ Environment sensors failed: {env_err}")
            
            
                
        except Exception as e:
            logger.error(f"Environment collection failed: {e}")

        return environment

    def _debug_rpc_response(self, rpc_command, context=""):
        """
        Execute an RPC command and return the result tree with debug logging.
        
        Args:
            rpc_command: RPC command string
            context: Context description for logging
            
        Returns:
            lxml.etree._Element: Parsed XML tree
        """
        try:
            logger.debug(f"Executing RPC for {context}: {rpc_command[:100]}...")
            rpc_reply = self.device.dispatch(to_ele(rpc_command))
            result = ETREE.fromstring(rpc_reply.xml)
            logger.debug(f"RPC response for {context} received successfully")
            return result
        except Exception as e:
            logger.error(f"RPC execution failed for {context}: {e}")
            raise   
    
    def get_alarms(self):
        """
        Retrieve DETAILED alarms from IOS-XR with full information.
        Returns comprehensive alarm data including all fields from 'show alarms detail'
        """
        alarms = []
        
        # Multiple namespace attempts for different XR versions
        NS_VARIANTS = [
            {"alm": "http://cisco.com/ns/yang/Cisco-IOS-XR-alarmgr-server-oper"},
            {"alm": "http://cisco.com/ns/yang/Cisco-IOS-XR-alarmgr-oper"},
        ]

        # Try multiple filter patterns for different XR versions
        filters = [
            # Pattern 1: Detail system location
            """
            <alarms xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-alarmgr-server-oper">
                <detail>
                    <detail-system>
                        <active/>
                        <history/>
                        <stats/>
                        <suppressed/>
                    </detail-system>
                </detail>
            </alarms>
            """,
            # Pattern 2: Detail card locations
            """
            <alarms xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-alarmgr-server-oper">
                <detail>
                    <detail-card>
                        <detail-locations>
                            <detail-location/>
                        </detail-locations>
                    </detail-card>
                </detail>
            </alarms>
            """,
            # Pattern 3: Brief system (fallback)
            """
            <alarms xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-alarmgr-server-oper">
                <brief>
                    <brief-system>
                        <active/>
                    </brief-system>
                </brief>
            </alarms>
            """,
        ]

        logger.info("=" * 80)
        logger.info("Starting DETAILED alarm collection via NETCONF")
        logger.info("=" * 80)

        # Try each filter pattern with each namespace
        for filter_idx, rpc_filter in enumerate(filters, 1):
            try:
                logger.info(f"Attempting filter pattern {filter_idx}...")
                rpc_reply = self.device.get(filter=("subtree", rpc_filter)).xml
                tree = ETREE.fromstring(rpc_reply)
                
                # Try each namespace variant
                for ns_idx, NS in enumerate(NS_VARIANTS, 1):
                    logger.debug(f"  Trying namespace variant {ns_idx}")
                    
                    # XPath patterns to try for detailed alarms
                    xpath_patterns = [
                        ".//alm:detail/alm:detail-system/alm:active/alm:alarm-info",
                        ".//alm:detail/alm:detail-card/alm:detail-locations/alm:detail-location/alm:active/alm:alarm-info",
                        ".//alm:alarm-info",
                        ".//alm:active/alm:alarm-info",
                    ]
                    
                    for xpath in xpath_patterns:
                        try:
                            alarm_nodes = tree.xpath(xpath, namespaces=NS)
                            if alarm_nodes:
                                logger.info(f" Found {len(alarm_nodes)} alarms using XPath: {xpath[:50]}...")
                                
                                for alarm in alarm_nodes:
                                    alarm_data = {
                                        # Core fields
                                        "aid": self._find_txt(alarm, "./alm:aid", "", NS),
                                        "description": self._find_txt(alarm, "./alm:description", "", NS),
                                        "severity": self._find_txt(alarm, "./alm:severity", "", NS),
                                        "location": self._find_txt(alarm, "./alm:location", "", NS),
                                        
                                        # Extended fields from 'show alarms detail'
                                        "tag_string": self._find_txt(alarm, "./alm:tag", "", NS),
                                        "module_name": self._find_txt(alarm, "./alm:module_name", "", NS),
                                        "eid": self._find_txt(alarm, "./alm:eid", "", NS),
                                        "reporting_agent_id": self._find_txt(alarm, "./alm:reporting_agent_id", "", NS),
                                        "pending_sync": self._find_txt(alarm, "./alm:pending_sync", "", NS),
                                        "status": self._find_txt(alarm, "./alm:status", "", NS),
                                        "group": self._find_txt(alarm, "./alm:group", "", NS),
                                        "set_time": self._find_txt(alarm, "./alm:set_time", "", NS),
                                        "clear_time": self._find_txt(alarm, "./alm:clear_time", "", NS),
                                        "service_affecting": self._find_txt(alarm, "./alm:service_affecting", "", NS),
                                        "type": self._find_txt(alarm, "./alm:type", "", NS),
                                        "interface": self._find_txt(alarm, "./alm:interface", "", NS),
                                        "alarm_name": self._find_txt(alarm, "./alm:alarm_name", "", NS),
                                        
                                        # Timestamp
                                        "timestamp": self._find_txt(alarm, "./alm:set_timestamp", "", NS),
                                        
                                        # Category
                                        "category": self._find_txt(alarm, "./alm:category", "", NS),
                                        
                                        # Condition description
                                        "condition_description": self._find_txt(alarm, "./alm:condition_description", "", NS),
                                    }
                                    
                                    # Clean up empty fields
                                    alarm_data = {k: v for k, v in alarm_data.items() if v}
                                    
                                    if alarm_data.get('aid') or alarm_data.get('description'):
                                        alarms.append(alarm_data)
                                        logger.debug(f"  Added alarm: {alarm_data.get('description', 'N/A')[:60]}")
                                
                                if alarms:
                                    logger.info(f" Successfully collected {len(alarms)} detailed alarms")
                                    return alarms
                        except Exception as xpath_err:
                            logger.debug(f"  XPath {xpath[:30]}... failed: {xpath_err}")
                            continue                
            except Exception as filter_err:
                logger.debug(f"Filter {filter_idx} failed: {filter_err}")
                continue

        # If NETCONF failed, try CLI fallback
        if not alarms:
            logger.warning("NETCONF alarm retrieval returned no results - attempting CLI fallback")
            alarms = self._get_alarms_via_cli_detailed()
        
        if not alarms:
            logger.info("No active alarms found on device (device is healthy)")
        else:
            logger.info(f"=" * 80)
            logger.info(f"TOTAL ALARMS COLLECTED: {len(alarms)}")
            logger.info(f"=" * 80)
        
        return alarms
    
    
    def _get_alarms_via_cli_detailed(self):
        """
        Enhanced CLI fallback - parses 'show alarms detail' output
        Returns detailed alarm information matching NETCONF format
        """
        alarms = []
        
        cli_commands = [
            "show alarms detail",  # Try detailed first
            "show alarms brief"    # Fallback to brief
        ]
        
        for cmd in cli_commands:
            try:
                logger.info(f"Attempting CLI command: {cmd}")
                
                # Use NETCONF CLI execution
                cli_rpc = f"""
                <action xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-action">
                    <cli-exec-action-xr>
                        <cmd>{cmd}</cmd>
                    </cli-exec-action-xr>
                </action>
                """
                
                rpc_reply = self.device.dispatch(to_ele(cli_rpc)).xml
                result_tree = ETREE.fromstring(rpc_reply)
                
                # Extract output text
                output = None
                for elem in result_tree.iter():
                    if elem.text and ('Active Alarms' in str(elem.text) or 'Description:' in str(elem.text)):
                        output = elem.text
                        break
                
                if not output:
                    logger.debug(f"No output from {cmd}")
                    continue
                
                logger.info(f"Got output from {cmd}, parsing...")
                
                # Parse detailed alarm output
                if 'show alarms detail' in cmd:
                    alarms = self._parse_detailed_alarm_output(output)
                else:
                    alarms = self._parse_brief_alarm_output(output)
                
                if alarms:
                    logger.info(f" Parsed {len(alarms)} alarms from CLI")
                    return alarms
                    
            except Exception as e:
                logger.error(f"CLI command '{cmd}' failed: {e}")
                continue
        
        return alarms
        
    def _parse_detailed_alarm_output(self, output):
        """
        Parse 'show alarms detail' CLI output into structured alarm data
        """
        alarms = []
        lines = output.split('\n')
        
        current_alarm = {}
        in_alarm_block = False
        
        for line in lines:
            line_stripped = line.strip()
            
            # Detect alarm block start
            if line_stripped.startswith('Description:'):
                # Save previous alarm if exists
                if current_alarm and current_alarm.get('description'):
                    alarms.append(current_alarm)
                
                # Start new alarm
                current_alarm = {}
                in_alarm_block = True
                current_alarm['description'] = line_stripped.split(':', 1)[1].strip() if ':' in line_stripped else ''
                continue
            
            # Detect alarm block separator (end of block)
            if '---' in line_stripped and len(line_stripped) > 20:
                if current_alarm and current_alarm.get('description'):
                    alarms.append(current_alarm)
                    current_alarm = {}
                in_alarm_block = False
                continue
            
            # Parse fields within alarm block
            if in_alarm_block and ':' in line_stripped:
                field, value = line_stripped.split(':', 1)
                field = field.strip()
                value = value.strip()
                
                # Map CLI fields to our data structure
                field_mapping = {
                    'Location': 'location',
                    'AID': 'aid',
                    'Tag String': 'tag_string',
                    'Module Name': 'module_name',
                    'EID': 'eid',
                    'Reporting Agent ID': 'reporting_agent_id',
                    'Pending Sync': 'pending_sync',
                    'Severity': 'severity',
                    'Status': 'status',
                    'Group': 'group',
                    'Set Time': 'set_time',
                    'Clear Time': 'clear_time',
                    'Service Affecting': 'service_affecting',
                    'Interface': 'interface',
                    'Alarm Name': 'alarm_name',
                }
                
                if field in field_mapping:
                    current_alarm[field_mapping[field]] = value
                    current_alarm['type'] = 'cli_detail'
        
        # Add last alarm
        if current_alarm and current_alarm.get('description'):
            alarms.append(current_alarm)
        
        logger.info(f"Parsed {len(alarms)} detailed alarms from CLI output")
        return alarms
        
    def _parse_brief_alarm_output(self, output):
        """
        Parse 'show alarms brief' CLI output (simpler format)
        """
        alarms = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith(("Location", "----", "Severity")):
                continue
            
            # Example: "0/RP0/CPU0  major  comm  Link Down on TenGigE0/0/0/1"
            parts = line.split(None, 3)
            if len(parts) >= 4:
                alarms.append({
                    "location": parts[0],
                    "severity": parts[1],
                    "group": parts[2],
                    "description": parts[3],
                    "type": "cli_brief",
                })
        
        return alarms


    def get_lldp_neighbors(self):
        """Return LLDP neighbors details."""
        # init result dict
        lldp_neighbors = {}

        rpc_reply = self.device.get(filter=("subtree", C.LLDP_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        lldp_xpath = ".//lldp:lldp/lldp:nodes/lldp:node/lldp:neighbors\
                        /lldp:details/lldp:detail"
        for neighbor in result_tree.xpath(
            lldp_xpath + "/lldp:lldp-neighbor", namespaces=C.NS
        ):
            interface_name = self._find_txt(
                neighbor, "./lldp:receiving-interface-name", default="", namespaces=C.NS
            )
            system_name = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    neighbor,
                    "./lldp:detail/lldp:system-name",
                    default="",
                    namespaces=C.NS,
                ),
            )
            port_id = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    neighbor, "./lldp:port-id-detail", default="", namespaces=C.NS
                ),
            )
            if interface_name not in lldp_neighbors.keys():
                lldp_neighbors[interface_name] = []
            lldp_neighbors[interface_name].append(
                {"hostname": system_name, "port": port_id}
            )

        return lldp_neighbors

    def get_lldp_neighbors_detail(self, interface=""):
        """Detailed view of the LLDP neighbors."""
        lldp_neighbors_detail = {}

        rpc_reply = self.device.get(filter=("subtree", C.LLDP_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        lldp_neighbor_xpath = ".//lldp:lldp/lldp:nodes/lldp:node/lldp:neighbors\
                /lldp:details/lldp:detail/lldp:lldp-neighbor"
        for neighbor in result_tree.xpath(lldp_neighbor_xpath, namespaces=C.NS):
            interface_name = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    neighbor,
                    "./lldp:receiving-interface-name",
                    default="",
                    namespaces=C.NS,
                ),
            )
            parent_interface = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    neighbor,
                    "./lldp:receiving-parent-interface-name",
                    default="None",
                    namespaces=C.NS,
                ),
            )
            chassis_id_raw = self._find_txt(
                neighbor, "./lldp:chassis-id", default="", namespaces=C.NS
            )
            chassis_id = napalm.base.helpers.convert(
                napalm.base.helpers.mac, chassis_id_raw, chassis_id_raw
            )
            port_id = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    neighbor, "./lldp:port-id-detail", default="", namespaces=C.NS
                ),
            )
            port_descr = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    neighbor,
                    "./lldp:detail/lldp:port-description",
                    default="",
                    namespaces=C.NS,
                ),
            )
            system_name = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    neighbor,
                    "./lldp:detail/lldp:system-name",
                    default="",
                    namespaces=C.NS,
                ),
            )
            system_descr = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    neighbor,
                    "./lldp:detail/lldp:system-description",
                    default="",
                    namespaces=C.NS,
                ),
            )
            system_capabilities = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    neighbor,
                    "./lldp:detail/lldp:system-capabilities",
                    default="",
                    namespaces=C.NS,
                ),
            )
            enabled_capabilities = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    neighbor,
                    "./lldp:detail/lldp:enabled-capabilities",
                    default="",
                    namespaces=C.NS,
                ),
            )

            if interface_name not in lldp_neighbors_detail.keys():
                lldp_neighbors_detail[interface_name] = []
            lldp_neighbors_detail[interface_name].append(
                {
                    "parent_interface": parent_interface,
                    "remote_chassis_id": chassis_id,
                    "remote_port": port_id,
                    "remote_port_description": port_descr,
                    "remote_system_name": system_name,
                    "remote_system_description": system_descr,
                    "remote_system_capab": napalm.base.helpers.transform_lldp_capab(
                        system_capabilities
                    ),
                    "remote_system_enable_capab": napalm.base.helpers.transform_lldp_capab(
                        enabled_capabilities
                    ),
                }
            )

        return lldp_neighbors_detail

    def cli(self, commands, encoding="text"):
        """Execute raw CLI commands and returns their output."""
        return NotImplementedError

    def get_bgp_config(self, group="", neighbor=""):
        """Return BGP configuration."""
        bgp_config = {}

        # a helper
        def build_prefix_limit(af_table, limit, prefix_percent, prefix_timeout):
            prefix_limit = {}
            inet = False
            inet6 = False
            preifx_type = "inet"
            if "ipv4" in af_table.lower():
                inet = True
            if "ipv6" in af_table.lower():
                inet6 = True
                preifx_type = "inet6"
            if inet or inet6:
                prefix_limit = {
                    preifx_type: {
                        af_table[5:].lower(): {
                            "limit": limit,
                            "teardown": {
                                "threshold": prefix_percent,
                                "timeout": prefix_timeout,
                            },
                        }
                    }
                }
            return prefix_limit

        # here begins actual method...
        rpc_reply = self.device.get_config(
            source="running", filter=("subtree", C.BGP_CFG_RPC_REQ_FILTER)
        ).xml

        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        data_ele = result_tree.find("./{*}data")
        # If there are no children in "<data>", then there is no BGP configured
        bgp_configured = bool(len(data_ele.getchildren()))
        if not bgp_configured:
            return {}

        if not group:
            neighbor = ""

        bgp_asn = napalm.base.helpers.convert(
            int,
            self._find_txt(
                result_tree,
                ".//bgpc:bgp/bgpc:instance/bgpc:instance-as/bgpc:four-byte-as/bgpc:as",
                default=0,
                namespaces=C.NS,
            ),
        )

        bgp_group_neighbors = {}
        bgp_neighbor_xpath = ".//bgpc:bgp/bgpc:instance/bgpc:instance-as/\
             bgpc:four-byte-as/bgpc:default-vrf/bgpc:bgp-entity/bgpc:neighbors/bgpc:neighbor"
        for bgp_neighbor in result_tree.xpath(bgp_neighbor_xpath, namespaces=C.NS):
            group_name = self._find_txt(
                bgp_neighbor,
                "./bgpc:neighbor-group-add-member",
                default="",
                namespaces=C.NS,
            )
            peer = napalm.base.helpers.ip(
                self._find_txt(
                    bgp_neighbor, "./bgpc:neighbor-address", default="", namespaces=C.NS
                )
            )
            if neighbor and peer != neighbor:
                continue
            description = self._find_txt(
                bgp_neighbor, "./bgpc:description", default="", namespaces=C.NS
            )
            peer_as_x = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_neighbor,
                    "./bgpc:remote-as/bgpc:as-xx",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            peer_as_y = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_neighbor,
                    "./bgpc:remote-as/bgpc:as-yy",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            peer_as = peer_as_x * 65536 + peer_as_y
            local_as_x = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_neighbor,
                    "./bgpc:local-as/bgpc:as-xx",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            local_as_y = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_neighbor,
                    "./bgpc:local-as/bgpc:as-yy",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            local_as = (local_as_x * 65536 + local_as_y) or bgp_asn
            af_table = self._find_txt(
                bgp_neighbor,
                "./bgpc:neighbor-afs/bgpc:neighbor-af/bgpc:af-name",
                default="",
                namespaces=C.NS,
            )
            prefix_limit = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_neighbor,
                    "./bgpc:neighbor-afs/bgpc:neighbor-af/\
                    bgpc:maximum-prefixes/bgpc:prefix-limit",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            prefix_percent = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_neighbor,
                    "./bgpc:neighbor-afs/bgpc:neighbor-af/\
                    bgpc:maximum-prefixes/bgpc:warning-percentage",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            prefix_timeout = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_neighbor,
                    "./bgpc:neighbor-afs/bgpc:neighbor-af/\
                    bgpc:maximum-prefixes/bgpc:restart-time",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            import_policy = self._find_txt(
                bgp_neighbor,
                "./bgpc:neighbor-afs/bgpc:neighbor-af/bgpc:route-policy-in",
                default="",
                namespaces=C.NS,
            )
            export_policy = self._find_txt(
                bgp_neighbor,
                "./bgpc:neighbor-afs/bgpc:neighbor-af/bgpc:route-policy-out",
                default="",
                namespaces=C.NS,
            )
            local_addr_raw = self._find_txt(
                bgp_neighbor,
                "./bgpc:local-address/bgpc:local-ip-address",
                default="",
                namespaces=C.NS,
            )
            local_address = napalm.base.helpers.convert(
                napalm.base.helpers.ip, local_addr_raw, local_addr_raw
            )
            password = self._find_txt(
                bgp_neighbor,
                "./bgpc:password/bgpc:password",
                default="",
                namespaces=C.NS,
            )
            nhs = False
            route_reflector = False
            if group_name not in bgp_group_neighbors.keys():
                bgp_group_neighbors[group_name] = {}
            bgp_group_neighbors[group_name][peer] = {
                "description": description,
                "remote_as": peer_as,
                "prefix_limit": build_prefix_limit(
                    af_table, prefix_limit, prefix_percent, prefix_timeout
                ),
                "export_policy": export_policy,
                "import_policy": import_policy,
                "local_address": local_address,
                "local_as": local_as,
                "authentication_key": password,
                "nhs": nhs,
                "route_reflector_client": route_reflector,
            }
            if neighbor and peer == neighbor:
                break

        bgp_neighbor_group_xpath = ".//bgpc:bgp/bgpc:instance/bgpc:instance-as/\
             bgpc:four-byte-as/bgpc:default-vrf/bgpc:bgp-entity/\
             bgpc:neighbor-groups/bgpc:neighbor-group"
        for bgp_group in result_tree.xpath(bgp_neighbor_group_xpath, namespaces=C.NS):
            group_name = self._find_txt(
                bgp_group, "./bgpc:neighbor-group-name", default="", namespaces=C.NS
            )
            if group and group != group_name:
                continue
            bgp_type = "external"  # by default external
            # must check
            description = self._find_txt(
                bgp_group, "./bgpc:description", default="", namespaces=C.NS
            )
            import_policy = self._find_txt(
                bgp_group,
                "./bgpc:neighbor-group-afs/\
                bgpc:neighbor-group-af/bgpc:route-policy-in",
                default="",
                namespaces=C.NS,
            )
            export_policy = self._find_txt(
                bgp_group,
                "./bgpc:neighbor-group-afs/\
                bgpc:neighbor-group-af/bgpc:route-policy-out",
                default="",
                namespaces=C.NS,
            )
            multipath = (
                self._find_txt(
                    bgp_group,
                    "./bgpc:neighbor-group-afs/\
                    bgpc:neighbor-group-af/bgpc:multipath",
                    default="",
                    namespaces=C.NS,
                )
                == "true"
            )
            peer_as_x = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_group,
                    "./bgpc:remote-as/bgpc:as-xx",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            peer_as_y = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_group,
                    "./bgpc:remote-as/bgpc:as-yy",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            peer_as = peer_as_x * 65536 + peer_as_y
            local_as_x = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_group,
                    "./bgpc:local-as/bgpc:as-xx",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            local_as_y = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_group,
                    "./bgpc:local-as/bgpc:as-yy",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            local_as = (local_as_x * 65536 + local_as_y) or bgp_asn
            multihop_ttl = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_group,
                    "./bgpc:ebgp-multihop/bgpc:max-hop-count",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            local_addr_raw = self._find_txt(
                bgp_group,
                "./bgpc:local-address/bgpc:local-ip-address",
                default="",
                namespaces=C.NS,
            )
            local_address = napalm.base.helpers.convert(
                napalm.base.helpers.ip, local_addr_raw, local_addr_raw
            )
            af_table = self._find_txt(
                bgp_group,
                "./bgpc:neighbor-afs/bgpc:neighbor-af/bgpc:af-name",
                default="",
                namespaces=C.NS,
            )
            prefix_limit = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_group,
                    "./bgpc:neighbor-group-afs/\
                    bgpc:neighbor-group-af/bgpc:maximum-prefixes/\
                    bgpc:prefix-limit",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            prefix_percent = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_group,
                    "./bgpc:neighbor-group-afs/\
                    bgpc:neighbor-group-af/bgpc:maximum-prefixes/\
                    bgpc:warning-percentage",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            prefix_timeout = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    bgp_group,
                    "./bgpc:neighbor-group-afs/\
                    bgpc:neighbor-group-af/bgpc:maximum-prefixes/\
                    bgpc:restart-time",
                    default="",
                    namespaces=C.NS,
                ),
                0,
            )
            remove_private = True  # is it specified in the XML?
            bgp_config[group_name] = {
                "apply_groups": [],  # on IOS-XR will always be empty list!
                "description": description,
                "local_as": local_as,
                "type": str(bgp_type),
                "import_policy": import_policy,
                "export_policy": export_policy,
                "local_address": local_address,
                "multipath": multipath,
                "multihop_ttl": multihop_ttl,
                "remote_as": peer_as,
                "remove_private_as": remove_private,
                "prefix_limit": build_prefix_limit(
                    af_table, prefix_limit, prefix_percent, prefix_timeout
                ),
                "neighbors": bgp_group_neighbors.get(group_name, {}),
            }
            if group and group == group_name:
                break

        bgp_config["_"] = {
            "apply_groups": [],
            "description": "",
            "local_as": bgp_asn,
            "type": "",
            "import_policy": "",
            "export_policy": "",
            "local_address": "",
            "multipath": False,
            "multihop_ttl": 0,
            "remote_as": 0,
            "remove_private_as": False,
            "prefix_limit": {},
            "neighbors": bgp_group_neighbors.get("", {}),
        }

        return bgp_config

    def get_bgp_neighbors_detail(self, neighbor_address=""):
        """Detailed view of the BGP neighbors operational data."""

        def get_vrf_neighbors_detail(
            rpc_reply_etree, xpath, vrf_name, vrf_keepalive, vrf_holdtime
        ):
            """Detailed view of the BGP neighbors operational data for a given VRF."""
            bgp_vrf_neighbors_detail = {}
            bgp_vrf_neighbors_detail[vrf_name] = {}
            for neighbor in rpc_reply_etree.xpath(xpath, namespaces=C.NS):
                up = (
                    self._find_txt(
                        neighbor, "./bgp:connection-state", default="", namespaces=C.NS
                    )
                    == "bgp-st-estab"
                )
                local_as = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor, "./bgp:local-as", default="", namespaces=C.NS
                    ),
                    0,
                )
                remote_as = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor, "./bgp:remote-as", default="", namespaces=C.NS
                    ),
                    0,
                )
                router_id = napalm.base.helpers.ip(
                    self._find_txt(
                        neighbor, "./bgp:router-id", default="", namespaces=C.NS
                    )
                )
                remote_address = napalm.base.helpers.ip(
                    self._find_txt(
                        neighbor, "./bgp:neighbor-address", default="", namespaces=C.NS
                    )
                )
                local_address_configured = (
                    self._find_txt(
                        neighbor,
                        "./bgp:is-local-address-configured",
                        default="",
                        namespaces=C.NS,
                    )
                    == "true"
                )
                local_address = napalm.base.helpers.ip(
                    self._find_txt(
                        neighbor,
                        "./bgp:connection-local-address/\
                        bgp:ipv4-address",
                        default="",
                        namespaces=C.NS,
                    )
                    or self._find_txt(
                        neighbor,
                        "./bgp:connection-local-address/\
                     bgp:ipv6-address",
                        default="",
                        namespaces=C.NS,
                    )
                )
                local_port = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor,
                        "./bgp:connection-local-port",
                        default="",
                        namespaces=C.NS,
                    ),
                )
                remote_address = napalm.base.helpers.ip(
                    self._find_txt(
                        neighbor,
                        "./bgp:connection-remote-address/\
                        bgp:ipv4-address",
                        default="",
                        namespaces=C.NS,
                    )
                    or self._find_txt(
                        neighbor,
                        "./bgp:connection-remote-address/\
                        bgp:ipv6-address",
                        default="",
                        namespaces=C.NS,
                    )
                )
                remote_port = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor,
                        "./bgp:connection-remote-port",
                        default="",
                        namespaces=C.NS,
                    ),
                )
                multihop = (
                    self._find_txt(
                        neighbor,
                        "\
                    ./bgp:is-external-neighbor-not-directly-connected",
                        default="",
                        namespaces=C.NS,
                    )
                    == "true"
                )
                remove_private_as = (
                    self._find_txt(
                        neighbor,
                        "./bgp:af-data/\
                    bgp:remove-private-as-from-updates",
                        default="",
                        namespaces=C.NS,
                    )
                    == "true"
                )
                multipath = (
                    self._find_txt(
                        neighbor,
                        "./bgp:af-data/\
                     bgp:selective-multipath-eligible",
                        default="",
                        namespaces=C.NS,
                    )
                    == "true"
                )
                import_policy = self._find_txt(
                    neighbor,
                    "./bgp:af-data/bgp:route-policy-in",
                    default="",
                    namespaces=C.NS,
                )
                export_policy = self._find_txt(
                    neighbor,
                    "./bgp:af-data/bgp:route-policy-out",
                    default="",
                    namespaces=C.NS,
                )
                input_messages = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor, "./bgp:messges-received", default="", namespaces=C.NS
                    ),
                    0,
                )
                output_messages = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor, "./bgp:messages-sent", default="", namespaces=C.NS
                    ),
                    0,
                )
                flap_count = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor,
                        "./bgp:connection-down-count",
                        default="",
                        namespaces=C.NS,
                    ),
                    0,
                )
                messages_queued_out = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor,
                        "./bgp:messages-queued-out",
                        default="",
                        namespaces=C.NS,
                    ),
                    0,
                )
                connection_state = (
                    self._find_txt(
                        neighbor, "./bgp:connection-state", default="", namespaces=C.NS
                    )
                    .replace("bgp-st-", "")
                    .title()
                )
                if connection_state == "Estab":
                    connection_state = "Established"
                previous_connection_state = napalm.base.helpers.convert(
                    str,
                    _BGP_STATE_.get(
                        self._find_txt(
                            neighbor,
                            "./bgp:previous-connection-state",
                            "0",
                            namespaces=C.NS,
                        )
                    ),
                )
                active_prefix_count = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor,
                        "./bgp:af-data/bgp:number-of-bestpaths",
                        default="",
                        namespaces=C.NS,
                    ),
                    0,
                )
                accepted_prefix_count = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor,
                        "./bgp:af-data/bgp:prefixes-accepted",
                        default="",
                        namespaces=C.NS,
                    ),
                    0,
                )
                suppressed_prefix_count = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor,
                        "./bgp:af-data/bgp:prefixes-denied",
                        default="",
                        namespaces=C.NS,
                    ),
                    0,
                )
                received_prefix_count = accepted_prefix_count + suppressed_prefix_count
                advertised_prefix_count = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor,
                        "./bgp:af-data/\
                        bgp:prefixes-advertised",
                        default="",
                        namespaces=C.NS,
                    ),
                    0,
                )
                suppress_4byte_as = (
                    self._find_txt(
                        neighbor, "./bgp:suppress4-byte-as", default="", namespaces=C.NS
                    )
                    == "true"
                )
                local_as_prepend = (
                    self._find_txt(
                        neighbor,
                        "./bgp:local-as-no-prepend",
                        default="",
                        namespaces=C.NS,
                    )
                    != "true"
                )
                holdtime = (
                    napalm.base.helpers.convert(
                        int,
                        self._find_txt(
                            neighbor, "./bgp:hold-time", default="", namespaces=C.NS
                        ),
                        0,
                    )
                    or vrf_holdtime
                )
                configured_holdtime = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor,
                        "./bgp:configured-hold-time",
                        default="",
                        namespaces=C.NS,
                    ),
                    0,
                )
                keepalive = (
                    napalm.base.helpers.convert(
                        int,
                        self._find_txt(
                            neighbor,
                            "./bgp:keep-alive-time",
                            default="",
                            namespaces=C.NS,
                        ),
                        0,
                    )
                    or vrf_keepalive
                )
                configured_keepalive = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        neighbor,
                        "./bgp:configured-keepalive",
                        default="",
                        namespaces=C.NS,
                    ),
                    0,
                )
                if remote_as not in bgp_vrf_neighbors_detail[vrf_name].keys():
                    bgp_vrf_neighbors_detail[vrf_name][remote_as] = []
                bgp_vrf_neighbors_detail[vrf_name][remote_as].append(
                    {
                        "up": up,
                        "local_as": local_as,
                        "remote_as": remote_as,
                        "router_id": router_id,
                        "local_address": local_address,
                        "routing_table": vrf_name,
                        "local_address_configured": local_address_configured,
                        "local_port": local_port,
                        "remote_address": remote_address,
                        "remote_port": remote_port,
                        "multihop": multihop,
                        "multipath": multipath,
                        "import_policy": import_policy,
                        "export_policy": export_policy,
                        "input_messages": input_messages,
                        "output_messages": output_messages,
                        "input_updates": 0,
                        "output_updates": 0,
                        "messages_queued_out": messages_queued_out,
                        "connection_state": connection_state,
                        "previous_connection_state": previous_connection_state,
                        "last_event": "",
                        "remove_private_as": remove_private_as,
                        "suppress_4byte_as": suppress_4byte_as,
                        "local_as_prepend": local_as_prepend,
                        "holdtime": holdtime,
                        "configured_holdtime": configured_holdtime,
                        "keepalive": keepalive,
                        "configured_keepalive": configured_keepalive,
                        "active_prefix_count": active_prefix_count,
                        "received_prefix_count": received_prefix_count,
                        "accepted_prefix_count": accepted_prefix_count,
                        "suppressed_prefix_count": suppressed_prefix_count,
                        "advertised_prefix_count": advertised_prefix_count,
                        "flap_count": flap_count,
                    }
                )
            return bgp_vrf_neighbors_detail

        rpc_reply = self.device.get(filter=("subtree", C.BGP_NEIGHBOR_REQ_FILTER)).xml
        # Converts string to tree
        rpc_reply_etree = ETREE.fromstring(rpc_reply)
        _BGP_STATE_ = {
            "0": "Unknown",
            "1": "Idle",
            "2": "Connect",
            "3": "OpenSent",
            "4": "OpenConfirm",
            "5": "Active",
            "6": "Established",
        }
        bgp_neighbors_detail = {}

        # get neighbors from default(global) VRF
        default_vrf_xpath = """.//bgp:bgp/bgp:instances/bgp:instance/
          bgp:instance-active/bgp:default-vrf"""
        vrf_name = "default"
        default_vrf_keepalive = napalm.base.helpers.convert(
            int,
            self._find_txt(
                rpc_reply_etree,
                default_vrf_xpath
                + "/bgp:global-process-info/bgp:vrf/\
                bgp:keep-alive-time",
                default="",
                namespaces=C.NS,
            ),
        )
        default_vrf_holdtime = napalm.base.helpers.convert(
            int,
            self._find_txt(
                rpc_reply_etree,
                default_vrf_xpath
                + "/bgp:global-process-info/bgp:vrf/\
                bgp:hold-time",
                default="",
                namespaces=C.NS,
            ),
        )
        bgp_neighbors_detail["global"] = get_vrf_neighbors_detail(
            rpc_reply_etree,
            default_vrf_xpath + "/bgp:neighbors/bgp:neighbor",
            vrf_name,
            default_vrf_keepalive,
            default_vrf_holdtime,
        )[vrf_name]

        # get neighbors from other VRFs
        vrf_xpath = """.//bgp:bgp/bgp:instances/
                    bgp:instance/bgp:instance-active/bgp:vrfs"""
        for vrf in rpc_reply_etree.xpath(vrf_xpath + "/bgp:vrf", namespaces=C.NS):
            vrf_name = self._find_txt(
                vrf, "./bgp:vrf-name", default="", namespaces=C.NS
            )
            vrf_keepalive = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    vrf,
                    "./bgp:global-process-info/bgp:vrf/\
                    bgp:keep-alive-time",
                    default="",
                    namespaces=C.NS,
                ),
            )
            vrf_holdtime = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    vrf,
                    "./bgp:global-process-info/bgp:vrf/\
                    bgp:hold-time",
                    default="",
                    namespaces=C.NS,
                ),
            )
            bgp_neighbors_detail.update(
                get_vrf_neighbors_detail(
                    rpc_reply_etree,
                    vrf_xpath
                    + "/bgp:vrf[bgp:vrf-name='"
                    + vrf_name
                    + "']\
                    /bgp:neighbors/bgp:neighbor",
                    vrf_name,
                    vrf_keepalive,
                    vrf_holdtime,
                )
            )

        return bgp_neighbors_detail

    def get_arp_table(self, vrf=""):
        """Return the ARP table."""
        if vrf:
            msg = "VRF support has not been added for \
                this getter on this platform."
            raise NotImplementedError(msg)

        arp_table = []

        rpc_reply = self.device.get(filter=("subtree", C.ARP_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)
        arp_entry_xpath = ".//arp:arp/arp:nodes/arp:node/arp:entries/arp:entry"
        for arp_entry in result_tree.xpath(arp_entry_xpath, namespaces=C.NS):
            interface = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    arp_entry, "./arp:interface-name", default="", namespaces=C.NS
                ),
            )
            ip = napalm.base.helpers.convert(
                str,
                self._find_txt(arp_entry, "./arp:address", default="", namespaces=C.NS),
            )
            age = napalm.base.helpers.convert(
                float,
                self._find_txt(arp_entry, "./arp:age", default="0.0", namespaces=C.NS),
            )
            mac_raw = self._find_txt(
                arp_entry, "./arp:hardware-address", default="", namespaces=C.NS
            )

            arp_table.append(
                {
                    "interface": interface,
                    "mac": napalm.base.helpers.mac(mac_raw),
                    "ip": napalm.base.helpers.ip(ip),
                    "age": age,
                }
            )

        return arp_table

    def get_ntp_peers(self):
        """Return the NTP peers configured on the device - FIXED."""
        ntp_peers = {}
        
        try:
            config_reply = self.device.get_config(source="running")
            tree = config_reply.data_ele
            
            # Try multiple XPath patterns for NTP peers
            peer_paths = [
                './/system/ntp/peer',
                './/ntp/peer'
            ]
            
            for xpath in peer_paths:
                peers = tree.xpath(xpath)
                if peers:
                    for peer in peers:
                        # The 'name' element contains the peer address/hostname
                        peer_name_elem = peer.find('./name')
                        if peer_name_elem is not None and peer_name_elem.text:
                            peer_addr = peer_name_elem.text.strip()
                            ntp_peers[peer_addr] = {}
                            logger.debug(f"Found NTP peer: {peer_addr}")
                    
                    if ntp_peers:
                        break
            
            logger.info(f"Found {len(ntp_peers)} NTP peers")
                            
        except Exception as e:
            logger.error(f"Failed to get NTP peers: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return ntp_peers


    def get_ntp_servers(self):
        """Return the NTP servers configured on the device - FIXED."""
        ntp_servers = {}
        
        try:
            config_reply = self.device.get_config(source="running")
            tree = config_reply.data_ele
            
            # Try multiple XPath patterns for NTP servers
            server_paths = [
                './/system/ntp/server',
                './/ntp/server'
            ]
            
            for xpath in server_paths:
                servers = tree.xpath(xpath)
                if servers:
                    for server in servers:
                        server_name_elem = server.find('./name')
                        if server_name_elem is not None and server_name_elem.text:
                            server_addr = server_name_elem.text.strip()
                            ntp_servers[server_addr] = {}
                            logger.debug(f"Found NTP server: {server_addr}")
                    
                    if ntp_servers:
                        break
            
            logger.info(f"Found {len(ntp_servers)} NTP servers")
                            
        except Exception as e:
            logger.error(f"Failed to get NTP servers: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return ntp_servers

    def get_ntp_stats(self):
        """Return NTP stats (associations)."""
        ntp_stats = []

        rpc_reply = self.device.get(filter=("subtree", C.NTP_STAT_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        xpath = ".//ntp:ntp/ntp:nodes/ntp:node/ntp:associations/\
                ntp:peer-summary-info/ntp:peer-info-common"
        for node in result_tree.xpath(xpath, namespaces=C.NS):
            synchronized = (
                self._find_txt(node, "./ntp:is-sys-peer", default="", namespaces=C.NS)
                == "true"
            )
            address = self._find_txt(node, "./ntp:address", default="", namespaces=C.NS)
            if address == "DLRSC node":
                continue
            referenceid = self._find_txt(
                node, "./ntp:reference-id", default="", namespaces=C.NS
            )
            hostpoll = napalm.base.helpers.convert(
                int, self._find_txt(node, "./ntp:host-poll", "0", namespaces=C.NS)
            )
            reachability = napalm.base.helpers.convert(
                int, self._find_txt(node, "./ntp:reachability", "0", namespaces=C.NS)
            )
            stratum = napalm.base.helpers.convert(
                int, self._find_txt(node, "./ntp:stratum", "0", namespaces=C.NS)
            )
            delay = napalm.base.helpers.convert(
                float, self._find_txt(node, "./ntp:delay", "0.0", namespaces=C.NS)
            )
            offset = napalm.base.helpers.convert(
                float, self._find_txt(node, "./ntp:offset", "0.0", namespaces=C.NS)
            )
            jitter = napalm.base.helpers.convert(
                float, self._find_txt(node, "./ntp:dispersion", "0.0", namespaces=C.NS)
            )

            ntp_stats.append(
                {
                    "remote": address,
                    "synchronized": synchronized,
                    "referenceid": referenceid,
                    "stratum": stratum,
                    "type": "",
                    "when": "",
                    "hostpoll": hostpoll,
                    "reachability": reachability,
                    "delay": delay,
                    "offset": offset,
                    "jitter": jitter,
                }
            )

        return ntp_stats
    
    
    def get_comprehensive_audit(self):
        """
        Perform comprehensive device audit - ENHANCED VERSION WITH BETTER ERROR HANDLING
        Returns dict with ALL device information including alarms and routing.
        """
        from datetime import datetime
        
        audit_results = {
            "timestamp": datetime.now().isoformat(),
            "device": self.hostname,
            "port": self.port,
            "collection_started": datetime.now().isoformat(),
        }
        
        # Define audit sections with collection methods
        audit_sections = {
            # CORE
            "facts": ("Device Facts", self.get_facts),
            
            # INTERFACES
            "interfaces": ("Interface Details", self.get_interfaces),
            "interface_counters": ("Interface Statistics", self.get_interfaces_counters),
            "interfaces_ip": ("Interface IP Addresses", self.get_interfaces_ip),
            "optics": ("Optical Transceiver Data", self.get_optics),
            
            # ROUTING
            "bgp_neighbors": ("BGP Neighbors", self.get_bgp_neighbors),
            "bgp_config": ("BGP Configuration", lambda: self.get_bgp_config()),
            "route_summary": ("Route Summary", lambda: self.get_route_summary()),
            "default_routes": ("Default Routes", lambda: self.get_route_to('0.0.0.0/0')),
            
            # HARDWARE
            "environment": ("Environment Status", self.get_environment),
            "alarms": ("Active Alarms", self.get_alarms),
            
            # LAYER 2
            "lldp_neighbors": ("LLDP Neighbors", self.get_lldp_neighbors),
            "lldp_neighbors_detail": ("LLDP Neighbors Detail", lambda: self.get_lldp_neighbors_detail()),
            "arp_table": ("ARP Table", lambda: self.get_arp_table()),
            "mac_table": ("MAC Address Table", self.get_mac_address_table),
            
            # TIME & MANAGEMENT
            "ntp_peers": ("NTP Peers", self.get_ntp_peers),
            "ntp_servers": ("NTP Servers", self.get_ntp_servers),
            "ntp_stats": ("NTP Statistics", self.get_ntp_stats),
            "users": ("User Accounts", self.get_users),
            "snmp_info": ("SNMP Information", self.get_snmp_information),
            
            # CONFIG
            "running_config": ("Running Configuration", lambda: self.get_config(retrieve='running')),
        }
        
        total_sections = len(audit_sections)
        successful_sections = 0
        failed_sections = []
        
        logger.info("=" * 80)
        logger.info(f"COMPREHENSIVE AUDIT STARTING: {self.hostname}")
        logger.info(f"Total sections: {total_sections}")
        logger.info("=" * 80)
        
        for idx, (section_name, (description, method)) in enumerate(audit_sections.items(), 1):
            try:
                logger.info(f"[{idx}/{total_sections}] Collecting {description}...")
                
                result = method()
                audit_results[section_name] = result
                
                # Log success with data size
                if isinstance(result, dict):
                    item_count = len(result)
                elif isinstance(result, list):
                    item_count = len(result)
                else:
                    item_count = 1
                
                logger.info(f"  ✓ {description}: {item_count} items collected")
                successful_sections += 1
                
            except Exception as e:
                logger.error(f"  ✗ {description} FAILED: {e}")
                audit_results[section_name] = {"error": str(e)}
                failed_sections.append(section_name)
        
        # Generate summary
        try:
            interfaces = audit_results.get("interfaces", {})
            bgp_neighbors = audit_results.get("bgp_neighbors", {})
            alarms = audit_results.get("alarms", [])
            
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
                },
                "bgp_summary": {
                    "total_vrfs": len(bgp_neighbors),
                    "total_peers": sum(len(v.get('peers', {})) for v in bgp_neighbors.values()),
                },
                "alarm_summary": {
                    "active_alarms": len(alarms) if isinstance(alarms, list) else 0,
                },
                "routing_summary": {
                    "route_summary": audit_results.get("route_summary", {}),
                    "default_routes": len(audit_results.get("default_routes", {})),
                }
            }
        except Exception as summary_err:
            logger.warning(f"Failed to generate summary: {summary_err}")
            audit_results["summary"] = {"error": str(summary_err)}
        
        audit_results["collection_completed"] = datetime.now().isoformat()
        
        # Calculate duration
        try:
            from datetime import datetime as dt
            start = dt.fromisoformat(audit_results["collection_started"])
            end = dt.fromisoformat(audit_results["collection_completed"])
            duration = (end - start).total_seconds()
            audit_results["collection_duration_seconds"] = round(duration, 2)
        except:
            pass
        
        logger.info("=" * 80)
        logger.info(f"✓ AUDIT COMPLETE: {self.hostname}")
        logger.info(f"  Success: {successful_sections}/{total_sections}")
        if failed_sections:
            logger.warning(f"  Failed: {', '.join(failed_sections)}")
        logger.info(f"  Duration: {audit_results.get('collection_duration_seconds', 'N/A')}s")
        logger.info("=" * 80)
        
        return audit_results

    def get_interfaces_ip(self):
        interfaces_ip = {}
        try:
            rpc_filter = """
            <interface-configurations xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-cfg">
            <interface-configuration>
                <active>act</active>
                <ipv4-network>
                <addresses>
                    <primary/>
                </addresses>
                </ipv4-network>
            </interface-configuration>
            </interface-configurations>
            """
            rpc_reply = self.device.get(filter=("subtree", rpc_filter)).xml
            tree = ETREE.fromstring(rpc_reply)

            # CHANGE THIS LINE - use C.NS instead of self.NS
            for intf in tree.xpath(".//if:interface-configuration", namespaces=C.NS):  # ← FIXED
                name = self._find_txt(intf, "./if:interface-name", "", C.NS)         # ← FIXED
                ipv4_addr = self._find_txt(intf, ".//if:address", "", C.NS)          # ← FIXED
                mask = self._find_txt(intf, ".//if:mask", "", C.NS)                  # ← FIXED
                if ipv4_addr:
                    interfaces_ip[name] = {
                        "ipv4": {
                            ipv4_addr: {"prefix_length": mask}
                        }
                    }
        except Exception as e:
            logging.error(f"Error retrieving interface IPs: {e}")
        return interfaces_ip
    
    def _get_interfaces_ip_via_cli(self):
        """Get interface IPs using CLI via NETCONF exec"""
        interfaces_ip = {}
        
        cli_rpc = """
        <action xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-action">
            <cli-exec-action-xr>
                <cmd>show ip interface brief</cmd>
            </cli-exec-action-xr>
        </action>
        """
        
        try:
            rpc_reply = self.device.dispatch(to_ele(cli_rpc)).xml
            result_tree = ETREE.fromstring(rpc_reply)
            
            # Extract output
            output = None
            for elem in result_tree.iter():
                if elem.text and 'Interface' in str(elem.text):
                    output = elem.text
                    break
            
            if output:
                lines = output.split('\n')
                for line in lines:
                    line = line.strip()
                    if not line or 'Interface' in line or '---' in line:
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 2:
                        iface_name = parts[0]
                        ip_addr = parts[1]
                        
                        if ip_addr != 'unassigned' and '.' in ip_addr:
                            if '/' in ip_addr:
                                ip, prefix = ip_addr.split('/')
                                prefix_len = int(prefix)
                            else:
                                ip = ip_addr
                                prefix_len = 32  # Default
                            
                            if iface_name not in interfaces_ip:
                                interfaces_ip[iface_name] = {}
                            if "ipv4" not in interfaces_ip[iface_name]:
                                interfaces_ip[iface_name]["ipv4"] = {}
                            
                            interfaces_ip[iface_name]["ipv4"][ip] = {
                                "prefix_length": prefix_len
                            }
        except Exception as e:
            logger.error(f"CLI IP parsing failed: {e}")
        
        return interfaces_ip

    def get_mac_address_table(self):
        """Return the MAC address table."""
        mac_table = []

        rpc_reply = self.device.get(filter=("subtree", C.MAC_TABLE_RPC_REQ_FILTER)).xml
        # Converts string to etree
        result_tree = ETREE.fromstring(rpc_reply)

        mac_xpath = ".//mac:l2vpn-forwarding/mac:nodes/mac:node/mac:l2fibmac-details"
        for mac_entry in result_tree.xpath(
            mac_xpath + "/mac:l2fibmac-detail", namespaces=C.NS
        ):
            mac_raw = self._find_txt(
                mac_entry, "./mac:address", default="", namespaces=C.NS
            )
            vlan = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    mac_entry, "./mac:name", default="", namespaces=C.NS
                ).replace("vlan", ""),
                0,
            )
            interface = self._find_txt(
                mac_entry,
                "./mac:segment/mac:ac/\
                            mac:interface-handle",
                default="",
                namespaces=C.NS,
            )

            mac_table.append(
                {
                    "mac": napalm.base.helpers.mac(mac_raw),
                    "interface": interface,
                    "vlan": vlan,
                    "active": True,
                    "static": False,
                    "moves": 0,
                    "last_move": 0.0,
                }
            )

        return mac_table

    def get_route_to(self, destination="", protocol="", longer=False):
        """Return route details to a specific destination."""
        routes = {}

        if not isinstance(destination, str):
            raise TypeError("Please specify a valid destination!")

        if longer:
            raise NotImplementedError("Longer prefixes not yet supported for IOS-XR")

        protocol = protocol.lower()
        if protocol == "direct":
            protocol = "connected"

        dest_split = destination.split("/")
        network = dest_split[0]
        prefix_length = 0
        if len(dest_split) == 2:
            prefix_length = dest_split[1]

        ipv = 4
        try:
            ipv = ipaddress.ip_address(network).version
        except ValueError:
            logger.error("Wrong destination IP Address format supplied to get_route_to")
            raise TypeError("Wrong destination IP Address!")

        if ipv == 6:
            route_info_rpc_command = (C.ROUTE_IPV6_RPC_REQ_FILTER).format(
                network=network, prefix_length=prefix_length
            )
        else:
            route_info_rpc_command = (C.ROUTE_IPV4_RPC_REQ_FILTER).format(
                network=network, prefix_length=prefix_length
            )

        rpc_reply = self.device.get(filter=("subtree", route_info_rpc_command)).xml
        # Converts string to etree
        routes_tree = ETREE.fromstring(rpc_reply)
        if ipv == 6:
            route_xpath = ".//rib{}:ipv6-rib".format(ipv)
        else:
            route_xpath = ".//rib{}:rib".format(ipv)
        route_xpath = (
            route_xpath
            + "/rib{ip}:vrfs/rib{ip}:vrf/rib{ip}:afs/\
        rib{ip}:af/rib{ip}:safs/rib{ip}:saf/rib{ip}:ip-rib-route-table-names/\
        rib{ip}:ip-rib-route-table-name/rib{ip}:routes/rib{ip}:route".format(
                ip=ipv
            )
        )
        for route in routes_tree.xpath(route_xpath, namespaces=C.NS):
            route_protocol = napalm.base.helpers.convert(
                str,
                self._find_txt(
                    route,
                    "./rib{}:protocol-name".format(ipv),
                    default="",
                    namespaces=C.NS,
                ).lower(),
            )
            if protocol and route_protocol != protocol:
                continue  # ignore routes learned via a different protocol
            # only in case the user requested a certain protocol
            route_details = {}
            address = self._find_txt(
                route, "./rib{}:prefix".format(ipv), default="", namespaces=C.NS
            )
            length = self._find_txt(
                route,
                "./rib{}:prefix-length-xr".format(ipv),
                default="",
                namespaces=C.NS,
            )
            priority = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    route, "./rib{}:priority".format(ipv), default="", namespaces=C.NS
                ),
            )
            age = napalm.base.helpers.convert(
                int,
                self._find_txt(
                    route, "./rib{}:route-age".format(ipv), default="", namespaces=C.NS
                ),
            )
            destination = napalm.base.helpers.convert(
                str, "{prefix}/{length}".format(prefix=address, length=length)
            )
            if destination not in routes.keys():
                routes[destination] = []

            route_details = {
                "current_active": False,
                "last_active": False,
                "age": age,
                "next_hop": "",
                "protocol": route_protocol,
                "outgoing_interface": "",
                "preference": priority,
                "selected_next_hop": False,
                "inactive_reason": "",
                "routing_table": "default",
                "protocol_attributes": {},
            }

            first_route = True
            for route_entry in route.xpath(
                ".//rib{ipv}:route-path/rib{ipv}:ipv{ipv}-rib-edm-path".format(ipv=ipv),
                namespaces=C.NS,
            ):
                # get all possible entries
                next_hop = self._find_txt(
                    route_entry,
                    "./rib{ipv}:address".format(ipv=ipv),
                    default="",
                    namespaces=C.NS,
                )
                single_route_details = {}
                single_route_details.update(route_details)
                single_route_details.update(
                    {"current_active": first_route, "next_hop": next_hop}
                )
                routes[destination].append(single_route_details)
                first_route = False

        return routes
    
    def get_route_summary(self, protocol=''):
        """
        Get routing table summary for both IPv4 and IPv6.
        Returns dict with route counts by protocol.
        """
        route_summary = {
            'ipv4': {},
            'ipv6': {}
        }
        
        try:
            # For each IP version
            for ipv in [4, 6]:
                try:
                    # Build appropriate filter
                    if ipv == 6:
                        ns_prefix = 'rib6'
                        filter_xml = ROUTE_IPV6_RPC_REQ_FILTER.format(network='::', prefix_length='0')
                    else:
                        ns_prefix = 'rib4'
                        filter_xml = ROUTE_IPV4_RPC_REQ_FILTER.format(network='0.0.0.0', prefix_length='0')
                    
                    # Get routes
                    rpc_reply = self.device.get(filter=("subtree", filter_xml)).xml
                    routes_tree = ETREE.fromstring(rpc_reply)
                    
                    # Count by protocol
                    protocol_counts = {}
                    route_xpath = f".//{ns_prefix}:route"
                    
                    for route in routes_tree.xpath(route_xpath, namespaces=C.NS):
                        protocol_name = self._find_txt(
                            route,
                            f"./{ns_prefix}:protocol-name",
                            "",
                            namespaces=C.NS
                        ).lower()
                        
                        if protocol_name:
                            protocol_counts[protocol_name] = protocol_counts.get(protocol_name, 0) + 1
                    
                    ip_version = 'ipv4' if ipv == 4 else 'ipv6'
                    route_summary[ip_version] = protocol_counts
                    logger.info(f"Route summary IPv{ipv}: {protocol_counts}")
                    
                except Exception as e:
                    logger.warning(f"Failed to get IPv{ipv} route summary: {e}")
                    
        except Exception as e:
            logger.error(f"Route summary failed: {e}")
    
        return route_summary

    def get_snmp_information(self):
        """Return the SNMP configuration - FIXED."""
        snmp_info = {
            "chassis_id": "",
            "contact": "",
            "location": "",
            "community": {}
        }
        
        try:
            config_reply = self.device.get_config(source="running")
            tree = config_reply.data_ele
            
            # Try multiple XPath patterns for SNMP config
            snmp_paths = [
                './/system/snmp',
                './/snmp'
            ]
            
            for xpath in snmp_paths:
                snmp_nodes = tree.xpath(xpath)
                if snmp_nodes:
                    snmp_node = snmp_nodes[0]
                    
                    # Get contact
                    contact_elem = snmp_node.find('./contact')
                    if contact_elem is not None and contact_elem.text:
                        snmp_info["contact"] = contact_elem.text.strip()
                    
                    # Get location
                    location_elem = snmp_node.find('./location')
                    if location_elem is not None and location_elem.text:
                        snmp_info["location"] = location_elem.text.strip()
                    
                    # Get communities
                    for community in snmp_node.xpath('./community'):
                        name_elem = community.find('./name')
                        if name_elem is not None and name_elem.text:
                            comm_name = name_elem.text.strip()
                            
                            # Get authorization level
                            auth_elem = community.find('./authorization')
                            authorization = auth_elem.text.strip() if auth_elem is not None and auth_elem.text else 'read-only'
                            
                            snmp_info["community"][comm_name] = {
                                "mode": "ro" if authorization == "read-only" else "rw",
                                "acl": ""
                            }
                            logger.debug(f"Found SNMP community: {comm_name}")
                    
                    # If we found SNMP config, break
                    if snmp_info["contact"] or snmp_info["location"] or snmp_info["community"]:
                        logger.info(f"Found SNMP config with {len(snmp_info['community'])} communities")
                        break
                            
        except Exception as e:
            logger.error(f"Failed to get SNMP information: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return snmp_info

    def get_probes_config(self):
        """Return the configuration of the probes."""
        sla_config = {}

        _PROBE_TYPE_XML_TAG_MAP_ = {
            "icmp-echo": "icmp-ping",
            "udp-echo": "udp-ping",
            "icmp-jitter": "icmp-ping-timestamp",
            "udp-jitter": "udp-ping-timestamp",
        }

        rpc_reply = self.device.get_config(
            source="running", filter=("subtree", C.PROBE_CFG_RPC_REQ_FILTER)
        ).xml
        # Converts string to etree
        sla_config_result_tree = ETREE.fromstring(rpc_reply)

        probes_config_xpath = ".//prbc:ipsla/prbc:operation/prbc:definitions/\
            prbc:definition"
        for probe in sla_config_result_tree.xpath(probes_config_xpath, namespaces=C.NS):
            probe_name = self._find_txt(
                probe, "./prbc:operation-id", default="", namespaces=C.NS
            )
            operation_type_etree = probe.xpath("./prbc:operation-type", namespaces=C.NS)
            if len(operation_type_etree):
                operation_type = (
                    operation_type_etree[0]
                    .getchildren()[0]
                    .tag.replace("{" + C.NS.get("prbc") + "}", "")
                )
                probe_type = _PROBE_TYPE_XML_TAG_MAP_.get(operation_type, "")
                operation_xpath = "./prbc:operation-type/prbc:{op_type}".format(
                    op_type=operation_type
                )
                operation = probe.xpath(operation_xpath, namespaces=C.NS)[0]
                test_name = self._find_txt(
                    operation, "./prbc:tag", default="", namespaces=C.NS
                )
                source = self._find_txt(
                    operation, "./prbc:source-address", default="", namespaces=C.NS
                )
                target = self._find_txt(
                    operation, "./prbc:dest-address", default="", namespaces=C.NS
                )
                test_interval = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        operation, "./prbc:frequency", default="0", namespaces=C.NS
                    ),
                )
                probe_count = napalm.base.helpers.convert(
                    int,
                    self._find_txt(
                        operation,
                        "./prbc:history/prbc:buckets",
                        default="0",
                        namespaces=C.NS,
                    ),
                )
                if probe_name not in sla_config.keys():
                    sla_config[probe_name] = {}
                if test_name not in sla_config[probe_name]:
                    sla_config[probe_name][test_name] = {}
                sla_config[probe_name][test_name] = {
                    "probe_type": probe_type,
                    "source": source,
                    "target": target,
                    "probe_count": probe_count,
                    "test_interval": test_interval,
                }

        return sla_config

    def get_probes_results(self):
        """Return the results of the probes."""
        sla_results = {}

        _PROBE_TYPE_XML_TAG_MAP_ = {
            "icmp-echo": "icmp-ping",
            "udp-echo": "udp-ping",
            "icmp-jitter": "icmp-ping-timestamp",
            "udp-jitter": "udp-ping-timestamp",
        }

        rpc_reply = self.device.get(filter=("subtree", C.PROBE_OPER_RPC_REQ_FILTER)).xml
        # Converts string to etree
        sla_results_tree = ETREE.fromstring(rpc_reply)

        probes_config = (
            self.get_probes_config()
        )  # need to retrieve also the configuration
        # source and tag/test_name not provided
        probe_result_xpath = ".//prb:ipsla/prb:operation-data/\
            prb:operations/prb:operation"
        for probe in sla_results_tree.xpath(probe_result_xpath, namespaces=C.NS):
            probe_name = self._find_txt(
                probe, "./prb:operation-id", default="", namespaces=C.NS
            )
            test_name = list(probes_config.get(probe_name).keys())[0]
            target = self._find_txt(
                probe,
                "./prb:history/prb:path/prb:lifes/prb:life/prb:buckets/\
                    prb:bucket[0]/prb:samples/prb:sample/prb:target-address/\
                    prb:ipv4-prefix-target/prb:address",
                default="",
                namespaces=C.NS,
            )
            source = probes_config.get(probe_name).get(test_name, {}).get("source", "")
            probe_type = _PROBE_TYPE_XML_TAG_MAP_.get(
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:latest/prb:target/\
                    prb:specific-stats/prb:op-type",
                    default="",
                    namespaces=C.NS,
                ),
                "",
            )
            probe_count = (
                probes_config.get(probe_name).get(test_name, {}).get("probe_count", 0)
            )
            response_times = probe.xpath(
                "./prb:history/prb:target/prb:lifes/prb:life[last()]/\
                    prb:buckets/prb:bucket/prb:response-time",
                namespaces=C.NS,
            )
            response_times = [
                napalm.base.helpers.convert(
                    int,
                    self._find_txt(response_time, ".", default="0", namespaces=C.NS),
                )
                for response_time in response_times
            ]
            rtt = 0.0

            if len(response_times):
                rtt = sum(response_times, 0.0) / len(response_times)
            return_codes = probe.xpath(
                "./prb:history/prb:target/prb:lifes/prb:life[last()]/\
                    prb:buckets/prb:bucket/prb:return-code",
                namespaces=C.NS,
            )
            return_codes = [
                self._find_txt(return_code, ".", default="", namespaces=C.NS)
                for return_code in return_codes
            ]

            last_test_loss = 0
            if len(return_codes):
                last_test_loss = napalm.base.helpers.convert(
                    int,
                    100
                    * (
                        1
                        - return_codes.count("ipsla-ret-code-ok")
                        / napalm.base.helpers.convert(float, len(return_codes))
                    ),
                )
            rms = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:aggregated/prb:hours/prb:hour/\
                    prb:distributed/prb:target/prb:distribution-intervals/\
                    prb:distribution-interval/prb:common-stats/\
                    prb:sum2-response-time",
                    default="0.0",
                    namespaces=C.NS,
                ),
            )
            global_test_updates = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:aggregated/prb:hours/prb:hour/\
                    prb:distributed/prb:target/prb:distribution-intervals/\
                    prb:distribution-interval/prb:common-stats/\
                    prb:update-count",
                    default="0.0",
                    namespaces=C.NS,
                ),
            )

            jitter = 0.0
            if global_test_updates:
                jitter = rtt - (rms / global_test_updates) ** 0.5
            # jitter = max(rtt - max(response_times), rtt - min(response_times))
            current_test_min_delay = 0.0  # no stats for undergoing test :(
            current_test_max_delay = 0.0
            current_test_avg_delay = 0.0
            last_test_min_delay = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:latest/prb:target/\
                    prb:common-stats/prb:min-response-time",
                    default="0.0",
                    namespaces=C.NS,
                ),
            )
            last_test_max_delay = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:latest/prb:target/\
                    prb:common-stats/prb:max-response-time",
                    default="0.0",
                    namespaces=C.NS,
                ),
            )
            last_test_sum_delay = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:latest/prb:target/\
                    prb:common-stats/prb:sum-response-time",
                    default="0.0",
                    namespaces=C.NS,
                ),
            )
            last_test_updates = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    ".//prb:statistics/prb:latest/prb:target/\
                    prb:common-stats/prb:update-count",
                    default="0.0",
                    namespaces=C.NS,
                ),
            )
            last_test_avg_delay = 0.0
            if last_test_updates:
                last_test_avg_delay = last_test_sum_delay / last_test_updates
            global_test_min_delay = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:aggregated/prb:hours/prb:hour/\
                    prb:distributed/prb:target/prb:distribution-intervals/\
                    prb:distribution-interval/prb:common-stats/\
                    prb:min-response-time",
                    default="0.0",
                    namespaces=C.NS,
                ),
            )
            global_test_max_delay = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:aggregated/prb:hours/prb:hour/\
                    prb:distributed/prb:target/prb:distribution-intervals/\
                    prb:distribution-interval/prb:common-stats/\
                    prb:max-response-time",
                    default="0.0",
                    namespaces=C.NS,
                ),
            )
            global_test_sum_delay = napalm.base.helpers.convert(
                float,
                self._find_txt(
                    probe,
                    "./prb:statistics/prb:aggregated/prb:hours/prb:hour/\
                    prb:distributed/prb:target/prb:distribution-intervals/\
                    prb:distribution-interval/prb:common-stats/\
                    prb:sum-response-time",
                    default="0.0",
                    namespaces=C.NS,
                ),
            )
            global_test_avg_delay = 0.0
            if global_test_updates:
                global_test_avg_delay = global_test_sum_delay / global_test_updates
            if probe_name not in sla_results.keys():
                sla_results[probe_name] = {}
            sla_results[probe_name][test_name] = {
                "target": target,
                "source": source,
                "probe_type": probe_type,
                "probe_count": probe_count,
                "rtt": rtt,
                "round_trip_jitter": jitter,
                "last_test_loss": last_test_loss,
                "current_test_min_delay": current_test_min_delay,
                "current_test_max_delay": current_test_max_delay,
                "current_test_avg_delay": current_test_avg_delay,
                "last_test_min_delay": last_test_min_delay,
                "last_test_max_delay": last_test_max_delay,
                "last_test_avg_delay": last_test_avg_delay,
                "global_test_min_delay": global_test_min_delay,
                "global_test_max_delay": global_test_max_delay,
                "global_test_avg_delay": global_test_avg_delay,
            }

        return sla_results

    def traceroute(
        self,
        destination,
        source=C.TRACEROUTE_SOURCE,
        ttl=C.TRACEROUTE_TTL,
        timeout=C.TRACEROUTE_TIMEOUT,
        vrf=C.TRACEROUTE_VRF,
    ):
        """Execute traceroute and return results."""
        traceroute_result = {}

        ipv = 4
        try:
            ipv = ipaddress.ip_address(destination).version
        except ValueError:
            logger.error(
                "Incorrect format of IP Address in traceroute \
             with value provided:%s"
                % (str(destination))
            )
            return {"error": "Wrong destination IP Address!"}

        source_tag = ""
        ttl_tag = ""
        timeout_tag = ""
        vrf_tag = ""
        if source:
            source_tag = "<source>{source}</source>".format(source=source)
        if ttl:
            ttl_tag = "<max-ttl>{maxttl}</max-ttl>".format(maxttl=ttl)
        if timeout:
            timeout_tag = "<timeout>{timeout}</timeout>".format(timeout=timeout)
        if vrf:
            vrf_tag = "<vrf-name>{vrf}</vrf-name>".format(vrf=vrf)

        traceroute_rpc_command = C.TRACEROUTE_RPC_REQ.format(
            version=ipv,
            destination=destination,
            vrf_tag=vrf_tag,
            source_tag=source_tag,
            ttl_tag=ttl_tag,
            timeout_tag=timeout_tag,
        )

        try:
            rpc_reply = self.device.dispatch(to_ele(traceroute_rpc_command)).xml
        except TimeoutExpiredError:
            return {"error": "Timed out while waiting for reply"}
        except RPCError as e:
            if e.message:
                return {"error": e.message}
            else:
                return {"error": "Invalid request ({})".format(e.tag)}

        # Converts string to etree
        traceroute_tree = ETREE.fromstring(rpc_reply)
        hops = traceroute_tree.xpath(
            ".//tr:ipv{}/tr:hops/tr:hop".format(ipv), namespaces=C.NS
        )

        traceroute_result["success"] = {}

        for hop in hops:
            hop_index = napalm.base.helpers.convert(
                int,
                self._find_txt(hop, "./tr:hop-index", default="-1", namespaces=C.NS),
            )
            hop_address = self._find_txt(
                hop, "./tr:hop-address", default="", namespaces=C.NS
            )

            if hop_address == "":
                continue
            hop_name = self._find_txt(
                hop, "./tr:hop-hostname", default=hop_address, namespaces=C.NS
            )

            traceroute_result["success"][hop_index] = {"probes": {}}
            for probe in hop.xpath("./tr:probes/tr:probe", namespaces=C.NS):
                probe_index = (
                    napalm.base.helpers.convert(
                        int,
                        self._find_txt(
                            probe, "./tr:probe-index", default="", namespaces=C.NS
                        ),
                        0,
                    )
                    + 1
                )
                probe_hop_address = str(
                    self._find_txt(
                        probe, "./tr:hop-address", default=hop_address, namespaces=C.NS
                    )
                )
                probe_hop_name = str(
                    self._find_txt(
                        probe, "./tr:hop-hostname", default=hop_name, namespaces=C.NS
                    )
                )
                rtt = napalm.base.helpers.convert(
                    float,
                    self._find_txt(
                        probe, "./tr:delta-time", default="", namespaces=C.NS
                    ),
                    timeout * 1000.0,
                )  # ms
                traceroute_result["success"][hop_index]["probes"][probe_index] = {
                    "ip_address": probe_hop_address,
                    "host_name": probe_hop_name,
                    "rtt": rtt,
                }

        return traceroute_result

    def get_users(self):
        """Return user configuration - FIXED."""
        users = {}
        
        _CLASS_TO_LEVEL = {
            "super-user": 15,
            "superuser": 15,
            "operator": 5,
            "read-only": 1,
            "unauthorized": 0
        }
        
        try:
            config_reply = self.device.get_config(source="running")
            tree = config_reply.data_ele
            
            # Try multiple XPath patterns for users
            user_paths = [
                './/system/login/user',
                './/login/user'
            ]
            
            for xpath in user_paths:
                users_found = tree.xpath(xpath)
                if users_found:
                    logger.info(f"Found {len(users_found)} users using XPath: {xpath}")
                    
                    for user in users_found:
                        # Get username
                        username_elem = user.find('./name')
                        if username_elem is None or username_elem.text is None:
                            continue
                        
                        username = username_elem.text.strip()
                        
                        # Get user class
                        class_elem = user.find('./class')
                        user_class = class_elem.text.strip() if class_elem is not None and class_elem.text else 'unauthorized'
                        level = _CLASS_TO_LEVEL.get(user_class.lower(), 0)
                        
                        users[username] = {
                            "level": level,
                            "password": "",
                            "sshkeys": []
                        }
                        
                        # Get SSH keys
                        auth_node = user.find('./authentication')
                        if auth_node is not None:
                            # Try all SSH key types
                            key_types = ['ssh-rsa', 'ssh-dsa', 'ssh-ecdsa', 'ssh-ed25519']
                            for key_type in key_types:
                                for key in auth_node.xpath(f'./{key_type}'):
                                    key_name_elem = key.find('./name')
                                    if key_name_elem is not None and key_name_elem.text:
                                        users[username]["sshkeys"].append(key_name_elem.text.strip())
                        
                        logger.debug(f"Found user: {username} (level {level})")
                    
                    # If we found users, break
                    if users:
                        break
            
            logger.info(f"Total users found: {len(users)}")
                            
        except Exception as e:
            logger.error(f"Failed to get users: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return users


    def get_config(self, retrieve="all", full=False, sanitized=False, format="text"):
        """Return device configuration."""

        encoding = self.config_encoding
        # 'full' argument not supported; 'with-default' capability not supported.
        if full:
            raise NotImplementedError(
                "'full' argument has not been implemented on the IOS-XR NETCONF driver"
            )

        if sanitized:
            raise NotImplementedError(
                "sanitized argument has not been implemented on the IOS-XR NETCONF driver"
            )

        # default values
        config = {"startup": "", "running": "", "candidate": ""}
        if encoding == "cli":
            subtree_filter = ("subtree", C.CLI_CONFIG_RPC_REQ_FILTER)
        elif encoding == "xml":
            subtree_filter = None
        else:
            raise NotImplementedError(
                f"config encoding must be one of {C.CONFIG_ENCODINGS}"
            )

        if retrieve.lower() in ["running", "all"]:
            config["running"] = str(
                self.device.get_config(source="running", filter=subtree_filter).xml
            )
        if retrieve.lower() in ["candidate", "all"]:
            config["candidate"] = str(
                self.device.get_config(source="candidate", filter=subtree_filter).xml
            )

        parser = ETREE.XMLParser(remove_blank_text=True)
        # Validate XML config strings and remove rpc-reply tag
        for datastore in config:
            if config[datastore] != "":
                if encoding == "cli":
                    cli_tree = ETREE.XML(config[datastore], parser=parser)[0]
                    if len(cli_tree):
                        config[datastore] = cli_tree[0].text.strip()
                    else:
                        config[datastore] = ""
                else:
                    config[datastore] = ETREE.tostring(
                        self._filter_config_tree(
                            ETREE.XML(config[datastore], parser=parser)[0]
                        ),
                        pretty_print=True,
                        encoding="unicode",
                    )
        if sanitized and encoding == "cli":
            return napalm.base.helpers.sanitize_configs(
                config, C.CISCO_SANITIZE_FILTERS
            )
        return config
    
    def get_hardware_inventory(self):
        """Return detailed hardware inventory."""
        hardware = {
            "chassis": {},
            "modules": []
        }
        
        try:
            # Get inventory via NETCONF
            facts_rpc_reply = self.device.dispatch(to_ele(C.FACTS_RPC_REQ)).xml
            facts_tree = ETREE.fromstring(facts_rpc_reply)
            
            # Parse chassis info
            basic_info = facts_tree.xpath('.//imo:inventory/imo:entities/imo:entity[1]/imo:attributes/imo:inv-basic-bag', namespaces=C.NS)
            if basic_info:
                hardware["chassis"] = {
                    "description": self._find_txt(basic_info[0], './imo:description', '', namespaces=C.NS),
                    "name": self._find_txt(basic_info[0], './imo:name', '', namespaces=C.NS),
                    "model": self._find_txt(basic_info[0], './imo:model-name', '', namespaces=C.NS),
                    "serial_number": self._find_txt(basic_info[0], './imo:serial-number', '', namespaces=C.NS),
                }
            
            # Parse all entities (cards, modules, etc.)
            for entity in facts_tree.xpath('.//imo:inventory/imo:entities/imo:entity', namespaces=C.NS):
                entity_name = self._find_txt(entity, './imo:name', '', namespaces=C.NS)
                if not entity_name:
                    continue
                
                attributes = entity.find('.//imo:attributes/imo:inv-basic-bag', namespaces=C.NS)
                if attributes is not None:
                    module = {
                        "name": entity_name,
                        "description": self._find_txt(attributes, './imo:description', '', namespaces=C.NS),
                        "model": self._find_txt(attributes, './imo:model-name', '', namespaces=C.NS),
                        "serial_number": self._find_txt(attributes, './imo:serial-number', '', namespaces=C.NS),
                        "version": self._find_txt(attributes, './imo:software-revision', '', namespaces=C.NS),
                        "part_number": self._find_txt(attributes, './imo:part-number', '', namespaces=C.NS),
                    }
                    
                    # Only add if has meaningful data
                    if module["description"] or module["model"]:
                        hardware["modules"].append(module)
            
            logger.info(f"Collected {len(hardware['modules'])} hardware modules")
            
        except Exception as e:
            logger.error(f"Failed to get hardware inventory: {e}")
        
        return hardware
    
    def get_optics(self):
        """
        Retrieve optical transceiver information from all interfaces.
        FIXED: Uses optics-present field when vendor-info is unavailable
        """
        optics_data = {}
        
        try:
            # NETCONF filter for optics data
            optics_filter = """
            <optics-oper xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-controller-optics-oper">
                <optics-ports>
                    <optics-port>
                        <name/>
                        <optics-info/>
                    </optics-port>
                </optics-ports>
            </optics-oper>
            """
            
            logging.info("=" * 80)
            logging.info("OPTICS COLLECTION - USING optics-present FIELD")
            logging.info("=" * 80)
            
            rpc_reply = self.device.get(filter=("subtree", optics_filter)).xml
            tree = ETREE.fromstring(rpc_reply)
            
            ns_optics = {'opt': 'http://cisco.com/ns/yang/Cisco-IOS-XR-controller-optics-oper'}
            
            ports_with_optics = 0
            
            # Find all optics-port nodes
            all_ports = tree.xpath('.//opt:optics-ports/opt:optics-port', namespaces=ns_optics)
            logging.info(f"Found {len(all_ports)} optics-port nodes in XML")
            
            for port in all_ports:
                port_name_elem = port.find('./opt:name', namespaces=ns_optics)
                if port_name_elem is None or not port_name_elem.text:
                    continue
                
                port_name = port_name_elem.text.strip()
                
                # Get optics-info
                optics_info = port.find('./opt:optics-info', namespaces=ns_optics)
                if optics_info is None:
                    optics_data[port_name] = {"physical_present": False}
                    continue
                
                # ✅ FIX: Use optics-present field directly
                optics_present_elem = optics_info.find('./opt:optics-present', namespaces=ns_optics)
                if optics_present_elem is None:
                    optics_data[port_name] = {"physical_present": False}
                    continue
                
                optics_present_value = optics_present_elem.text
                
                # Skip if optics not present
                if optics_present_value != 'true':
                    optics_data[port_name] = {"physical_present": False}
                    continue
                
                # ✅ Optics IS present
                ports_with_optics += 1
                logging.info(f"✅ {port_name}: Optics detected (optics-present=true)")
                
                # Get optics type - use derived-optics-type if available
                derived_optics_type = self._find_txt(optics_info, './opt:derived-optics-type', '', namespaces=ns_optics)
                optics_type = self._find_txt(optics_info, './opt:optics-type', '', namespaces=ns_optics)
                
                # Use derived type if available, fallback to base type
                final_optics_type = derived_optics_type if derived_optics_type and derived_optics_type != 'Unavailable' else optics_type
                
                # Get wavelength
                wavelength_raw = self._find_txt(optics_info, './opt:grey-wavelength', '0', namespaces=ns_optics)
                try:
                    # Wavelength is in hundredths of nm, convert to nm
                    wavelength = float(wavelength_raw) / 100.0 if wavelength_raw else 0
                    wavelength_str = f"{wavelength:.2f}" if wavelength > 0 else ""
                except (ValueError, TypeError):
                    wavelength_str = ""
                
                # Try to get vendor-info (even though it's usually missing)
                vendor_info = optics_info.find('./opt:vendor-info', namespaces=ns_optics)
                if vendor_info is not None:
                    vendor_name = self._find_txt(vendor_info, './opt:name', '', namespaces=ns_optics)
                    vendor_part = self._find_txt(vendor_info, './opt:part-number', '', namespaces=ns_optics)
                    vendor_serial = self._find_txt(vendor_info, './opt:serial-number', '', namespaces=ns_optics)
                    oui_number = self._find_txt(vendor_info, './opt:oui-number', '', namespaces=ns_optics)
                    rev_number = self._find_txt(vendor_info, './opt:rev-number', '', namespaces=ns_optics)
                    pid = self._find_txt(vendor_info, './opt:pid', '', namespaces=ns_optics)
                    vid = self._find_txt(vendor_info, './opt:vid', '', namespaces=ns_optics)
                    date_code = self._find_txt(vendor_info, './opt:date-code', '', namespaces=ns_optics)
                else:
                    # Vendor info not available - use placeholder values
                    vendor_name = "Unknown Vendor"
                    vendor_part = "Unknown"
                    vendor_serial = "Unknown"
                    oui_number = ""
                    rev_number = ""
                    pid = ""
                    vid = ""
                    date_code = ""
                
                # Get power readings - these should be available
                # Try lane data first
                lanes = optics_info.xpath('./opt:lane-data/opt:lane-alarm-info', namespaces=ns_optics)
                
                if lanes:
                    output_power_total = 0.0
                    input_power_total = 0.0
                    laser_bias_total = 0.0
                    
                    for lane in lanes:
                        tx_power_str = self._find_txt(lane, './opt:output-power', '0', namespaces=ns_optics)
                        rx_power_str = self._find_txt(lane, './opt:input-power', '0', namespaces=ns_optics)
                        laser_bias_str = self._find_txt(lane, './opt:laser-bias-current', '0', namespaces=ns_optics)
                        
                        try:
                            output_power_total += float(tx_power_str) / 100.0
                            input_power_total += float(rx_power_str) / 100.0
                            laser_bias_total += float(laser_bias_str) / 500.0
                        except (ValueError, TypeError):
                            pass
                    
                    lane_count = len(lanes)
                    output_power = output_power_total / lane_count if lane_count > 0 else 0.0
                    input_power = input_power_total / lane_count if lane_count > 0 else 0.0
                    laser_bias = laser_bias_total / lane_count if lane_count > 0 else 0.0
                else:
                    # Single lane - get from optics-info directly
                    tx_power_str = self._find_txt(optics_info, './opt:output-power', '0', namespaces=ns_optics)
                    rx_power_str = self._find_txt(optics_info, './opt:input-power', '0', namespaces=ns_optics)
                    laser_bias_str = self._find_txt(optics_info, './opt:laser-bias-current', '0', namespaces=ns_optics)
                    
                    try:
                        output_power = float(tx_power_str) / 100.0
                        input_power = float(rx_power_str) / 100.0
                        laser_bias = float(laser_bias_str) / 500.0
                    except (ValueError, TypeError):
                        output_power = input_power = laser_bias = 0.0
                
                # Get temperature and voltage
                temp_str = self._find_txt(optics_info, './opt:temperature', '0', namespaces=ns_optics)
                voltage_str = self._find_txt(optics_info, './opt:voltage', '0', namespaces=ns_optics)
                
                try:
                    temperature = float(temp_str) / 1000.0
                    voltage = float(voltage_str) / 10000.0
                except (ValueError, TypeError):
                    temperature = voltage = 0.0
                
                # Get thresholds from NETCONF data
                rx_low_thresh = self._find_txt(optics_info, './opt:rx-low-threshold', '-139', namespaces=ns_optics)
                rx_high_thresh = self._find_txt(optics_info, './opt:rx-high-threshold', '20', namespaces=ns_optics)
                tx_low_thresh = self._find_txt(optics_info, './opt:tx-low-threshold', '-113', namespaces=ns_optics)
                tx_high_thresh = self._find_txt(optics_info, './opt:tx-high-threshold', '16', namespaces=ns_optics)
                
                try:
                    rx_low = float(rx_low_thresh) / 10.0
                    rx_high = float(rx_high_thresh) / 10.0
                    tx_low = float(tx_low_thresh) / 10.0
                    tx_high = float(tx_high_thresh) / 10.0
                except (ValueError, TypeError):
                    rx_low, rx_high = -13.9, 2.0
                    tx_low, tx_high = -11.3, 1.6
                
                # Determine form factor from optics type
                form_factor = "Unknown"
                if "SFP+" in final_optics_type or "10G" in final_optics_type:
                    form_factor = "SFP+"
                elif "SFP" in final_optics_type or "1G" in final_optics_type:
                    form_factor = "SFP"
                elif "QSFP" in final_optics_type:
                    form_factor = "QSFP"
                elif "CFP" in final_optics_type:
                    form_factor = "CFP"
                
                optics_data[port_name] = {
                    "physical_present": True,
                    "vendor_name": vendor_name,
                    "vendor_part": vendor_part,
                    "vendor_serial": vendor_serial,
                    "oui_number": oui_number,
                    "rev_number": rev_number,
                    "pid": pid,
                    "vid": vid,
                    "date_code": date_code,
                    "hardware_version": "0.0",
                    "form_factor": form_factor,
                    "transceiver_type": final_optics_type,
                    "wavelength": wavelength_str,
                    "output_power": {"instant": round(output_power, 2)},
                    "input_power": {"instant": round(input_power, 2)},
                    "temperature": {"instant": round(temperature, 2)},
                    "voltage": {"instant": round(voltage, 2)},
                    "laser_bias_current": {"instant": round(laser_bias, 1)},
                    "performance_monitoring": "Disable",
                    "alarms": [],
                    "rx_power_thresholds": {
                        "high_alarm": round(rx_high, 1),
                        "low_alarm": round(rx_low, 1),
                        "high_warning": round(rx_high - 1.0, 1),
                        "low_warning": round(rx_low + 4.0, 1)
                    },
                    "tx_power_thresholds": {
                        "high_alarm": round(tx_high, 1),
                        "low_alarm": round(tx_low, 1),
                        "high_warning": round(tx_high - 0.3, 1),
                        "low_warning": round(tx_low + 4.0, 1)
                    },
                    "lbc_thresholds": {
                        "high_alarm": 10.50, "low_alarm": 2.50,
                        "high_warning": 10.50, "low_warning": 2.50
                    },
                    "temp_thresholds": {
                        "high_alarm": 75.00, "low_alarm": -5.00,
                        "high_warning": 70.00, "low_warning": 0.00
                    },
                    "voltage_thresholds": {
                        "high_alarm": 3.63, "low_alarm": 2.97,
                        "high_warning": 3.46, "low_warning": 3.13
                    }
                }
                
                logging.info(f"  Type: {final_optics_type}")
                logging.info(f"  TX: {output_power:.2f} dBm, RX: {input_power:.2f} dBm")
            
            logging.info("")
            logging.info("=" * 80)
            logging.info(f"OPTICS COLLECTION SUMMARY")
            logging.info(f"Total ports: {len(all_ports)}")
            logging.info(f"With optics: {ports_with_optics}")
            logging.info("=" * 80)
            
        except Exception as e:
            logging.error(f"Failed to get optics data: {e}")
            import traceback
            logging.error(traceback.format_exc())
        
        return optics_data

    def _parse_optics_cli_output(self, output):
        """
        Parse 'show controllers optics' CLI output
        Extracted as separate method for reusability
        """
        optics_data = {}
        
        try:
            lines = output.split('\n')
            current_interface = None
            current_data = {}
            has_optics = False
            
            for line in lines:
                line_stripped = line.strip()
                
                # Detect interface name (starts with "Controller Optics0/0/0/X")
                if line_stripped.startswith('Controller ') and 'Optics' in line_stripped:
                    # Save previous interface if it had optics
                    if current_interface and has_optics and current_data:
                        optics_data[current_interface] = current_data
                        logging.info(f"✅ Parsed: {current_interface}")
                    
                    # Start new interface - extract name from "Controller Optics0/0/0/0"
                    parts = line_stripped.split()
                    if len(parts) >= 2:
                        current_interface = parts[1]  # e.g., "Optics0/0/0/0"
                        current_data = {"physical_present": False}
                        has_optics = False
                
                # Check for optics presence indicators
                if 'Controller State' in line_stripped and ': Up' in line_stripped:
                    has_optics = True
                    current_data["physical_present"] = True
                
                if 'Optics not present' in line_stripped.lower() or 'not supported' in line_stripped.lower():
                    has_optics = False
                    current_data["physical_present"] = False
                
                # Parse optics type
                if 'Optics Type' in line_stripped or 'Optics type' in line_stripped:
                    has_optics = True
                    current_data["physical_present"] = True
                    if ':' in line_stripped:
                        optics_type = line_stripped.split(':', 1)[1].strip()
                        current_data["transceiver_type"] = optics_type
                        current_data["form_factor"] = "SFP+" if "SFP+" in optics_type else "QSFP" if "QSFP" in optics_type else "Unknown"
                
                # Parse wavelength
                if 'Wavelength' in line_stripped and '=' in line_stripped:
                    try:
                        wavelength = line_stripped.split('=')[1].strip().split()[0]
                        current_data["wavelength"] = wavelength
                    except (IndexError, ValueError):
                        pass
                
                # Parse vendor information (only if optics present)
                if current_data.get("physical_present"):
                    # Vendor name
                    if 'Name' in line_stripped and '=' not in line_stripped and ':' in line_stripped:
                        vendor = line_stripped.split(':', 1)[1].strip()
                        current_data["vendor_name"] = vendor
                    
                    # Part Number
                    if 'Part Number' in line_stripped and ':' in line_stripped:
                        part = line_stripped.split(':', 1)[1].strip()
                        current_data["vendor_part"] = part
                    
                    # Serial Number
                    if 'Serial Number' in line_stripped and ':' in line_stripped:
                        serial = line_stripped.split(':', 1)[1].strip()
                        current_data["vendor_serial"] = serial
                    
                    # OUI Number
                    if 'OUI Number' in line_stripped and ':' in line_stripped:
                        oui = line_stripped.split(':', 1)[1].strip()
                        current_data["oui_number"] = oui
                    
                    # Rev Number
                    if 'Rev Number' in line_stripped and ':' in line_stripped:
                        rev = line_stripped.split(':', 1)[1].strip()
                        current_data["rev_number"] = rev
                    
                    # PID
                    if 'PID' in line_stripped and ':' in line_stripped:
                        pid = line_stripped.split(':', 1)[1].strip()
                        current_data["pid"] = pid
                    
                    # VID
                    if 'VID' in line_stripped and ':' in line_stripped:
                        vid = line_stripped.split(':', 1)[1].strip()
                        current_data["vid"] = vid
                    
                    # Date Code
                    if 'Date Code' in line_stripped and ':' in line_stripped:
                        date_code = line_stripped.split(':', 1)[1].strip()
                        current_data["date_code"] = date_code
                    
                    # Hardware Version
                    if 'Hardware Version' in line_stripped and ':' in line_stripped:
                        hw_ver = line_stripped.split(':', 1)[1].strip()
                        current_data["hardware_version"] = hw_ver
                    
                    # Parse TX Power
                    if ('TX Power' in line_stripped or 'Actual TX Power' in line_stripped) and '=' in line_stripped:
                        try:
                            power_str = line_stripped.split('=')[1].strip().split()[0]
                            tx_power = float(power_str)
                            current_data["output_power"] = {"instant": tx_power}
                        except (ValueError, IndexError):
                            pass
                    
                    # Parse RX Power
                    if 'RX Power' in line_stripped and '=' in line_stripped:
                        try:
                            power_str = line_stripped.split('=')[1].strip().split()[0]
                            rx_power = float(power_str)
                            current_data["input_power"] = {"instant": rx_power}
                        except (ValueError, IndexError):
                            pass
                    
                    # Parse Laser Bias Current
                    if 'Laser Bias Current' in line_stripped and '=' in line_stripped:
                        try:
                            bias_str = line_stripped.split('=')[1].strip().split()[0]
                            laser_bias = float(bias_str)
                            current_data["laser_bias_current"] = {"instant": laser_bias}
                        except (ValueError, IndexError):
                            pass
                    
                    # Parse Temperature
                    if 'Temperature' in line_stripped and '=' in line_stripped and 'Threshold' not in line_stripped:
                        try:
                            temp_str = line_stripped.split('=')[1].strip().split()[0]
                            temp = float(temp_str)
                            current_data["temperature"] = {"instant": temp}
                        except (ValueError, IndexError):
                            pass
                    
                    # Parse Voltage
                    if 'Voltage' in line_stripped and '=' in line_stripped and 'Threshold' not in line_stripped:
                        try:
                            volt_str = line_stripped.split('=')[1].strip().split()[0]
                            voltage = float(volt_str)
                            current_data["voltage"] = {"instant": voltage}
                        except (ValueError, IndexError):
                            pass
                    
                    # Add default thresholds if not present
                    if "rx_power_thresholds" not in current_data:
                        current_data["rx_power_thresholds"] = {
                            "high_alarm": 2.0, "low_alarm": -13.9,
                            "high_warning": -1.0, "low_warning": -9.9
                        }
                    if "tx_power_thresholds" not in current_data:
                        current_data["tx_power_thresholds"] = {
                            "high_alarm": 1.6, "low_alarm": -11.3,
                            "high_warning": -1.3, "low_warning": -7.3
                        }
                    if "lbc_thresholds" not in current_data:
                        current_data["lbc_thresholds"] = {
                            "high_alarm": 10.50, "low_alarm": 2.50,
                            "high_warning": 10.50, "low_warning": 2.50
                        }
                    if "temp_thresholds" not in current_data:
                        current_data["temp_thresholds"] = {
                            "high_alarm": 75.00, "low_alarm": -5.00,
                            "high_warning": 70.00, "low_warning": 0.00
                        }
                    if "voltage_thresholds" not in current_data:
                        current_data["voltage_thresholds"] = {
                            "high_alarm": 3.63, "low_alarm": 2.97,
                            "high_warning": 3.46, "low_warning": 3.13
                        }
                    
                    current_data["performance_monitoring"] = "Disable"
                    current_data["alarms"] = []
            
            # Don't forget the last interface
            if current_interface and has_optics and current_data:
                optics_data[current_interface] = current_data
                logging.info(f"✅ Parsed: {current_interface}")
            
            if optics_data:
                with_optics = sum(1 for info in optics_data.values() if info.get('physical_present', False))
                logging.info(f"CLI parsing complete: {with_optics} interfaces with optics")
            
        except Exception as e:
            logging.error(f"CLI output parsing failed: {e}")
            import traceback
            logging.error(traceback.format_exc())
        
        return optics_data

    def _convert_to_float(self, value, default=0.0):
        """Helper to convert string to float safely."""
        try:
            return float(value)
        except (ValueError, TypeError):
            return default
        
    def _get_optics_via_cli(self):
        """
        Fallback method: Get optics data using CLI 'show controllers optics'
        Enhanced parser for IOS-XR output format
        """
        optics_data = {}
        
        try:
            # Execute CLI command via NETCONF
            cli_rpc = """
            <action xmlns="http://cisco.com/ns/yang/Cisco-IOS-XR-action">
                <cli-exec-action-xr>
                    <cmd>show controllers optics</cmd>
                </cli-exec-action-xr>
            </action>
            """
            
            logging.info("Executing 'show controllers optics' via CLI...")
            rpc_reply = self.device.dispatch(to_ele(cli_rpc)).xml
            result_tree = ETREE.fromstring(rpc_reply)
            
            # Extract output text
            output = None
            for elem in result_tree.iter():
                if elem.text and ('Controller State' in str(elem.text) or 'Optics0/' in str(elem.text)):
                    output = elem.text
                    break
            
            if not output:
                logging.warning("No CLI output received")
                return optics_data
            
            logging.info(f"Received CLI output: {len(output)} characters")
            
            # Parse the CLI output
            lines = output.split('\n')
            current_interface = None
            current_data = {}
            has_optics = False
            
            for line in lines:
                line_stripped = line.strip()
                
                # Detect interface name (starts with "Controller Optics0/0/0/X")
                if line_stripped.startswith('Controller ') and 'Optics' in line_stripped:
                    # Save previous interface if it had optics
                    if current_interface and has_optics and current_data:
                        optics_data[current_interface] = current_data
                        logging.info(f"✅ CLI: Found optics on {current_interface}")
                    
                    # Start new interface - extract name from "Controller Optics0/0/0/0"
                    parts = line_stripped.split()
                    if len(parts) >= 2:
                        current_interface = parts[1]  # e.g., "Optics0/0/0/0"
                        current_data = {"physical_present": False}
                        has_optics = False
                
                # Check for optics presence indicators
                if 'Controller State' in line_stripped and ': Up' in line_stripped:
                    has_optics = True
                    current_data["physical_present"] = True
                
                if 'Optics not present' in line_stripped.lower() or 'not supported' in line_stripped.lower():
                    has_optics = False
                    current_data["physical_present"] = False
                
                # Parse optics type
                if 'Optics Type' in line_stripped or 'Optics type' in line_stripped:
                    has_optics = True
                    current_data["physical_present"] = True
                    if ':' in line_stripped:
                        optics_type = line_stripped.split(':', 1)[1].strip()
                        current_data["transceiver_type"] = optics_type
                        current_data["form_factor"] = "SFP+" if "SFP+" in optics_type else "QSFP" if "QSFP" in optics_type else "Unknown"
                
                # Parse wavelength
                if 'Wavelength' in line_stripped and '=' in line_stripped:
                    try:
                        wavelength = line_stripped.split('=')[1].strip().split()[0]
                        current_data["wavelength"] = wavelength
                    except (IndexError, ValueError):
                        pass
                
                # Parse vendor information (only if optics present)
                if current_data.get("physical_present"):
                    # Vendor name
                    if 'Name' in line_stripped and '=' not in line_stripped and ':' in line_stripped:
                        vendor = line_stripped.split(':', 1)[1].strip()
                        current_data["vendor_name"] = vendor
                    
                    # Part Number
                    if 'Part Number' in line_stripped and ':' in line_stripped:
                        part = line_stripped.split(':', 1)[1].strip()
                        current_data["vendor_part"] = part
                    
                    # Serial Number
                    if 'Serial Number' in line_stripped and ':' in line_stripped:
                        serial = line_stripped.split(':', 1)[1].strip()
                        current_data["vendor_serial"] = serial
                    
                    # OUI Number
                    if 'OUI Number' in line_stripped and ':' in line_stripped:
                        oui = line_stripped.split(':', 1)[1].strip()
                        current_data["oui_number"] = oui
                    
                    # Rev Number
                    if 'Rev Number' in line_stripped and ':' in line_stripped:
                        rev = line_stripped.split(':', 1)[1].strip()
                        current_data["rev_number"] = rev
                    
                    # PID
                    if 'PID' in line_stripped and ':' in line_stripped:
                        pid = line_stripped.split(':', 1)[1].strip()
                        current_data["pid"] = pid
                    
                    # VID
                    if 'VID' in line_stripped and ':' in line_stripped:
                        vid = line_stripped.split(':', 1)[1].strip()
                        current_data["vid"] = vid
                    
                    # Date Code
                    if 'Date Code' in line_stripped and ':' in line_stripped:
                        date_code = line_stripped.split(':', 1)[1].strip()
                        current_data["date_code"] = date_code
                    
                    # Hardware Version
                    if 'Hardware Version' in line_stripped and ':' in line_stripped:
                        hw_ver = line_stripped.split(':', 1)[1].strip()
                        current_data["hardware_version"] = hw_ver
                    
                    # Parse TX Power
                    if ('TX Power' in line_stripped or 'Actual TX Power' in line_stripped) and '=' in line_stripped:
                        try:
                            power_str = line_stripped.split('=')[1].strip().split()[0]
                            tx_power = float(power_str)
                            current_data["output_power"] = {"instant": tx_power}
                        except (ValueError, IndexError):
                            pass
                    
                    # Parse RX Power
                    if 'RX Power' in line_stripped and '=' in line_stripped:
                        try:
                            power_str = line_stripped.split('=')[1].strip().split()[0]
                            rx_power = float(power_str)
                            current_data["input_power"] = {"instant": rx_power}
                        except (ValueError, IndexError):
                            pass
                    
                    # Parse Laser Bias Current
                    if 'Laser Bias Current' in line_stripped and '=' in line_stripped:
                        try:
                            bias_str = line_stripped.split('=')[1].strip().split()[0]
                            laser_bias = float(bias_str)
                            current_data["laser_bias_current"] = {"instant": laser_bias}
                        except (ValueError, IndexError):
                            pass
                    
                    # Parse Temperature
                    if 'Temperature' in line_stripped and '=' in line_stripped and 'Threshold' not in line_stripped:
                        try:
                            temp_str = line_stripped.split('=')[1].strip().split()[0]
                            temp = float(temp_str)
                            current_data["temperature"] = {"instant": temp}
                        except (ValueError, IndexError):
                            pass
                    
                    # Parse Voltage
                    if 'Voltage' in line_stripped and '=' in line_stripped and 'Threshold' not in line_stripped:
                        try:
                            volt_str = line_stripped.split('=')[1].strip().split()[0]
                            voltage = float(volt_str)
                            current_data["voltage"] = {"instant": voltage}
                        except (ValueError, IndexError):
                            pass
                    
                    # Parse thresholds if present
                    if 'Rx Power Threshold' in line_stripped:
                        try:
                            parts = line_stripped.split()
                            if len(parts) >= 5:
                                current_data["rx_power_thresholds"] = {
                                    "high_alarm": float(parts[-4]),
                                    "low_alarm": float(parts[-3]),
                                    "high_warning": float(parts[-2]),
                                    "low_warning": float(parts[-1])
                                }
                        except (ValueError, IndexError):
                            pass
                    
                    if 'Tx Power Threshold' in line_stripped:
                        try:
                            parts = line_stripped.split()
                            if len(parts) >= 5:
                                current_data["tx_power_thresholds"] = {
                                    "high_alarm": float(parts[-4]),
                                    "low_alarm": float(parts[-3]),
                                    "high_warning": float(parts[-2]),
                                    "low_warning": float(parts[-1])
                                }
                        except (ValueError, IndexError):
                            pass
            
            # Don't forget the last interface
            if current_interface and has_optics and current_data:
                optics_data[current_interface] = current_data
                logging.info(f"✅ CLI: Found optics on {current_interface}")
            
            if optics_data:
                with_optics = sum(1 for info in optics_data.values() if info.get('physical_present', False))
                logging.info(f"✅ CLI parsing complete: {with_optics} interfaces with optics")
            else:
                logging.info("CLI parsing found no interfaces with optics")
            
        except Exception as e:
            logging.error(f"CLI fallback parsing failed: {e}")
            import traceback
            logging.error(traceback.format_exc())
        
        return optics_data