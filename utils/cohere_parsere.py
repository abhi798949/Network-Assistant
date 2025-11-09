import os
import re
import json
from openai import OpenAI
from dotenv import load_dotenv
import logging

# Load from .env if available
load_dotenv()

def get_client():
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("🔒 No OpenRouter API key found. Please set OPENROUTER_API_KEY environment variable or add it to .env file.")
    
    return OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )

def debug_device_type(device_info):
    """
    Debug function to check what device_type is being used
    """
    raw_device_type = device_info.get("device_type", "cisco_xr") if device_info else "cisco_xr"
    normalized_device_type = normalize_device_type(raw_device_type)
    
    print(f"Debug - Raw device_type: '{raw_device_type}'")
    print(f"Debug - Normalized device_type: '{normalized_device_type}'")
    print(f"Debug - Device info: {device_info}")
    
    return normalized_device_type

def normalize_device_type(device_type):
    """
    Normalize device type to match Netmiko's expected values
    """
    if not device_type:
        return "cisco_xr"
    
    device_type = str(device_type).strip().lower()
    
    # Handle XR variations early
    if 'xr' in device_type or 'ios xr' in device_type:
        return 'cisco_xr'
    
    # Handle Juniper variations
    if 'juniper' in device_type or 'junos' in device_type:
        return 'juniper_junos'
    
    # Handle Nokia variations
    if 'nokia' in device_type or 'sros' in device_type or 'sr os' in device_type:
        return 'nokia_sros'
    
    # Handle common variations and mappings
    device_mappings = {
        "cisco ios": "cisco_ios",
        "cisco-ios": "cisco_ios",
        "ios": "cisco_ios",
        "cisco ios xr": "cisco_xr",
        "cisco-ios-xr": "cisco_xr",
        "cisco_ios_xr": "cisco_xr",
        "xr": "cisco_xr",
        "iosxr": "cisco_xr",
        "ios-xr": "cisco_xr",
        "juniper junos": "juniper_junos",
        "juniper-junos": "juniper_junos",
        "junos": "juniper_junos",
        "juniper": "juniper_junos",
        "cisco nx-os": "cisco_nxos",
        "cisco-nx-os": "cisco_nxos",
        "cisco nexus": "cisco_nxos",
        "nexus": "cisco_nxos",
        "nxos": "cisco_nxos",
        "cisco asa": "cisco_asa",
        "asa": "cisco_asa",
        "nokia sros": "nokia_sros",
        "nokia": "nokia_sros",
        "sros": "nokia_sros",
        "sr os": "nokia_sros",
    }
    
    # Check direct mapping first
    if device_type in device_mappings:
        return device_mappings[device_type]
    
    # If already in correct format, return as-is
    supported_types = [
        'cisco_ios', 'cisco_xr', 'cisco_nxos', 'cisco_asa', 'juniper_junos',
        'arista_eos', 'hp_comware', 'huawei_vrp', 'fortinet', 'paloalto_panos',
        'nokia_sros'
    ]
    
    if device_type in supported_types:
        return device_type
    
    # Default fallback
    return "cisco_xr"

def get_show_command_keywords(prompt, device_info):
    """
    Generate show command keywords (like "interface", "bgp") using LLM training
    This mimics the "show ?" output that shows available command keywords
    """
    device_type = normalize_device_type(device_info.get("device_type", "cisco_xr"))
    
    # Try LLM approach for command keywords
    try:
        keywords = get_llm_command_keywords(prompt, device_type)
        if keywords:
            return keywords
    except Exception as e:
        print(f"LLM keyword generation failed: {e}")
    
    # Fallback to minimal keywords
    return get_fallback_keywords(device_type)

def get_llm_command_keywords(prompt, device_type):
    """
    Use LLM to generate show command keywords with descriptions
    """
    client = get_client()
    
    # Training examples for command keywords (not full commands)
    training_examples = {
        "cisco_ios": """
Training: Cisco IOS "show ?" command keywords:

When user types "show ?" on Cisco IOS, device responds with:
- access-lists: Access lists
- arp: ARP show commands  
- bgp: BGP show commands
- cdp: CDP information
- configuration: Contents of Non-Volatile memory
- controllers: Interface controllers status
- crypto: Encryption module
- debugging: State of each debugging option
- dhcp: Dynamic Host Configuration Protocol status
- environment: Environmental monitor
- flash: Display information about flash: file system
- history: Display the session command history
- hosts: IP domain-name, lookup style, nameservers, and host table
- interfaces: Interface status and configuration
- inventory: Show the physical inventory
- ip: IP information
- ipv6: IPv6 information
- line: TTY line information
- logging: Show the contents of logging buffers
- mac-address-table: MAC forwarding table
- memory: Memory statistics
- mpls: MPLS information
- ntp: Network time protocol
- ospf: OSPF information
- isis: IS-IS information
- platform: Show platform information
- processes: Active process statistics
- protocols: Active network routing protocols
- route-map: route-map information
- running-config: Current operating configuration
- snmp: SNMP statistics
- spanning-tree: Spanning tree topology
- startup-config: Contents of startup configuration
- tcp: Status of TCP connections
- users: Display information about terminal lines
- version: System hardware and software status
- vlan: VTP VLAN status
- vrf: VRF information
        """,
        
        "cisco_xr": """
Training: Cisco IOS-XR "show ?" command keywords:

When user types "show ?" on Cisco XR, device responds with:
- aaa: Show AAA configuration and operational data
- access-lists: Access lists
- adjacency: Adjacency information
- alarms: Show Alarms associated with XR
- arp: ARP show commands
- bgp: BGP information
- bridge: Bridge-domain information
- bundle: Bundle information
- cef: Cisco Express Forwarding
- configuration: Show configuration
- controllers: Show controller information
- crypto: Cryptographic subsystem
- dhcp: DHCP information
- environment: Show environmental information
- ethernet: Ethernet information
- hsrp: HSRP information
- interfaces: Show interface information
- inventory: Show the physical inventory
- ipv4: IPv4 configuration commands
- ipv6: IPv6 configuration commands
- isis: IS-IS Routing Information
- l2vpn: Show L2VPN information
- ldp: Show LDP related information
- lldp: Show LLDP information
- logging: Show the contents of logging buffers
- memory: Show memory usage
- mpls: MPLS show commands
- multicast-routing: IP multicast routing information
- ntp: Show NTP information
- ospf: OSPF show commands
- platform: Show platform information
- processes: Show process information
- redundancy: Show redundancy information
- route: Show route information
- running-config: Current operating configuration
- snmp: Show SNMP information
- tcp: Show TCP information
- version: Show version information
- vrf: Show VRF information
        """,
        
        "juniper_junos": """
Training: Juniper JunOS "show ?" command keywords:

When user types "show ?" on JunOS, device responds with:
- chassis: Chassis and chassis hardware information
- class-of-service: Class-of-service (CoS) information  
- configuration: Current configuration information
- firewall: Show firewall information
- interfaces: Interface information
- isis: Show IS-IS information
- ldp: Show LDP information
- log: Contents of log files
- mpls: Show MPLS information
- ospf: Show OSPF information
- pim: Show PIM information
- route: Routing table information
- rsvp: Show RSVP information
- security: Show security information
- snmp: Show SNMP information
- system: System information
- ted: Show TED information
- version: Software information
- vrrp: Show VRRP information
        """,
        
        "nokia_sros": """
Training: Nokia SR OS "show ?" command keywords:

When user types "show ?" on Nokia SR OS, device responds with:
- aggregate: Aggregate routes
- aps: APS information
- arp: ARP table
- bfd: BFD sessions and templates
- card: Card information
- chassis: Chassis and environment information
- dhcp: DHCP statistics and summary
- ecmp: ECMP configuration
- fib: Forwarding Information Base
- icmp6: ICMPv6 statistics
- interface: IP interface details
- isis: ISIS routes
- ldp: LDP bindings
- log: Log information
- mda: MDA information
- mvpn: Multicast VPN information
- neighbor: IPv6 neighbor table
- network-domains: Network domain table
- policy: Route policies
- pools: Pool information
- port: Port information
- route-table: Routing table
- router: Router configuration and status
- service: Service information
- static-arp: Static ARP entries
- static-route: Static routes
- status: Router and protocol status
- system: System information
- tunnel-table: Tunnel table
- version: Software version
        """
    }
    
    # Select training example
    examples = training_examples.get(device_type, training_examples["cisco_xr"])
    
    enhanced_prompt = f"""
You are simulating a {device_type} device's "show ?" help output.

{examples}

Generate ONLY the command keywords with descriptions, exactly like a real device would show.

Format: keyword: description
Return only the keyword list, nothing else.

User request: "{prompt}"

Keywords:"""

    try:
        completion = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "https://network-automation-tool.local",
                "X-Title": "Network Automation Parser",
            },
            model="openai/gpt-4o-mini",
            messages=[
                {
                    "role": "user",
                    "content": enhanced_prompt
                }
            ],
            temperature=0.1,
            max_tokens=1000,
        )
        
        # Parse the response to extract keyword-description pairs
        return parse_keyword_response(completion.choices[0].message.content.strip())
        
    except Exception as e:
        raise e

def parse_keyword_response(response):
    """
    Parse LLM response to extract keyword-description pairs
    """
    keywords = []

    lines = response.splitlines()
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
            
        # Remove bullet points or dashes at the start
        line = re.sub(r'^[-"*]\s*', '', line)
        
        # Look for "keyword: description" format
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                keyword = parts[0].strip().replace('_', '-')
                description = parts[1].strip()
                if keyword and description:
                    keywords.append((keyword, description))
    
    return keywords

def get_fallback_keywords(device_type):
    """
    Minimal fallback keywords for emergency cases
    """
    fallback_keywords = {
        "cisco_ios": [
            ("interfaces", "Interface status and configuration"),
            ("ip", "IP information"), 
            ("version", "System hardware and software status"),
            ("running-config", "Current operating configuration"),
            ("arp", "ARP show commands"),
            ("bgp", "BGP show commands"),
            ("ospf", "OSPF information"),
            ("isis", "IS-IS information"),
            ("eigrp", "EIGRP information"),
            ("cdp", "CDP information"),
            ("memory", "Memory statistics"),
            ("logging", "Show the contents of logging buffers")
        ],
        "cisco_xr": [
            ("interfaces", "Show interface information"),
            ("route", "Show route information"),
            ("version", "Show version information"),
            ("configuration", "Show configuration"),
            ("bgp", "BGP information"),
            ("ospf", "OSPF show commands"),
            ("isis", "IS-IS Routing Information"),
            ("lldp", "Show LLDP information"),
            ("platform", "Show platform information"),
            ("memory", "Show memory usage")
        ],
        "juniper_junos": [
            ("interfaces", "Interface information"),
            ("route", "Routing table information"),
            ("version", "Software information"),
            ("configuration", "Current configuration information"),
            ("system", "System information"),
            ("chassis", "Chassis and chassis hardware information"),
            ("log", "Contents of log files"),
            ("isis", "Show IS-IS information"),
            ("ospf", "Show OSPF information"),
            ("bgp", "Show BGP information")
        ],
        "nokia_sros": [
            ("port", "Port information"),
            ("router interface", "Interface information"),
            ("router route-table", "Routing table information"),
            ("version", "Software version"),
            ("router status", "Router and protocol status"),
            ("log log-id", "Log information"),
            ("chassis", "Chassis information"),
            ("card", "Card information"),
            ("mda", "MDA information"),
            ("isis", "ISIS routes"),
            ("ospf", "OSPF information"),
            ("bgp", "BGP information")
        ]
    }
    
    return fallback_keywords.get(device_type, fallback_keywords["cisco_xr"])

def get_llm_show_commands(prompt, device_type):
    """
    Use LLM with comprehensive training to generate actual show commands
    """
    # Normalize device type before using
    device_type = normalize_device_type(device_type)
    client = get_client()
    
    # Training context for actual commands
    training_context = create_command_training_context(device_type)
    
    enhanced_prompt = f"""
You are a network engineering AI trained extensively on {device_type} show commands.

{training_context}

Based on your training, analyze the user request and provide the most relevant show commands.

User request: "{prompt}"

Important guidelines:
1. Return only show commands, one per line
2. Use proper {device_type} syntax
3. For "all commands" requests, provide comprehensive coverage
4. Match user intent precisely
5. No explanations or extra text
6. If the prompt includes "up" with "interfaces", include filtering syntax like "| include up" for Cisco or "| match up" for JunOS/SR OS
7. If the prompt specifies a protocol like "isis", "bgp", "ospf", "eigrp", include relevant protocol-specific show commands
8. If the prompt asks for protocol configuration (e.g., "isis configure in running configuration"), show the running configuration for that protocol
9. For general natural language prompts about network status, routing, or configuration, generate fixed CLI commands based on common practices

Commands:"""

    try:
        completion = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "https://network-automation-tool.local",
                "X-Title": "Network Automation Parser",
            },
            model="openai/gpt-4o-mini",
            messages=[
                {
                    "role": "user",
                    "content": enhanced_prompt
                }
            ],
            temperature=0.15,
            max_tokens=800,
        )
        
        commands = extract_config_commands(completion.choices[0].message.content.strip())
        show_commands = [cmd for cmd in commands if cmd.lower().startswith('show') or (device_type == "nokia_sros" and cmd.lower().startswith('admin'))]
        
        # Quality filter - ensure commands make sense
        return filter_valid_commands(show_commands, device_type)
        
    except Exception as e:
        logging.error(f"LLM show commands failed: {e}")
        return []

def create_command_training_context(device_type):
    """
    Create rich training context based on device type for actual commands
    """
    contexts = {
        "cisco_ios": """
Training Data - Cisco IOS Show Commands:

Interface Management:
- "interface status" → show ip interface brief, show interfaces status
- "interfaces up" → show ip interface brief | include up, show interfaces status | include up
- "port errors" → show interfaces counters errors
- "interface utilization" → show interfaces counters
- "check interfaces" → show ip interface brief, show interfaces description
- "show ports" → show interfaces status

Routing and Protocols:
- "routing table" → show ip route, show ip route summary
- "bgp status" → show ip bgp summary, show ip bgp neighbors
- "bgp configuration" → show running-config | section router bgp
- "ospf info" → show ip ospf, show ip ospf neighbor, show ip ospf database
- "ospf configuration" → show running-config | section router ospf
- "isis info" → show isis neighbors, show isis database, show clns neighbors
- "isis configuration" → show running-config | section router isis
- "eigrp neighbors" → show ip eigrp neighbors, show ip eigrp topology
- "eigrp configuration" → show running-config | section router eigrp
- "check routing" → show ip protocols, show ip route

System Information:
- "system info" → show version, show inventory, show environment
- "memory usage" → show memory, show processes cpu
- "uptime" → show version | include uptime
- "check system health" → show processes cpu, show memory, show logging

Network Discovery:
- "neighbors" → show cdp neighbors detail, show lldp neighbors
- "arp table" → show arp, show ip arp

Security and Access:
- "access lists" → show access-lists, show ip access-lists
- "mac table" → show mac address-table, show mac address-table dynamic

VLAN and Switching:
- "vlan info" → show vlan brief, show vlan
- "spanning tree" → show spanning-tree, show spanning-tree summary

Logs and Troubleshooting:
- "logs" → show logging, show logging last 50
- "configuration" → show running-config, show startup-config
- "show config" → show running-config

All Commands Request:
- "all show commands" → [comprehensive list of all IOS show commands]
        """,
        
        "cisco_xr": """
Training Data - Cisco IOS-XR Show Commands:

Interface Management:
- "interface status" → show interfaces brief, show ipv4 interface brief
- "interfaces up" → show interfaces brief | include up, show ipv4 interface brief | include up
- "interface counters" → show interfaces counters
- "check interfaces" → show interfaces, show interfaces description
- "show ports" → show interfaces brief

Routing Protocols:  
- "routing table" → show route, show route summary, show route ipv4
- "bgp status" → show bgp summary, show bgp neighbors
- "bgp configuration" → show running-config router bgp
- "ospf info" → show ospf, show ospf neighbor, show ospf database
- "ospf configuration" → show running-config router ospf
- "isis info" → show isis neighbors, show isis database, show isis adjacency
- "isis configuration" → show running-config router isis
- "isis status" → show isis adjacency, show isis interface brief, show isis topology
- "check routing" → show route, show bgp summary, show ospf neighbor

System and Platform:
- "system info" → show version, show inventory
- "platform" → show platform, show environment
- "memory" → show memory summary, show processes cpu
- "redundancy" → show redundancy, show redundancy summary
- "check system health" → show platform, show memory summary, show logging

MPLS and L2VPN:
- "mpls info" → show mpls ldp neighbor, show mpls interfaces
- "l2vpn" → show l2vpn bridge-domain, show l2vpn forwarding

Configuration Management:
- "configuration" → show running-config, show configuration
- "commit history" → show configuration commit list, show configuration history
- "show config" → show running-config

Network Discovery:
- "neighbors" → show lldp neighbors detail, show cdp neighbors

Logs and Monitoring:
- "logs" → show logging, show logging last 50
- "alarms" → show alarms brief

All Commands Request:
- "all show commands" → [comprehensive list of all XR show commands]
        """,
        
        "juniper_junos": """
Training Data - Juniper JunOS Show Commands:

Interface Management:
- "interface status" → show interfaces terse, show interfaces extensive
- "interfaces up" → show interfaces terse | match "up.*up", show interfaces extensive | match "up.*up"
- "interface details" → show interfaces detail
- "check interfaces" → show interfaces terse, show interfaces description
- "show ports" → show interfaces terse

Routing:
- "routing table" → show route, show route summary
- "bgp status" → show bgp summary, show bgp neighbor
- "bgp configuration" → show configuration protocols bgp
- "ospf info" → show ospf neighbor, show ospf database
- "ospf configuration" → show configuration protocols ospf
- "isis info" → show isis adjacency, show isis database
- "isis configuration" → show configuration protocols isis
- "check routing" → show route, show bgp summary, show ospf neighbor

System Information:
- "system info" → show version, show chassis hardware
- "system status" → show system uptime, show chassis environment
- "check system health" → show system uptime, show chassis alarms, show log messages

Configuration:
- "configuration" → show configuration, show configuration | display set
- "commit history" → show system commit
- "show config" → show configuration

Network Services:
- "lldp neighbors" → show lldp neighbors, show lldp neighbors detail

Logs and Monitoring:
- "logs" → show log messages, show log messages | last 20

All Commands Request:
- "all show commands" → [comprehensive list of all JunOS show commands]
        """,
        
        "nokia_sros": """
Training Data - Nokia SR OS Show Commands:

Interface Management:
- "interface status" → show router interface, show port
- "interfaces up" → show router interface | match up, show port | match up
- "interface details" → show router interface detail, show port detail
- "port errors" → show port statistics
- "interface utilization" → monitor port rate interval 3, show router interface statistics
- "check interfaces" → show router interface, show port description
- "show ports" → show port

Routing and Protocols:
- "routing table" → show router route-table, show router route-table summary
- "bgp status" → show router bgp summary, show router bgp neighbor
- "bgp configuration" → show router bgp, admin display-config | match "bgp" context all
- "ospf info" → show router ospf neighbor, show router ospf database
- "ospf configuration" → show router ospf, admin display-config | match "ospf" context all
- "isis info" → show router isis adjacency, show router isis database, show router isis status
- "isis configuration" → show router isis, admin display-config | match "isis" context all
- "check routing" → show router route-table, show router status

System Information:
- "system info" → show version, show chassis, show card state
- "memory usage" → show system memory-pools
- "uptime" → show system uptime
- "check system health" → show system cpu, show system memory-pools, show log log-id 99

Network Discovery:
- "neighbors" → show router arp, show router neighbor
- "arp table" → show router arp

Security and Access:
- "access lists" → show router policy
- "mac table" → show service fdb-info (for services)

Logs and Troubleshooting:
- "logs" → show log log-id 99, show log log-id 99 | match pattern
- "configuration" → admin display-config, show bof
- "show config" → admin display-config

All Commands Request:
- "all show commands" → [comprehensive list of all SR OS show commands]
        """
    }
    
    return contexts.get(device_type, contexts["cisco_xr"])

def filter_valid_commands(commands, device_type):
    """
    Filter commands to ensure they're valid for the device type
    """
    if not commands:
        return []
    
    # Device-specific validation patterns
    valid_patterns = {
        "cisco_ios": [
            r"^show\s+",
            r"^show ip\s+",
            r"^show ipv6\s+",
            r"^show interfaces?\s+",
            r"^show running-config\s*(\|\s*(include|section)\s+\S+)?",
            r"^show version",
            r"^show mac\s+",
            r"^show vlan\s+",
        ],
        "cisco_xr": [
            r"^show\s+",
            r"^show ipv4\s+",
            r"^show ipv6\s+",
            r"^show interfaces?\s+",
            r"^show route\s+",
            r"^show bgp\s+",
            r"^show running-config\s*(\|\s*(include|section)\s+\S+)?",
            r"^show configuration\s+",
            r"^show platform\s+",
        ],
        "juniper_junos": [
            r"^show\s+",
            r"^show interfaces\s+",
            r"^show route\s+",
            r"^show configuration\s*(\|\s*match\s+\S+)?",
            r"^show chassis\s+",
            r"^show system\s+",
        ],
        "nokia_sros": [
            r"^show\s+",
            r"^show router\s+",
            r"^show port\s+",
            r"^show service\s+",
            r"^show log\s+",
            r"^show chassis\s+",
            r"^show card\s+",
            r"^show mda\s+",
            r"^show version",
            r"^admin display-config\s*(\|\s*match\s+\S+)?",
        ]
    }
    
    patterns = valid_patterns.get(device_type, valid_patterns["cisco_xr"])
    
    filtered = []
    for cmd in commands:
        cmd = cmd.strip()
        if any(re.match(pattern, cmd, re.IGNORECASE) for pattern in patterns):
            filtered.append(cmd)
    
    return filtered[:20]  # Limit results

def get_device_show_commands(prompt, device_info):
    """
    Map natural prompt to actual device show commands.
    Returns comprehensive command list for 'all show commands' requests.
    """
    device_type = normalize_device_type(device_info.get("device_type", "cisco_xr"))
    
    # Try LLM approach first for flexible natural language handling
    try:
        commands = get_llm_show_commands(prompt, device_type)
        if commands:
            return commands
    except Exception as e:
        print(f"LLM command generation failed: {e}")
    
    # Fallback to basic mapping
    return get_basic_fallback_commands(prompt, device_type)

def get_comprehensive_fallback_commands(device_type):
    """
    Comprehensive fallback command list for "all commands" requests
    """
    comprehensive_commands = {
        "cisco_ios": [
            "show version", "show running-config", "show ip interface brief | include up",
            "show interfaces", "show ip route", "show ip bgp summary",
            "show ip ospf neighbor", "show isis neighbors", "show cdp neighbors", 
            "show arp", "show mac address-table", "show vlan brief", 
            "show spanning-tree", "show memory", "show processes cpu", 
            "show logging", "show ip eigrp neighbors", "show running-config | section router isis",
            "show running-config | section router bgp", "show running-config | section router ospf",
            "show running-config | section router eigrp"
        ],
        "cisco_xr": [
            "show version", "show running-config", "show interfaces brief | include up",
            "show route", "show bgp summary", "show ospf neighbor",
            "show isis neighbors", "show isis database", "show lldp neighbors", 
            "show platform", "show memory summary", "show logging", 
            "show configuration commit list", "show mpls ldp neighbor",
            "show running-config router isis", "show running-config router bgp",
            "show running-config router ospf"
        ],
        "juniper_junos": [
            "show version", "show configuration", "show interfaces terse | match \"up.*up\"",
            "show route", "show bgp summary", "show ospf neighbor",
            "show isis adjacency", "show lldp neighbors", "show chassis hardware", 
            "show system uptime", "show log messages", "show configuration protocols isis",
            "show configuration protocols bgp", "show configuration protocols ospf"
        ],
        "nokia_sros": [
            "show version", "admin display-config", "show router interface | match up",
            "show router route-table", "show router bgp summary", 
            "show router ospf neighbor", "show router isis adjacency",
            "show router isis database", "show port | match up", "show chassis", 
            "show card state", "show log log-id 99", "show router arp",
            "admin display-config | match \"isis\" context all",
            "admin display-config | match \"bgp\" context all",
            "admin display-config | match \"ospf\" context all"
        ]
    }
    
    return comprehensive_commands.get(device_type, comprehensive_commands["cisco_xr"])

def get_basic_fallback_commands(prompt, device_type):
    """
    Basic fallback commands for specific requests with enhanced protocol detection
    """
    prompt_lower = prompt.lower()
    
    basic_commands = {
        "cisco_ios": {
            "interface": ["show ip interface brief | include up", "show interfaces status | include up"],
            "route": ["show ip route", "show ip route summary"], 
            "bgp": ["show ip bgp summary", "show ip bgp neighbors"],
            "bgp configuration": ["show running-config | section router bgp"],
            "ospf": ["show ip ospf neighbor", "show ip ospf database"],
            "ospf configuration": ["show running-config | section router ospf"],
            "isis": ["show isis neighbors", "show isis database", "show clns neighbors"],
            "isis configuration": ["show running-config | section router isis"],
            "eigrp": ["show ip eigrp neighbors", "show ip eigrp topology"],
            "eigrp configuration": ["show running-config | section router eigrp"],
            "vrf": ["show ip vrf", "show ip vrf detail"],
            "mpls": ["show mpls interfaces", "show mpls ldp neighbor"],
            "version": ["show version"],
            "config": ["show running-config"],
            "memory": ["show memory", "show processes cpu"],
            "log": ["show logging"],
            "arp": ["show arp", "show ip arp"],
            "mac": ["show mac address-table"],
            "vlan": ["show vlan brief"],
            "cdp": ["show cdp neighbors", "show cdp neighbors detail"],
            "lldp": ["show lldp neighbors", "show lldp neighbors detail"],
            "system health": ["show processes cpu", "show memory", "show logging"]
        },
        "cisco_xr": {
            "interface": ["show interfaces brief | include up", "show ipv4 interface brief | include up"],
            "route": ["show route", "show route summary"],
            "bgp": ["show bgp summary", "show bgp neighbors"], 
            "bgp configuration": ["show running-config router bgp"],
            "ospf": ["show ospf neighbor", "show ospf database"],
            "ospf configuration": ["show running-config router ospf"],
            "isis": ["show isis neighbors", "show isis database", "show isis adjacency"],
            "isis configuration": ["show running-config router isis"],
            "mpls": ["show mpls ldp neighbor", "show mpls interfaces", "show mpls forwarding"],
            "l2vpn": ["show l2vpn bridge-domain", "show l2vpn xconnect"],
            "vrf": ["show vrf all", "show vrf detail"],
            "version": ["show version"],
            "config": ["show running-config", "show configuration"],
            "memory": ["show memory summary", "show processes cpu"],
            "log": ["show logging"],
            "arp": ["show arp"],
            "platform": ["show platform", "show inventory"],
            "lldp": ["show lldp neighbors", "show lldp neighbors detail"],
            "redundancy": ["show redundancy", "show redundancy summary"],
            "system health": ["show platform", "show memory summary", "show logging"]
        },
        "juniper_junos": {
            "interface": ["show interfaces terse | match \"up.*up\"", "show interfaces extensive | match \"up.*up\""],
            "route": ["show route", "show route summary"],
            "bgp": ["show bgp summary", "show bgp neighbor"],
            "bgp configuration": ["show configuration protocols bgp"],
            "ospf": ["show ospf neighbor", "show ospf database"],
            "ospf configuration": ["show configuration protocols ospf"],
            "isis": ["show isis adjacency", "show isis database"],
            "isis configuration": ["show configuration protocols isis"],
            "mpls": ["show mpls lsp", "show mpls interface"],
            "ldp": ["show ldp neighbor", "show ldp session"],
            "version": ["show version"],
            "config": ["show configuration"],
            "log": ["show log messages"],
            "chassis": ["show chassis hardware", "show chassis environment"],
            "lldp": ["show lldp neighbors"],
            "system": ["show system uptime", "show system alarms"],
            "system health": ["show system uptime", "show chassis alarms", "show log messages"]
        },
        "nokia_sros": {
            "interface": ["show router interface | match up", "show port | match up"],
            "route": ["show router route-table", "show router route-table summary"],
            "bgp": ["show router bgp summary", "show router bgp neighbor"],
            "bgp configuration": ["show router bgp", "admin display-config | match \"bgp\" context all"],
            "ospf": ["show router ospf neighbor", "show router ospf database"],
            "ospf configuration": ["show router ospf", "admin display-config | match \"ospf\" context all"],
            "isis": ["show router isis adjacency", "show router isis database", "show router isis status"],
            "isis configuration": ["show router isis", "admin display-config | match \"isis\" context all"],
            "mpls": ["show router mpls interface", "show router mpls status"],
            "ldp": ["show router ldp session", "show router ldp bindings"],
            "vrf": ["show service service-using", "show router route-table"],
            "version": ["show version"],
            "config": ["admin display-config"],
            "log": ["show log log-id 99"],
            "arp": ["show router arp"],
            "chassis": ["show chassis", "show card"],
            "port": ["show port", "show port detail"],
            "system health": ["show system cpu", "show system memory-pools", "show log log-id 99"]
        }
    }
    
    commands_map = basic_commands.get(device_type, basic_commands["cisco_xr"])
    
    # Enhanced keyword matching with multi-word phrases
    keyword_phrases = {
        "isis": ["isis", "is-is", "is is", "intermediate system"],
        "isis configuration": ["isis configure", "isis config", "isis configuration", "isis in running configuration", "isis settings", "configured isis"],
        "bgp": ["bgp", "border gateway", "border gateway protocol"],
        "bgp configuration": ["bgp configure", "bgp config", "bgp configuration", "bgp in running configuration", "bgp settings", "configured bgp"],
        "ospf": ["ospf", "open shortest", "open shortest path first"],
        "ospf configuration": ["ospf configure", "ospf config", "ospf configuration", "ospf in running configuration", "ospf settings", "configured ospf"],
        "eigrp": ["eigrp", "enhanced interior"],
        "eigrp configuration": ["eigrp configure", "eigrp config", "eigrp configuration", "eigrp in running configuration", "eigrp settings", "configured eigrp"],
        "mpls": ["mpls", "label switching", "multiprotocol label switching"],
        "ldp": ["ldp", "label distribution"],
        "l2vpn": ["l2vpn", "layer 2 vpn", "l2 vpn"],
        "vrf": ["vrf", "virtual routing"],
        "interface": ["interface", "port status", "ports up", "which ports", "interfaces up", "interfaces down", "check interfaces", "interface status", "show ports"],
        "route": ["route", "routing table", "routes", "check routing"],
        "arp": ["arp", "address resolution"],
        "mac": ["mac", "mac address", "mac table"],
        "vlan": ["vlan", "virtual lan"],
        "cdp": ["cdp", "cisco discovery"],
        "lldp": ["lldp", "link layer discovery"],
        "version": ["version", "software version", "hardware version"],
        "config": ["config", "configuration", "show config", "running config", "startup config"],
        "memory": ["memory", "cpu", "resource", "memory usage"],
        "log": ["log", "syslog", "messages", "logs", "error logs"],
        "chassis": ["chassis", "hardware", "inventory"],
        "platform": ["platform", "system info"],
        "redundancy": ["redundancy", "failover", "high availability"],
        "system health": ["system health", "check system", "device health", "monitor system"]
    }
    
    # Check each phrase category
    for keyword, phrases in keyword_phrases.items():
        if any(phrase in prompt_lower for phrase in phrases):
            if keyword in commands_map:
                return commands_map[keyword]
    
    # Fallback: if asking about "status" or "check", try to determine what to check
    if any(word in prompt_lower for word in ["status", "check", "show", "display", "what"]):
        # Default to interface status
        return commands_map.get("interface", []) + commands_map.get("version", [])
    
    # Final fallback
    return commands_map.get("interface", [])

def get_action_from_prompt(prompt, device_type="cisco_xr"):
    """
    Generate device-specific CLI commands based on natural language prompt
    """
    client = get_client()
    
    # Normalize device type
    device_type = normalize_device_type(device_type)
    
    # Detect if this is a configuration request
    config_indicators = [
        'config', 'configure', 'set', 'create', 'add', 'enable', 'disable',
        'remove', 'delete', 'change', 'modify', 'assign', 'commit', 'vlan'
    ]
    
    show_indicators = [
        'show', 'display', 'get', 'list', 'check', 'view', 'what is'
    ]
    
    prompt_lower = prompt.lower()
    is_config_request = any(indicator in prompt_lower for indicator in config_indicators)
    is_show_request = any(indicator in prompt_lower for indicator in show_indicators) or not is_config_request  # Default to show if ambiguous
    
    # If it's clearly a show request, handle separately
    if is_show_request:
        device_info = {"device_type": device_type}
        commands = get_device_show_commands(prompt, device_info)
        if isinstance(commands, list) and commands:
            return "\n".join(commands) if isinstance(commands[0], str) else ""
        return ""
    
    # Configuration command generation - ENHANCED
    if device_type == "cisco_xr":
        system_instruction = """You are a Cisco IOS-XR configuration generator.

CRITICAL RULES:
- Output ONLY configuration commands
- NO explanations, NO comments, NO markdown
- Start with: configure
- End with: commit
- One command per line
- Use proper IOS-XR syntax
- For natural language prompts, generate fixed CLI config commands based on intent

Example request: "config vlan 10 on gig0/0/0/4"
Correct output:
configure
interface GigabitEthernet0/0/0/4.10
encapsulation dot1q 10
ipv4 address 10.10.1.1 255.255.255.0
no shutdown   
commit

Example request: "enable bgp with asn 65000"
Correct output:
configure
router bgp 65000
commit"""
    elif device_type == "juniper_junos":
        system_instruction = """You are a Juniper JunOS configuration generator.

CRITICAL RULES:
- Output ONLY configuration commands
- NO explanations, NO comments, NO markdown
- Start with: configure
- Use set commands for configuration
- End with: commit
- One command per line
- Use proper JunOS syntax
- For natural language prompts, generate fixed CLI config commands based on intent

Example request: "configure vlan 10"
Correct output:
configure
set vlans vlan10 vlan-id 10
commit

Example request: "enable ospf on interface ge-0/0/0"
Correct output:
configure
set protocols ospf area 0.0.0.0 interface ge-0/0/0
commit"""
    elif device_type == "nokia_sros":
        system_instruction = """You are a Nokia SR OS configuration generator.

CRITICAL RULES:
- Output ONLY configuration commands
- NO explanations, NO comments, NO markdown
- Start with: configure
- Use hierarchical commands
- End with: exit all
- One command per line
- Use proper SR OS syntax
- For natural language prompts, generate fixed CLI config commands based on intent

Example request: "configure interface to-ABC with IP 10.10.10.1/24 on port 1/1/1"
Correct output:
configure
router
interface "to-ABC"
address 10.10.10.1/24
port 1/1/1
exit
exit
exit all

Example request: "enable isis"
Correct output:
configure
router
isis
exit
exit
exit all"""
    else:  # Default to Cisco IOS
        system_instruction = """You are a Cisco IOS configuration generator.

CRITICAL RULES:
- Output ONLY configuration commands
- NO explanations, NO comments, NO markdown 
- Start with: configure terminal
- End with: end
- One command per line
- For natural language prompts, generate fixed CLI config commands based on intent

Example request: "configure vlan 10"
Correct output:
configure terminal
vlan 10
name DATA
end

Example request: "set ip on interface gig1/0 192.168.1.1/24"
Correct output:
configure terminal
interface GigabitEthernet1/0
ip address 192.168.1.1 255.255.255.0
no shutdown
end"""

    user_request = f"User request: {prompt}\n\nGenerate configuration commands:"

    try:
        completion = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "https://network-automation-tool.local",
                "X-Title": "Network Automation Parser",
            },
            model="openai/gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_request}
            ],
            temperature=0.05,  # Very low for consistency
            max_tokens=300,
        )
        
        response = completion.choices[0].message.content.strip()
        
        # Log for debugging
        logging.info(f"LLM Prompt: {prompt}")
        logging.info(f"LLM Response: {response[:300]}")
        
        return response
        
    except Exception as e:
        logging.error(f"LLM failed: {e}")
        # Fallback
        if device_type == "cisco_xr":
            return generate_xr_fallback(prompt)
        elif device_type == "nokia_sros":
            return generate_sros_fallback(prompt)
        elif device_type == "juniper_junos":
            return generate_junos_fallback(prompt)
        else:
            return ""

def generate_xr_fallback(prompt):
    """Template fallback for XR when LLM fails"""
    import re
    prompt_lower = prompt.lower()
    
    # Extract VLAN and interface
    vlan_match = re.search(r'vlan\s*(\d+)', prompt_lower)
    intf_match = re.search(r'gig[a-z]*\s*(\d+/\d+/\d+/\d+)', prompt_lower)
    
    if vlan_match and intf_match:
        vlan = vlan_match.group(1)
        intf = f"GigabitEthernet{intf_match.group(1)}"
        
        return f"""configure
interface {intf}.{vlan}
encapsulation dot1q {vlan}
ipv4 address 10.{vlan}.1.1 255.255.255.0
no shutdown
commit"""
    
    # Additional fallback for common config requests
    if "bgp" in prompt_lower:
        return f"""configure
router bgp 65000
commit"""
    elif "ospf" in prompt_lower:
        return f"""configure
router ospf 1
commit"""
    
    return f"configure\n! Could not parse: {prompt}\ncommit"

def generate_junos_fallback(prompt):
    """Template fallback for JunOS when LLM fails"""
    import re
    prompt_lower = prompt.lower()
    
    vlan_match = re.search(r'vlan\s*(\d+)', prompt_lower)
    
    if vlan_match:
        vlan = vlan_match.group(1)
        return f"""configure
set vlans vlan{vlan} vlan-id {vlan}
commit"""
    
    # Additional fallback
    if "bgp" in prompt_lower:
        return f"""configure
set protocols bgp group internal
commit"""
    elif "ospf" in prompt_lower:
        return f"""configure
set protocols ospf area 0.0.0.0
commit"""
    
    return f"configure\n# Could not parse: {prompt}\ncommit"

def generate_sros_fallback(prompt):
    """Template fallback for SR OS when LLM fails"""
    import re
    prompt_lower = prompt.lower()
    
    intf_match = re.search(r'interface\s*(\w+)', prompt_lower)
    ip_match = re.search(r'ip\s*(\d+\.\d+\.\d+\.\d+/\d+)', prompt_lower)
    port_match = re.search(r'port\s*(\d+/\d+/\d+)', prompt_lower)
    
    if intf_match and ip_match and port_match:
        intf = intf_match.group(1)
        ip = ip_match.group(1)
        port = port_match.group(1)
        
        return f"""configure
router
interface "{intf}"
address {ip}
port {port}
exit
exit
exit all"""
    
    # Additional fallback
    if "isis" in prompt_lower:
        return f"""configure
router
isis
exit
exit
exit all"""
    elif "bgp" in prompt_lower:
        return f"""configure
router
bgp
exit
exit
exit all"""
    
    return f"configure\n# Could not parse: {prompt}\nexit all"

def fallback_command_mapping(prompt, device_type, examples):
    """
    Fallback function that maps common phrases to commands without AI
    """
    prompt_lower = prompt.lower()
    
    # Common show command mappings
    if any(phrase in prompt_lower for phrase in ["ports are up", "interface status", "interfaces up", "which ports", "check interfaces", "show ports"]):
        if device_type == "nokia_sros":
            return "show router interface | match up"
        elif device_type == "cisco_xr":
            return "show interfaces brief | include up"
        elif device_type == "juniper_junos":
            return "show interfaces terse | match \"up.*up\""
        else:
            return "show ip interface brief | include up"
    elif any(phrase in prompt_lower for phrase in ["running config", "configuration", "config", "show config"]):
        if device_type == "nokia_sros":
            return "admin display-config"
        elif device_type == "juniper_junos":
            return "show configuration"
        else:
            return "show running-config"
    elif any(phrase in prompt_lower for phrase in ["isis configure", "isis config", "isis configuration", "isis in running configuration"]):
        if device_type == "nokia_sros":
            return "admin display-config | match \"isis\" context all"
        elif device_type == "juniper_junos":
            return "show configuration protocols isis"
        elif device_type == "cisco_xr":
            return "show running-config router isis"
        else:
            return "show running-config | section router isis"
    elif any(phrase in prompt_lower for phrase in ["bgp configure", "bgp config", "bgp configuration", "bgp in running configuration"]):
        if device_type == "nokia_sros":
            return "admin display-config | match \"bgp\" context all"
        elif device_type == "juniper_junos":
            return "show configuration protocols bgp"
        elif device_type == "cisco_xr":
            return "show running-config router bgp"
        else:
            return "show running-config | section router bgp"
    elif any(phrase in prompt_lower for phrase in ["ospf configure", "ospf config", "ospf configuration", "ospf in running configuration"]):
        if device_type == "nokia_sros":
            return "admin display-config | match \"ospf\" context all"
        elif device_type == "juniper_junos":
            return "show configuration protocols ospf"
        elif device_type == "cisco_xr":
            return "show running-config router ospf"
        else:
            return "show running-config | section router ospf"
    elif "isis" in prompt_lower:
        if device_type == "nokia_sros":
            return "show router isis adjacency"
        elif device_type == "juniper_junos":
            return "show isis adjacency"
        elif device_type == "cisco_xr":
            return "show isis neighbors"
        else:
            return "show isis neighbors"
    elif "bgp" in prompt_lower:
        if device_type == "nokia_sros":
            return "show router bgp summary"
        elif device_type == "juniper_junos":
            return "show bgp summary"
        elif device_type == "cisco_xr":
            return "show bgp summary"
        else:
            return "show ip bgp summary"
    elif "ospf" in prompt_lower:
        if device_type == "nokia_sros":
            return "show router ospf neighbor"
        elif device_type == "juniper_junos":
            return "show ospf neighbor"
        elif device_type == "cisco_xr":
            return "show ospf neighbor"
        else:
            return "show ip ospf neighbor"
    elif "eigrp" in prompt_lower:
        if device_type in ["cisco_ios", "cisco_xr"]:
            return "show ip eigrp neighbors"
        else:
            return "show ip route"  # Fallback as EIGRP is Cisco-specific
    elif "version" in prompt_lower:
        return "show version"
    elif any(phrase in prompt_lower for phrase in ["routes", "routing table", "route table", "check routing"]):
        if device_type == "nokia_sros" or device_type == "cisco_xr":
            return "show route" if device_type == "cisco_xr" else "show router route-table"
        elif device_type == "juniper_junos":
            return "show route"
        else:
            return "show ip route"
    elif "arp" in prompt_lower:
        if device_type == "nokia_sros":
            return "show router arp"
        else:
            return "show arp"
    elif any(phrase in prompt_lower for phrase in ["mac", "mac table", "mac address"]):
        if device_type == "nokia_sros":
            return "show service fdb-info"
        elif device_type == "cisco_xr":
            return "show l2vpn forwarding"
        elif device_type == "juniper_junos":
            return "show ethernet-switching table"
        else:
            return "show mac address-table"
    elif any(phrase in prompt_lower for phrase in ["system health", "check system", "device health"]):
        if device_type == "nokia_sros":
            return "show system cpu"
        elif device_type == "juniper_junos":
            return "show chassis alarms"
        elif device_type == "cisco_xr":
            return "show platform"
        else:
            return "show processes cpu"
    else:
        # Default to interface status for port-related queries
        if device_type == "nokia_sros":
            return "show router interface | match up"
        elif device_type == "cisco_xr":
            return "show interfaces brief | include up"
        elif device_type == "juniper_junos":
            return "show interfaces terse | match \"up.*up\""
        else:
            return "show ip interface brief | include up"

def extract_config_commands(response):
    """
    Extract commands - simplified and more lenient
    """
    if not response:
        return []
    
    lines = response.split('\n')
    commands = []
    
    for line in lines:
        line = line.strip()
        
        # Skip empty
        if not line:
            continue
        
        # Skip markdown code blocks
        if line.startswith('```'):
            continue
        
        # Skip pure comments (but allow inline comments after commands)
        if line.startswith(('#', '!', '//')):
            continue
        
        # Skip common headers/footers
        skip_patterns = [
            'output:', 'example:', 'note:', 'explanation:', 
            'configuration commands:', 'commands:', 'result:',
            'here are', 'here is', 'the following'
        ]
        if any(line.lower().startswith(pattern) for pattern in skip_patterns):
            continue
        
        # Remove device prompts (Router#, Switch>, etc)
        line = re.sub(r'^(Router|Switch|Device|RP/\d+)[>#]\s*', '', line)
        
        # Remove numbered list prefixes
        line = re.sub(r'^\d+[\.)]\s+', '', line)
        line = re.sub(r'^[-*•]\s+', '', line)
        
        # Remove inline comments but keep the command
        line = re.sub(r'\s+[#!].*', '', line)
        
        line = line.strip()
        
        # Accept if reasonable length and looks like a command
        if len(line) >= 2 and not line.startswith(('The ', 'This ', 'It ', 'A ')):
            commands.append(line)
    
    return commands

def explain_commands(commands, vendor="cisco"):
    """
    Simple explanation function that returns basic explanations for commands.
    Fallback for when rich explanations aren't available.
    
    Args:
        commands: List of command strings
        vendor: Device vendor (cisco, juniper, etc.)
    
    Returns:
        List of explanation strings
    """
    if not commands:
        return []
    
    client = get_client()
    
    # Build prompt for basic explanations
    commands_text = "\n".join(f"{i+1}. {cmd}" for i, cmd in enumerate(commands))
    
    prompt = f"""
You are a network engineer expert. Explain what each of these {vendor} commands does in one clear sentence.

Commands:
{commands_text}

Provide explanations in this format:
Command 1: [explanation]
Command 2: [explanation]
...

Keep explanations concise and technical.
"""

    try:
        completion = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "https://network-automation-tool.local",
                "X-Title": "Network Automation Parser",
            },
            model="openai/gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=1000,
        )
        
        response = completion.choices[0].message.content.strip()
        
        # Parse response into list
        explanations = []
        lines = response.split('\n')
        for line in lines:
            line = line.strip()
            if ':' in line and (line[0].isdigit() or line.lower().startswith('command')):
                # Extract explanation after colon
                parts = line.split(':', 1)
                if len(parts) == 2:
                    explanations.append(parts[1].strip())
        
        # Ensure we have an explanation for each command
        while len(explanations) < len(commands):
            explanations.append("Command execution")
            
        return explanations[:len(commands)]
        
    except Exception as e:
        logging.error(f"Command explanation failed: {e}")
        return ["Command execution"] * len(commands)

def explain_commands_rich(items, vendor="cisco"):
    """
    Rich explanation function that provides detailed context-aware explanations.
    Takes command + output pairs and returns structured explanations.
    
    Args:
        items: List of dicts with 'command' and 'output' keys
        vendor: Device vendor (cisco, juniper, etc.)
    
    Returns:
        List of dicts with structured explanations:
        {
            'command': str,
            'what_it_does': str,
            'how_to_use': str,
            'what_the_output_means': str,
            'key_points': [str, ...]
        }
    """
    if not items:
        return []
    
    client = get_client()
    
    explanations = []
    
    for item in items:
        cmd = item.get('command', '').strip()
        output = item.get('output', '').strip()
        
        if not cmd:
            continue
            
        # Truncate very long outputs
        output_preview = output[:2000] if len(output) > 2000 else output
        
        prompt = f"""
You are a network engineer expert analyzing {vendor} network device commands and their outputs.

Command: {cmd}

Output (preview):
{output_preview}

Provide a structured explanation with these sections:

1. WHAT IT DOES: One sentence explaining the command's purpose
2. HOW TO USE: Brief explanation of when/why to run this command
3. WHAT THE OUTPUT MEANS: Interpret the actual output shown above - what does it tell us?
4. KEY POINTS: 2-3 bullet points of important observations from this specific output

Format your response exactly like this:
WHAT IT DOES: [explanation]
HOW TO USE: [explanation]
WHAT THE OUTPUT MEANS: [explanation]
KEY POINTS:
- [point 1]
- [point 2]
- [point 3]
"""

        try:
            completion = client.chat.completions.create(
                extra_headers={
                    "HTTP-Referer": "https://network-automation-tool.local",
                    "X-Title": "Network Automation Parser",
                },
                model="openai/gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=800,
            )
            
            response = completion.choices[0].message.content.strip()
            
            # Parse structured response
            explanation = {
                'command': cmd,
                'what_it_does': '',
                'how_to_use': '',
                'what_the_output_means': '',
                'key_points': []
            }
            
            lines = response.split('\n')
            current_section = None
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                if line.startswith('WHAT IT DOES:'):
                    explanation['what_it_does'] = line.replace('WHAT IT DOES:', '').strip()
                    current_section = 'what_it_does'
                elif line.startswith('HOW TO USE:'):
                    explanation['how_to_use'] = line.replace('HOW TO USE:', '').strip()
                    current_section = 'how_to_use'
                elif line.startswith('WHAT THE OUTPUT MEANS:'):
                    explanation['what_the_output_means'] = line.replace('WHAT THE OUTPUT MEANS:', '').strip()
                    current_section = 'what_the_output_means'
                elif line.startswith('KEY POINTS:'):
                    current_section = 'key_points'
                elif line.startswith('-') or line.startswith('•'):
                    if current_section == 'key_points':
                        point = line.lstrip('-•').strip()
                        if point:
                            explanation['key_points'].append(point)
            
            explanations.append(explanation)
            
        except Exception as e:
            logging.error(f"Rich explanation failed for command '{cmd}': {e}")
            # Provide fallback explanation
            explanations.append({
                'command': cmd,
                'what_it_does': 'Network device command execution',
                'how_to_use': 'Run from device CLI in appropriate mode',
                'what_the_output_means': 'Output analysis unavailable',
                'key_points': ['Command executed successfully']
            })
    
    return explanations

def get_action_from_prompt_with_device(prompt, device_info=None):
    """
    Enhanced version that takes device info dict and uses appropriate device type.
    Main entry point for command generation.
    """
    if not device_info:
        device_info = {"device_type": "cisco_xr"}
    
    device_type = normalize_device_type(device_info.get("device_type", "cisco_xr"))
    prompt_lower = prompt.lower().strip()
    
    # Check if this looks like an exact command (literal pass-through)
    exact_command_keywords = ['show', 'display', 'ping', 'traceroute', 'telnet', 'ssh', 'configure']
    
    # If prompt starts with a command keyword and is short/direct, treat as literal
    words = prompt.strip().split()
    if words and words[0].lower() in exact_command_keywords:
        # Check if it looks like a literal command (short, no natural language)
        question_words = ['what', 'which', 'how', 'why', 'when', 'where', 'tell', 'give', 'provide', 'list', 'all', 'get', 'check']
        has_question_words = any(qw in prompt_lower for qw in question_words)
        
        # If it's short and has no question words, it's likely a literal command
        if not has_question_words and len(words) <= 6:
            logging.info(f"Treating as literal command: {prompt}")
            return prompt  # Return the command as-is
    
    # Check if this is a show/display command request (natural language)
    show_indicators = [
        "show", "display", "get", "list", "check status", 
        "what is", "tell me about", "provide information",
        "all commands", "give all", "which ports", "interface status",
        "check", "view", "see", "list out"
    ]
    
    if any(indicator in prompt_lower for indicator in show_indicators):
        # Use the device-specific show command generator
        logging.info(f"Processing as show command request for device: {device_type}")
        commands = get_device_show_commands(prompt, device_info)
        
        if isinstance(commands, list) and commands:
            if isinstance(commands[0], tuple):
                # Help keywords - format as help response
                return "Available commands:\n" + "\n".join([f"{k}: {d}" for k, d in commands])
            else:
                # Actual commands
                result = "\n".join(commands)
                logging.info(f"Generated {len(commands)} commands: {result[:100]}")
                return result
        else:
            logging.warning(f"No commands generated for prompt: {prompt}")
            # Return fallback
            return "\n".join(get_basic_fallback_commands(prompt, device_type))
    
    # Configuration commands
    logging.info(f"Processing as configuration request for device: {device_type}")
    return get_action_from_prompt(prompt, device_type)
