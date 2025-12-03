#!/usr/bin/env python3
#
# OPNsense Monitoring Plugin for openITCOCKPIT
#
# This script monitors CPU Load (1-min avg), Memory Usage, and Disk Usage
# on an OPNsense firewall via its built-in API.
#
# Usage:
# python3 check_opnsense_stats.py \
#   --host <OPNsense_IP_or-Hostname> \
#   --key <API_Key> \
#   --secret <API_Secret> \
#   --cpu-warn 5.0 --cpu-crit 10.0 \
#   --mem-warn 75 --mem-crit 90 \
#   --disk-warn 80 --disk-crit 95
#
# Output format: <STATUS> - <Message> | <Perfdata>
# Exit codes: 0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN
#

import requests
import json
import sys
import argparse

# --- Configuration ---
# Default thresholds for Warning and Critical states
DEFAULT_CPU_WARN = 5.0
DEFAULT_CPU_CRIT = 10.0
DEFAULT_MEM_WARN = 75  # %
DEFAULT_MEM_CRIT = 90  # %
DEFAULT_DISK_WARN = 80 # %
DEFAULT_DISK_CRIT = 95 # %

# API Endpoints
API_SYSTEM_RESOURCES = "/api/diagnostics/system/system_resources"
API_SYSTEM_DISK = "/api/diagnostics/system/system_disk"

# Relevant mount points to check for monitoring.
PRIMARY_MOUNT_POINTS = ('/', '/usr', '/var', '/home', '/cf', '/var/log')


def parse_args():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="OPNsense Monitoring Plugin for openITCOCKPIT (Nagios/Icinga format)."
    )
    parser.add_argument('--host', required=True, help='OPNsense IP address or hostname.')
    parser.add_argument('--key', required=True, help='OPNsense API Key.')
    parser.add_argument('--secret', required=True, help='OPNsense API Secret.')
    parser.add_argument('--port', default=443, type=int, help='OPNsense API port (default: 443).')

    # Thresholds
    parser.add_argument('--cpu-warn', type=float, default=DEFAULT_CPU_WARN, help=f'CPU 1-min Load Avg Warning threshold (default: {DEFAULT_CPU_WARN}).')
    parser.add_argument('--cpu-crit', type=float, default=DEFAULT_CPU_CRIT, help=f'CPU 1-min Load Avg Critical threshold (default: {DEFAULT_CPU_CRIT}).')
    parser.add_argument('--mem-warn', type=float, default=DEFAULT_MEM_WARN, help=f'Memory Usage %% Warning threshold (default: {DEFAULT_MEM_WARN}).')
    parser.add_argument('--mem-crit', type=float, default=DEFAULT_MEM_CRIT, help=f'Memory Usage %% Critical threshold (default: {DEFAULT_MEM_CRIT}).')
    parser.add_argument('--disk-warn', type=float, default=DEFAULT_DISK_WARN, help=f'Disk Usage %% Warning threshold (default: {DEFAULT_DISK_WARN}).')
    parser.add_argument('--disk-crit', type=float, default=DEFAULT_DISK_CRIT, help=f'Disk Usage %% Critical threshold (default: {DEFAULT_DISK_CRIT}).')
    
    return parser.parse_args()


def make_api_call(host, port, key, secret, endpoint):
    """Makes an authenticated API call to OPNsense."""
    url = f"https://{host}:{port}{endpoint}"
    # Hardcoded timeout back to 15 seconds
    TIMEOUT = 15
    try:
        # Use Basic Authentication with API Key and Secret
        # verify=False is used for self-signed certificates, common in OPNsense setups.
        response = requests.get(url, auth=(key, secret), verify=False, timeout=TIMEOUT)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        # Improved error message for network issues including timeouts
        if isinstance(e, requests.exceptions.Timeout):
             print(f"UNKNOWN - API call timed out after {TIMEOUT} seconds for {endpoint}. Check network connectivity and OPNsense load.")
        else:
             print(f"UNKNOWN - API call failed to {endpoint}: {e}")
        sys.exit(3)
    except json.JSONDecodeError:
        # Include a snippet of the response text for easier debugging of malformed JSON
        print(f"UNKNOWN - Failed to decode JSON response from {endpoint}: {response.text[:100]}... Is the API key/secret correct?")
        sys.exit(3)
    except Exception as e:
        print(f"UNKNOWN - An unexpected error occurred during API call to {endpoint}: {e}")
        sys.exit(3)


def check_threshold(value, warn, crit):
    """Determines the status (OK, WARNING, CRITICAL) based on thresholds."""
    if value >= crit:
        return 2, "CRITICAL"
    elif value >= warn:
        return 1, "WARNING"
    else:
        return 0, "OK"


def main():
    """Main function to execute the checks and output results."""
    args = parse_args()
    
    overall_status = 0
    message_parts = []
    perfdata_parts = []

    # --- 1. CPU and Memory Check (using system_resources) ---
    # Removed args.timeout
    sys_data = make_api_call(args.host, args.port, args.key, args.secret, API_SYSTEM_RESOURCES)
    
    # --- CPU Load (1-minute average) ---
    try:
        # OPNsense returns load average as a string "0.10, 0.15, 0.20"
        load_avg_str = sys_data.get('load_average', '0.0,0.0,0.0')
        load_avg = [float(x.strip()) for x in load_avg_str.split(',')]
        
        cpu_load_1min = load_avg[0]
        cpu_status, cpu_status_str = check_threshold(cpu_load_1min, args.cpu_warn, args.cpu_crit)

        overall_status = max(overall_status, cpu_status)
        message_parts.append(f"CPU Load 1-min: {cpu_load_1min:.2f} ({cpu_status_str})")
        perfdata_parts.append(f"'cpu_load_1min'={cpu_load_1min:.2f};{args.cpu_warn};{args.cpu_crit};0.0;")
    except (KeyError, IndexError, ValueError):
        message_parts.append("CPU Load data UNAVAILABLE")
        overall_status = max(overall_status, 3) # UNKNOWN

    # --- Memory Usage ---
    try:
        # Expected fields: total, used, free in bytes.
        mem_total = int(sys_data['memory']['total'])
        mem_used = int(sys_data['memory']['used'])
        
        if mem_total > 0:
            mem_usage_pct = (mem_used / mem_total) * 100
            mem_status, mem_status_str = check_threshold(mem_usage_pct, args.mem_warn, args.mem_crit)
            
            overall_status = max(overall_status, mem_status)
            message_parts.append(f"Memory: {mem_usage_pct:.1f}% ({mem_status_str})")
            perfdata_parts.append(f"'mem_usage_pct'={mem_usage_pct:.1f}%;{args.mem_warn};{args.mem_crit};0;100")
            perfdata_parts.append(f"'mem_used_bytes'={mem_used}B")
            perfdata_parts.append(f"'mem_total_bytes'={mem_total}B")

        else:
            message_parts.append("Memory data UNAVAILABLE (Total=0)")
            overall_status = max(overall_status, 3)
            
    except (KeyError, ValueError):
        message_parts.append("Memory data UNAVAILABLE")
        overall_status = max(overall_status, 3) # UNKNOWN


    # --- 2. Disk Usage Check (using system_disk) ---
    # Removed args.timeout
    disk_data = make_api_call(args.host, args.port, args.key, args.secret, API_SYSTEM_DISK)
    
    processed_filesystems = 0
    available_mounts = []

    # Iterate over all filesystems using the 'devices' key as confirmed by cURL output.
    for fs in disk_data.get('devices', []): 
        mountpoint = fs.get('mountpoint')
        
        # Only process filesystems that are considered primary storage.
        if mountpoint in PRIMARY_MOUNT_POINTS:
            available_mounts.append(mountpoint)
            
            try:
                # Use 'used_pct' as the capacity percentage, as confirmed by the API output.
                disk_capacity_pct = float(fs.get('used_pct', 0))
                
                disk_status, disk_status_str = check_threshold(disk_capacity_pct, args.disk_warn, args.disk_crit)
                
                overall_status = max(overall_status, disk_status)
                
                # Use a specific label for perfdata (e.g., disk_root_pct for /)
                perfdata_label = mountpoint.replace('/', '_').strip('_') or 'root' 
                
                message_parts.append(f"Disk {mountpoint}: {disk_capacity_pct:.1f}% ({disk_status_str})")
                perfdata_parts.append(f"'disk_{perfdata_label}_pct'={disk_capacity_pct:.1f}%;{args.disk_warn};{args.disk_crit};0;100")
                
                # NOTE: The OPNsense API response for disk usage provided by the user 
                # returns used/total fields (e.g., "4.1G") as strings with units, 
                # which cannot be reliably parsed as bytes (B) here without a unit converter.
                # Perfdata for bytes is excluded to avoid ValueError.
                
                processed_filesystems += 1
                
            except (KeyError, ValueError, TypeError):
                message_parts.append(f"Disk {mountpoint} data UNKNOWN (Parsing error on 'used_pct')")
                overall_status = max(overall_status, 3) # UNKNOWN

    # If no relevant filesystems were found, output a specific UNKNOWN message
    if processed_filesystems == 0:
        # Collect all non-device/non-temporary mount points for debugging feedback
        all_api_mounts = [
            fs.get('mountpoint') for fs in disk_data.get('devices', []) 
            if fs.get('mountpoint') and not fs.get('mountpoint').startswith(('/dev', '/proc', '/tmp', '/var/run'))
        ]
        mount_list_str = ", ".join(all_api_mounts) if all_api_mounts else "None"

        message_parts.append(f"Disk check UNKNOWN: No primary filesystem found ({PRIMARY_MOUNT_POINTS}). Available mounts: [{mount_list_str}]")
        overall_status = max(overall_status, 3) # UNKNOWN

    # --- Final Output ---
    
    STATUS_MAP = {
        0: "OK",
        1: "WARNING",
        2: "CRITICAL",
        3: "UNKNOWN"
    }
    
    final_status_text = STATUS_MAP.get(overall_status, "UNKNOWN")
    final_message = " | ".join(message_parts)
    final_perfdata = " ".join(perfdata_parts)
    
    print(f"{final_status_text} - {final_message} | {final_perfdata}")
    sys.exit(overall_status)


if __name__ == '__main__':
    # Disable SSL warnings because 'verify=False' is used (needed if OPNsense uses self-signed certs)
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    main()
