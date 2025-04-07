import json
import subprocess
import os
import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import requests
import shutil  # to check if tshark is in PATH

# ---------------------------
# CONFIGURATION & SETUP
# ---------------------------

# Configure logging to show info on the console as well as in a log file.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='llm_packet_analyzer.log',
    filemode='a'
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# Set up file paths (use raw strings or double backslashes on Windows)
pcap_path = r"4.pcap"  # Update to your actual file
json_path = r"q.json"
dataset_out = r"llm_enhanced_dataset.json"

# LM Studio server configuration (adjust port if needed)
LM_STUDIO_URL = "http://10.5.0.2:1234/v1/chat/completions"

# Configure which LLM to use - DeepSeek Coder is recommended for technical analysis
LLM_CONFIG = {
    "model": "deepseek-coder-v2-lite-instruct",  # Identifier for DeepSeek Coder
    "temperature": 0.2,       # Low temperature for more focused, deterministic outputs
    "max_tokens": 1024,       # Generous token limit for detailed analysis
    "top_p": 0.95,
    "timeout": 60             # Timeout in seconds
}

# ---------------------------
# HELPER FUNCTIONS
# ---------------------------

def verify_file(file_path: str, description: str) -> bool:
    """Verify that a file exists and print its details."""
    if os.path.exists(file_path):
        size = os.path.getsize(file_path)
        msg = f"{description} exists: {file_path} (size: {size} bytes)"
        logging.info(msg)
        print(f"[INFO] {msg}")
        return True
    else:
        msg = f"{description} not found: {file_path}"
        logging.error(msg)
        print(f"[ERROR] {msg}")
        return False

def check_tshark_installed() -> bool:
    """Check if tshark is available in the system PATH."""
    if shutil.which("tshark") is None:
        msg = "tshark executable not found in PATH. Please install Wireshark and add tshark to PATH."
        logging.error(msg)
        print(f"[ERROR] {msg}")
        return False
    logging.info("tshark is installed and found in PATH.")
    return True

def extract_pcap_to_json(pcap_path: str, json_path: str) -> bool:
    """Extract PCAP to JSON using tshark with detailed options."""
    if not os.path.exists(pcap_path):
        msg = f"PCAP file not found: {pcap_path}"
        logging.error(msg)
        print(f"[ERROR] {msg}")
        return False

    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "json",
        "-x",  # Include hex dumps
        "-V"   # Verbose output
    ]
    
    logging.info(f"Converting {pcap_path} to JSON using command: {' '.join(cmd)}")
    try:
        with open(json_path, "w") as outfile:
            result = subprocess.run(cmd, stdout=outfile, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            msg = f"tshark conversion failed: {result.stderr}"
            logging.error(msg)
            print(f"[ERROR] {msg}")
            return False
        logging.info(f"Successfully converted PCAP to JSON at {json_path}")
    except Exception as e:
        logging.exception(f"Exception during tshark conversion: {e}")
        print(f"[ERROR] Exception during tshark conversion: {e}")
        return False

    # Verify that the JSON file was created and is non-empty.
    return verify_file(json_path, "JSON output file")

def get_protocol_hierarchy(frame_info: Dict) -> List[str]:
    """Extract the protocol stack from frame data."""
    if 'frame' in frame_info and 'frame.protocols' in frame_info['frame']:
        return frame_info['frame']['frame.protocols'].split(':')
    return []

def get_field_safely(data: Dict, field_path: str, default: str = "N/A") -> Any:
    """Safely extract fields from nested dictionary structure."""
    current = data
    for part in field_path.split('.'):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current

def extract_packet_details(frame_info: Dict) -> Dict[str, Any]:
    """Extract comprehensive packet details based on protocol."""
    protocols = get_protocol_hierarchy(frame_info)
    
    # Basic frame information
    details = {
        "timestamp": get_field_safely(frame_info, 'frame.frame.time'),
        "frame_number": get_field_safely(frame_info, 'frame.frame.number'),
        "length": get_field_safely(frame_info, 'frame.frame.len'),
        "protocols": protocols,
        "protocol_names": ", ".join(protocols)
    }
    
    # Ethernet layer
    if 'eth' in frame_info:
        details["eth"] = {
            "src_mac": get_field_safely(frame_info, 'eth.eth.src'),
            "dst_mac": get_field_safely(frame_info, 'eth.eth.dst'),
            "type": get_field_safely(frame_info, 'eth.eth.type')
        }
    
    # IPv4
    if 'ip' in frame_info:
        details["ip"] = {
            "src": get_field_safely(frame_info, 'ip.ip.src'),
            "dst": get_field_safely(frame_info, 'ip.ip.dst'),
            "ttl": get_field_safely(frame_info, 'ip.ip.ttl'),
            "id": get_field_safely(frame_info, 'ip.ip.id'),
            "flags": get_field_safely(frame_info, 'ip.ip.flags'),
            "version": get_field_safely(frame_info, 'ip.ip.version')
        }
    
    # IPv6
    if 'ipv6' in frame_info:
        details["ipv6"] = {
            "src": get_field_safely(frame_info, 'ipv6.ipv6.src'),
            "dst": get_field_safely(frame_info, 'ipv6.ipv6.dst'),
            "hlim": get_field_safely(frame_info, 'ipv6.ipv6.hlim'),
            "plen": get_field_safely(frame_info, 'ipv6.ipv6.plen'),
            "version": get_field_safely(frame_info, 'ipv6.ipv6.version')
        }
    
    # TCP
    if 'tcp' in frame_info:
        details["tcp"] = {
            "srcport": get_field_safely(frame_info, 'tcp.tcp.srcport'),
            "dstport": get_field_safely(frame_info, 'tcp.tcp.dstport'),
            "flags": get_field_safely(frame_info, 'tcp.tcp.flags'),
            "seq": get_field_safely(frame_info, 'tcp.tcp.seq'),
            "ack": get_field_safely(frame_info, 'tcp.tcp.ack'),
            "window_size": get_field_safely(frame_info, 'tcp.tcp.window_size'),
            "len": get_field_safely(frame_info, 'tcp.tcp.len')
        }
        # Enhanced flag interpretation
        flag_value = get_field_safely(frame_info, 'tcp.tcp.flags')
        if flag_value != "N/A":
            flag_dict = {}
            if 'tcp.flags' in frame_info['tcp']:
                tcp_flags = str(frame_info['tcp']['tcp.flags'])
                flag_dict = {
                    "syn": "1" if "SYN" in tcp_flags else "0",
                    "ack": "1" if "ACK" in tcp_flags else "0",
                    "fin": "1" if "FIN" in tcp_flags else "0",
                    "rst": "1" if "RST" in tcp_flags else "0",
                    "psh": "1" if "PSH" in tcp_flags else "0",
                    "urg": "1" if "URG" in tcp_flags else "0"
                }
            details["tcp"]["flags_decoded"] = flag_dict
    
    # UDP
    if 'udp' in frame_info:
        details["udp"] = {
            "srcport": get_field_safely(frame_info, 'udp.udp.srcport'),
            "dstport": get_field_safely(frame_info, 'udp.udp.dstport'),
            "length": get_field_safely(frame_info, 'udp.udp.length'),
            "checksum": get_field_safely(frame_info, 'udp.udp.checksum')
        }
    
    # ICMP
    if 'icmp' in frame_info:
        details["icmp"] = {
            "type": get_field_safely(frame_info, 'icmp.icmp.type'),
            "code": get_field_safely(frame_info, 'icmp.icmp.code'),
            "checksum": get_field_safely(frame_info, 'icmp.icmp.checksum')
        }
    
    # ARP
    if 'arp' in frame_info:
        details["arp"] = {
            "opcode": get_field_safely(frame_info, 'arp.arp.opcode'),
            "src_proto_ipv4": get_field_safely(frame_info, 'arp.arp.src.proto_ipv4'),
            "dst_proto_ipv4": get_field_safely(frame_info, 'arp.arp.dst.proto_ipv4'),
            "src_hw_mac": get_field_safely(frame_info, 'arp.arp.src.hw_mac'),
            "dst_hw_mac": get_field_safely(frame_info, 'arp.arp.dst.hw_mac')
        }
    
    # DNS
    if 'dns' in frame_info:
        dns_data = {
            "id": get_field_safely(frame_info, 'dns.dns.id'),
            "flags": get_field_safely(frame_info, 'dns.dns.flags'),
            "response": "1" if "dns.flags.response" in str(frame_info) else "0"
        }
        queries = []
        answers = []
        if 'Queries' in frame_info.get('dns', {}):
            for query_key, query_value in frame_info['dns']['Queries'].items():
                if isinstance(query_value, dict) and 'dns.qry.name' in query_value:
                    queries.append({
                        "name": query_value['dns.qry.name'],
                        "type": get_field_safely(query_value, 'dns.qry.type')
                    })
        if 'Answers' in frame_info.get('dns', {}):
            for answer_key, answer_value in frame_info['dns']['Answers'].items():
                if isinstance(answer_value, dict):
                    answer = {
                        "name": get_field_safely(answer_value, 'dns.resp.name', ''),
                        "type": get_field_safely(answer_value, 'dns.resp.type', ''),
                        "ttl": get_field_safely(answer_value, 'dns.resp.ttl', '')
                    }
                    if 'dns.a' in answer_value:
                        answer["ip"] = answer_value['dns.a']
                    answers.append(answer)
        dns_data["queries"] = queries
        dns_data["answers"] = answers
        details["dns"] = dns_data
    
    # HTTP
    if 'http' in frame_info:
        http_data = {}
        request_method = get_field_safely(frame_info, 'http.http.request.method')
        if request_method != "N/A":
            http_data["request"] = {
                "method": request_method,
                "uri": get_field_safely(frame_info, 'http.http.request.uri'),
                "version": get_field_safely(frame_info, 'http.http.request.version')
            }
            headers = {}
            if 'http.request.line' in frame_info['http']:
                for key, value in frame_info['http'].items():
                    if key.startswith('http.') and not key.startswith('http.request') and not key.startswith('http.response'):
                        header_name = key.replace('http.', '')
                        headers[header_name] = value
            http_data["request"]["headers"] = headers
        response_code = get_field_safely(frame_info, 'http.http.response.code')
        if response_code != "N/A":
            http_data["response"] = {
                "code": response_code,
                "phrase": get_field_safely(frame_info, 'http.http.response.phrase'),
                "version": get_field_safely(frame_info, 'http.http.response.version')
            }
        details["http"] = http_data
    
    # DHCP/DHCPv6
    if 'dhcp' in frame_info:
        details["dhcp"] = {
            "msgtype": get_field_safely(frame_info, 'dhcp.dhcp.type'),
            "client_mac": get_field_safely(frame_info, 'dhcp.dhcp.hw.mac_addr'),
            "client_ip": get_field_safely(frame_info, 'dhcp.dhcp.client_ip'),
            "your_ip": get_field_safely(frame_info, 'dhcp.dhcp.your_ip')
        }
    elif 'dhcpv6' in frame_info:
        details["dhcpv6"] = {
            "msgtype": get_field_safely(frame_info, 'dhcpv6.dhcpv6.msgtype'),
            "xid": get_field_safely(frame_info, 'dhcpv6.dhcpv6.xid')
        }
    
    # Try to extract payload data if available
    for proto in ['data', 'tcp', 'udp']:
        if proto in frame_info and f'{proto}.payload' in frame_info[proto]:
            details["payload"] = frame_info[proto][f'{proto}.payload']
            break
    
    return details

def create_analysis_prompt(packet_details: Dict[str, Any]) -> str:
    """Create a prompt for the LLM based on packet details."""
    prompt = f"""
I need you to analyze this network packet and explain what's happening in technical detail.

PACKET DETAILS:
Frame #: {packet_details.get('frame_number')}
Timestamp: {packet_details.get('timestamp')}
Protocols: {packet_details.get('protocol_names')}
Frame Length: {packet_details.get('length')} bytes
"""
    for proto in ['eth', 'ip', 'ipv6', 'tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'dhcp', 'dhcpv6']:
        if proto in packet_details:
            prompt += f"\n{proto.upper()} LAYER:\n"
            for key, value in packet_details[proto].items():
                if isinstance(value, dict):
                    prompt += f"- {key}:\n"
                    for subkey, subvalue in value.items():
                        prompt += f"  - {subkey}: {subvalue}\n"
                elif isinstance(value, list) and value:
                    prompt += f"- {key}:\n"
                    for item in value:
                        if isinstance(item, dict):
                            for subkey, subvalue in item.items():
                                prompt += f"  - {subkey}: {subvalue}\n"
                        else:
                            prompt += f"  - {item}\n"
                else:
                    prompt += f"- {key}: {value}\n"
    
    if "payload" in packet_details:
        payload = packet_details["payload"]
        if len(payload) > 200:
            payload = payload[:200] + "... [truncated]"
        prompt += f"\nPAYLOAD:\n{payload}\n"
    
    prompt += """
Please provide a detailed technical analysis of this packet, including:
1. What exactly is happening in this communication.
2. The purpose and function of this packet in the network conversation.
3. Any notable characteristics, flags, or patterns.
4. Potential security implications (if any).
5. Context about the protocols involved.

Format your response as a clear, detailed explanation suitable for a network analyst.
"""
    return prompt

def query_lm_studio(packet_details: Dict[str, Any]) -> Optional[str]:
    """Send packet data to LM Studio server and get analysis."""
    prompt = create_analysis_prompt(packet_details)
    payload = {
        "model": LLM_CONFIG["model"],
        "messages": [
            {"role": "system", "content": "You are a network security expert analyzing packet captures. Provide detailed, technical analysis of network packets explaining exactly what is happening, potential security implications, and context about the protocols involved."},
            {"role": "user", "content": prompt}
        ],
        "temperature": LLM_CONFIG["temperature"],
        "max_tokens": LLM_CONFIG["max_tokens"],
        "top_p": LLM_CONFIG["top_p"]
    }
    
    logging.info(f"Querying LM Studio for packet {packet_details.get('frame_number')}")
    try:
        response = requests.post(
            LM_STUDIO_URL,
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=LLM_CONFIG["timeout"]
        )
        if response.status_code == 200:
            result = response.json()
            if "choices" in result and len(result["choices"]) > 0:
                analysis = result["choices"][0]["message"]["content"]
                logging.debug(f"LLM Analysis for packet {packet_details.get('frame_number')}: {analysis}")
                return analysis
            else:
                msg = f"Unexpected response format from LM Studio: {result}"
                logging.warning(msg)
                print(f"[WARNING] {msg}")
        else:
            msg = f"Error from LM Studio API: {response.status_code} - {response.text}"
            logging.error(msg)
            print(f"[ERROR] {msg}")
    except requests.exceptions.RequestException as e:
        msg = f"Request exception when querying LM Studio: {e}"
        logging.error(msg)
        print(f"[ERROR] {msg}")
    except Exception as e:
        logging.exception(f"Unexpected error in LLM query: {e}")
        print(f"[ERROR] Unexpected error in LLM query: {e}")
    return None

def create_dataset():
    """Create training dataset with LLM-enhanced analysis."""
    logging.info("----- Starting dataset creation process -----")
    
    # Check if tshark is installed
    if not check_tshark_installed():
        print("[!] tshark is not installed or not in PATH. Exiting.")
        return

    # Verify the PCAP file exists
    if not verify_file(pcap_path, "PCAP file"):
        print("[!] PCAP file is missing. Exiting.")
        return

    # Extract PCAP to JSON
    if not extract_pcap_to_json(pcap_path, json_path):
        logging.error("Failed to extract PCAP data. Exiting dataset creation.")
        print("[ERROR] PCAP extraction failed. Exiting.")
        return

    # Verify JSON file after extraction
    if not verify_file(json_path, "JSON output file"):
        print("[ERROR] JSON output file is missing or empty. Exiting.")
        return

    # Load JSON data
    logging.info(f"Loading packet data from {json_path}")
    try:
        with open(json_path, "r") as f:
            packet_data = json.load(f)
    except json.JSONDecodeError as e:
        msg = f"Failed to parse JSON from {json_path}: {e}"
        logging.error(msg)
        print(f"[ERROR] {msg}")
        return
    except FileNotFoundError:
        msg = f"JSON file {json_path} not found."
        logging.error(msg)
        print(f"[ERROR] {msg}")
        return

    # Check LM Studio server health and list available models
    try:
        test_response = requests.get("http://10.5.0.2:1234/v1/models", timeout=5)
        if test_response.status_code != 200:
            msg = "LM Studio API is not responding correctly. Ensure it's running on port 1234."
            logging.error(msg)
            print(f"[ERROR] {msg}")
            return
        models_info = test_response.json()
        logging.info(f"LM Studio API is available. Models: {models_info}")
        print(f"[INFO] LM Studio API is available. Models: {models_info}")
    except requests.exceptions.RequestException as e:
        msg = f"Could not connect to LM Studio API: {e}"
        logging.error(msg)
        print(f"[ERROR] {msg}")
        return

    dataset = []
    skipped = 0
    processed = 0
    total_packets = len(packet_data)
    logging.info(f"Processing {total_packets} packets from JSON data.")
    print(f"[*] Starting processing of {total_packets} packets with LLM analysis...")

    for i, packet in enumerate(packet_data):
        try:
            frame_info = packet.get('_source', {}).get('layers', {})
            if not frame_info or not isinstance(frame_info, dict):
                skipped += 1
                msg = f"Skipping packet at index {i}: missing or invalid frame info."
                logging.debug(msg)
                print(f"[WARNING] {msg}")
                continue

            # Extract packet details
            packet_details = extract_packet_details(frame_info)
            logging.debug(f"Extracted details for packet {packet_details.get('frame_number')}.")

            # Query LM Studio with retries
            llm_analysis = None
            max_retries = 2
            for attempt in range(max_retries):
                llm_analysis = query_lm_studio(packet_details)
                if llm_analysis:
                    break
                msg = f"Attempt {attempt+1} failed for packet {packet_details.get('frame_number')}. Retrying..."
                logging.warning(msg)
                print(f"[WARNING] {msg}")
                time.sleep(2)

            if not llm_analysis:
                msg = f"LLM analysis failed for packet {packet_details.get('frame_number')}. Using fallback description."
                logging.warning(msg)
                print(f"[WARNING] {msg}")
                llm_analysis = f"This is a {packet_details.get('protocol_names')} packet with frame number {packet_details.get('frame_number')}."

            # Build training example
            item = {
                "instruction": "Analyze this network packet data and provide a detailed technical explanation of what's happening.",
                "input": json.dumps(packet_details, indent=2),
                "output": llm_analysis
            }
            dataset.append(item)
            processed += 1

            # Log progress every 10 packets or on the last one
            if (i + 1) % 10 == 0 or (i + 1) == total_packets:
                progress_message = f"Processed {i+1}/{total_packets} packets."
                logging.info(progress_message)
                print(f"[*] {progress_message}")
        except Exception as e:
            logging.exception(f"Error processing packet at index {i}: {e}")
            print(f"[ERROR] Error processing packet at index {i}: {e}")
            skipped += 1

    # Save the dataset to file
    try:
        with open(dataset_out, "w") as f:
            json.dump(dataset, f, indent=2)
        logging.info(f"Dataset successfully written to {dataset_out}")
        print(f"[✓] Dataset written to {dataset_out} with {processed} entries ({skipped} skipped).")
    except Exception as e:
        msg = f"Failed to write dataset to {dataset_out}: {e}"
        logging.exception(msg)
        print(f"[ERROR] {msg}")

    # Verify dataset output file
    verify_file(dataset_out, "Dataset output file")
    logging.info("----- Dataset creation process complete -----")

if __name__ == "__main__":
    create_dataset()
