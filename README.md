LLM Packet Analyzer

LLM Packet Analyzer is a Python tool that converts PCAP files into structured JSON data and leverages a local LM Studio LLM API to provide detailed technical analyses of network packets. The output is a training dataset ideal for fine-tuning or instructing your local LLM on network packet analysis, anomaly detection, and cybersecurity insights.
Features

    PCAP Extraction: Uses tshark to convert PCAP files to JSON with verbose packet details.
    Detailed Packet Parsing: Extracts comprehensive information across multiple protocols (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP, DHCP, etc.).
    LLM-Enhanced Analysis: Sends each packet’s details to a locally running LM Studio server for expert-level technical analysis.
    Robust Error Handling: Checks for required files and dependencies, logs detailed information, and reports errors during processing.
    Dataset Creation: Generates a JSON training dataset with each entry containing both raw packet details and the corresponding LLM analysis.

Prerequisites

    Python 3.x
    Tshark: Part of Wireshark; ensure it is installed and added to your system's PATH.
    LM Studio Server: A running instance of LM Studio accessible at the configured URL (default: http://localhost:1234).
