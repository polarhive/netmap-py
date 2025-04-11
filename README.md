# **UE23CS252B: CN mini-project**  

A modern, web-based network port scanner with vulnerability assessment capabilities.

## Features

- Fast, multi-threaded port scanning
- Web interface for easy operation
- IP range scanning (CIDR, range, or individual IPs)
- Port range specification
- Vulnerability assessment based on open ports
- Visual data representation (charts and graphs)
- Service identification and security information

## Usage

1. Open your browser and navigate to `http://localhost:5000/`
2. Enter an IP address or range:
   - Single IP: `192.168.1.1`
   - IP range: `192.168.1.1-192.168.1.10`
   - CIDR notation: `192.168.1.0/24`
3. Enter port(s) to scan:
   - Single port: `80`
   - Port range: `20-100`
   - Multiple ports: `22,80,443,8080`
   - Or use the "Auto Scan Common Ports" option
4. Click "Scan" and view the results

### mapping.json

Defines port service information and vulnerability scores:

```json
{
    "80": {
        "score": 1,
        "service": "HTTP",
        "description": "Web server",
        "common_exploits": "Injection, XSS, misconfiguration"
    }
}
```

## Architecture

- `scanner.py`: Main application file with scanning logic and web server
- `templates/`: Contains HTML templates for the web interface
- `config.json`: Application configuration
- `mapping.json`: Port to service mapping and vulnerability information

## Security Note

This tool is designed for network administrators and security professionals to assess their own networks. Always ensure you have proper authorization before scanning any network.


## **Credits**  

```
PES2UG23CS368 Nathan Matthew Paul  
PES2UG23CS371 Navneet Nayak  
Copyright (C) 2025  
```

[![license: GPL](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://opensource.org/license/gpl-3-0)  