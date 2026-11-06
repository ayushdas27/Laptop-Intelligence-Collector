import os
import sys
import subprocess
import sqlite3
import datetime
import socket
import urllib.request
import platform

# Ensure we are saving outputs in the correct directory
OUTPUT_DIR = "Output"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

DB_PATH = os.path.join(OUTPUT_DIR, "laptop_audit.db")
HTML_PATH = os.path.join(OUTPUT_DIR, "laptop_report.html")
TXT_PATH = os.path.join(OUTPUT_DIR, "laptop_report.txt")

collected_data = []
session_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def add_record(category, field, value):
    """Helper to append structured data, ensuring values are strings and formatted cleanly."""
    if not value or str(value).strip() == "":
        value = "Unavailable / Not Found"
    
    # Clean up massive text blocks to prevent formatting issues
    val_str = str(value).strip()
    collected_data.append({
        "Category": category,
        "Field": field,
        "Value": val_str
    })

def run_cmd(command, timeout_sec=15):
    """Executes a Windows command and returns the output safely."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout_sec)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return f"Error / Access Denied (Code {result.returncode})"
    except subprocess.TimeoutExpired:
        return "Command Timeout"
    except Exception as e:
        return f"Execution Error: {str(e)}"

def run_ps(ps_command, timeout_sec=15):
    """Executes a PowerShell command and returns the output safely."""
    cmd = f'powershell -NoProfile -Command "{ps_command}"'
    return run_cmd(cmd, timeout_sec)

# ==========================================
# COLLECTION MODULES
# ==========================================

def collect_device_info():
    print("[1/8] Collecting device information...")
    add_record("Device", "Hostname", platform.node())
    add_record("Device", "OS Version", f"{platform.system()} {platform.release()} (Build {platform.version()})")
    add_record("Device", "System Architecture", platform.machine())
    
    add_record("Device", "Manufacturer", run_ps("(Get-CimInstance Win32_ComputerSystem).Manufacturer"))
    add_record("Device", "Model", run_ps("(Get-CimInstance Win32_ComputerSystem).Model"))
    add_record("Device", "BIOS Version", run_ps("(Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion"))
    
    boot_time = run_ps("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime")
    add_record("Device", "Last Boot Time", boot_time)

def collect_network_info():
    print("[2/8] Collecting network information...")
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            pub_ip = response.read().decode('utf-8')
    except:
        pub_ip = "Offline / Unavailable"
    add_record("Network", "Public IPv4", pub_ip)
    
    add_record("Network", "Private IP", socket.gethostbyname(platform.node()))
    
    adapters = run_ps("Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress | Format-Table -AutoSize")
    add_record("Network", "Network Adapters", adapters)
    
    ipconfig = run_cmd("ipconfig")
    add_record("Network", "IP Configuration", ipconfig)

def collect_dns_info():
    print("[3/8] Collecting DNS information...")
    dns_servers = run_ps("Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize")
    add_record("DNS", "Configured DNS Servers", dns_servers)
    
    dns_cache = run_cmd("ipconfig /displaydns")
    if "Could not display" in dns_cache or len(dns_cache) < 10:
        dns_cache = "DNS Cache empty or unavailable."
    add_record("DNS", "Recent DNS Cache Records", dns_cache[:2000] + "\n...[Truncated for length]" if len(dns_cache) > 2000 else dns_cache)

def collect_connections():
    print("[4/8] Collecting active connections...")
    netstat = run_cmd("netstat -ano")
    add_record("Connections", "Active TCP & UDP Endpoints", netstat[:3000] + "\n...[Truncated for readability]" if len(netstat) > 3000 else netstat)

def collect_hardware():
    print("[5/8] Collecting hardware information...")
    add_record("Hardware", "CPU Model", run_ps("(Get-CimInstance Win32_Processor).Name"))
    add_record("Hardware", "CPU Cores", run_ps("(Get-CimInstance Win32_Processor).NumberOfCores"))
    add_record("Hardware", "CPU Logical Threads", run_ps("(Get-CimInstance Win32_Processor).NumberOfLogicalProcessors"))
    
    ram_bytes = run_ps("(Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum")
    try:
        ram_gb = round(int(ram_bytes) / (1024**3), 2)
        add_record("Hardware", "Installed RAM", f"{ram_gb} GB")
    except:
        add_record("Hardware", "Installed RAM", "Unavailable")
        
    add_record("Hardware", "GPU Information", run_ps("(Get-CimInstance Win32_VideoController).Name"))
    add_record("Hardware", "Storage Devices", run_ps("Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, VolumeName, @{Name='FreeGB';Expression={[math]::Round($_.FreeSpace/1GB,2)}}, @{Name='TotalGB';Expression={[math]::Round($_.Size/1GB,2)}} | Format-Table -AutoSize"))

def collect_activity():
    print("[6/8] Collecting system activity...")
    processes = run_ps("Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Name, Id, CPU | Format-Table -AutoSize")
    add_record("Apps & Services", "Top 20 Running Processes (by CPU)", processes)
    
    services = run_ps("Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 20 Name, DisplayName | Format-Table -AutoSize")
    add_record("Apps & Services", "Running Services (Sample)", services)
    
    startup = run_ps("Get-CimInstance Win32_StartupCommand | Select-Object Name, Command | Format-Table -AutoSize")
    add_record("Apps & Services", "Startup Applications", startup)

def collect_security():
    print("[7/8] Collecting security information...")
    add_record("Security", "Firewall Status", run_cmd("netsh advfirewall show allprofiles state"))
    
    defender = run_ps("Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, BehaviorMonitorEnabled, RealTimeProtectionEnabled | Format-List")
    add_record("Security", "Windows Defender Status", defender)
    
    logins = run_cmd('wevtutil qe Security /c:5 /f:text /q:"*[System[(EventID=4624)]]"')
    if "Access is denied" in logins or "Error" in logins:
         logins = "Requires Administrator Privileges to read Security Event Logs."
    add_record("Security", "Recent Successful Logins (Event 4624)", logins)
    
    usb_history = run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*' -ErrorAction SilentlyContinue | Select-Object FriendlyName | Format-Table -AutoSize")
    add_record("Security", "USB Storage History", usb_history if usb_history else "Requires Admin or No History")

def collect_wifi():
    print("[8/8] Collecting Wi-Fi & Diagnostics...")
    wifi_interfaces = run_cmd("netsh wlan show interfaces")
    add_record("Wi-Fi", "Current Connection Details", wifi_interfaces)
    
    wifi_profiles = run_cmd("netsh wlan show profiles")
    add_record("Wi-Fi", "Saved Wi-Fi Profiles", wifi_profiles)
    
    ping_gw = run_cmd("ping -n 2 8.8.8.8")
    add_record("Diagnostics", "Ping Test (8.8.8.8)", ping_gw)
    
    add_record("Diagnostics", "HTTPS Resolution Test", run_ps("Test-NetConnection -ComputerName google.com -Port 443 | Select-Object ComputerName, TcpTestSucceeded | Format-Table"))

# ==========================================
# REPORT GENERATORS
# ==========================================

def generate_sqlite():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_timestamp TEXT,
            category TEXT,
            field TEXT,
            value TEXT
        )
    ''')
    for row in collected_data:
        cursor.execute('''
            INSERT INTO system_audit (session_timestamp, category, field, value)
            VALUES (?, ?, ?, ?)
        ''', (session_timestamp, row["Category"], row["Field"], row["Value"]))
    conn.commit()
    conn.close()

def generate_txt():
    with open(TXT_PATH, "w", encoding="utf-8") as f:
        f.write(f"LAPTOP INTELLIGENCE REPORT - {session_timestamp}\n")
        f.write("="*60 + "\n")
        f.write(f"{'CATEGORY':<20} | {'FIELD':<30} | VALUE\n")
        f.write("="*60 + "\n")
        for row in collected_data:
            flat_value = row['Value'].replace('\n', ' -- ').replace('\r', '')
            f.write(f"{row['Category']:<20} | {row['Field']:<30} | {flat_value}\n")

def generate_html():
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Laptop Intelligence Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #0056b3; text-align: center; border-bottom: 2px solid #0056b3; padding-bottom: 10px; }}
        .dashboard {{ display: flex; justify-content: space-between; background: #e9ecef; padding: 15px; border-radius: 6px; margin-bottom: 20px; font-weight: bold; }}
        .search-box {{ width: 100%; padding: 12px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 5px; font-size: 16px; box-sizing: border-box; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; table-layout: fixed; }}
        th, td {{ padding: 12px; border: 1px solid #dee2e6; text-align: left; vertical-align: top; word-wrap: break-word; }}
        th {{ background-color: #0056b3; color: white; }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        tr:hover {{ background-color: #e2e6ea; }}
        pre {{ margin: 0; white-space: pre-wrap; font-family: 'Consolas', monospace; font-size: 13px; color: #444; }}
        .category-badge {{ background: #17a2b8; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Laptop Intelligence & System Report</h1>
        <div class="dashboard">
            <span>Collection Time: {session_timestamp}</span>
            <span>Hostname: {platform.node()}</span>
        </div>
        
        <input type="text" id="searchInput" class="search-box" placeholder="Search across all categories, fields, and values..." onkeyup="filterTable()">
        
        <table id="reportTable">
            <thead>
                <tr>
                    <th style="width: 15%;">Category</th>
                    <th style="width: 25%;">Field</th>
                    <th style="width: 60%;">Value</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for row in collected_data:
        html_content += f"""
                <tr>
                    <td><span class="category-badge">{row['Category']}</span></td>
                    <td><strong>{row['Field']}</strong></td>
                    <td><pre>{row['Value']}</pre></td>
                </tr>
        """
        
    html_content += """
            </tbody>
        </table>
    </div>
    
    <script>
        function filterTable() {
            let input = document.getElementById("searchInput");
            let filter = input.value.toUpperCase();
            let table = document.getElementById("reportTable");
            let tr = table.getElementsByTagName("tr");

            for (let i = 1; i < tr.length; i++) {
                let tdArray = tr[i].getElementsByTagName("td");
                let match = false;
                for (let j = 0; j < tdArray.length; j++) {
                    if (tdArray[j]) {
                        if (tdArray[j].innerText.toUpperCase().indexOf(filter) > -1) {
                            match = true;
                            break;
                        }
                    }
                }
                tr[i].style.display = match ? "" : "none";
            }
        }
    </script>
</body>
</html>
"""
    with open(HTML_PATH, "w", encoding="utf-8") as f:
        f.write(html_content)

if __name__ == "__main__":
    print("\nLAPTOP INTELLIGENCE COLLECTOR")
    print("=" * 40)
    
    collect_device_info()
    collect_network_info()
    collect_dns_info()
    collect_connections()
    collect_hardware()
    collect_activity()
    collect_security()
    collect_wifi()
    
    print("\n[*] Compiling reports...")
    generate_sqlite()
    generate_txt()
    generate_html()
    
    print("\nCOLLECTION COMPLETED SUCCESSFULLY.")
    print("Reports generated in the 'Output' folder:")
    print(" - laptop_report.html")
    print(" - laptop_report.txt")
    print(" - laptop_audit.db")
