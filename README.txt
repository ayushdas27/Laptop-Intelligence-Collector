======================================================
WINDOWS LAPTOP INTELLIGENCE & INFO COLLECTOR
======================================================

DESCRIPTION:
This tool automatically collects comprehensive system, hardware, network, and security information from the local Windows computer. It compiles this data into a responsive HTML report, a standard text file, and an SQLite database for historical tracking.

REQUIREMENTS:
- Windows 10 or Windows 11
- Python 3.x installed and added to the system PATH

INSTRUCTIONS:
1. Extract all files into a single folder.
2. Double-click the "Run_Laptop_Intelligence.bat" file.
3. The script will automatically verify Python, run the collection processes, and display progress in the terminal.
4. Once completed, check the "Output" folder for your files:
   - laptop_report.html (Interactive Dashboard)
   - laptop_report.txt (Raw text format)
   - laptop_audit.db (SQLite database of historical runs)

SECURITY & PRIVACY:
- All data is processed locally. No data is transmitted to external servers.
- The script uses read-only operations and does not disable any Windows security features.
- Wi-Fi passwords, private keys, and browser credentials are never collected.
- Some advanced security events (like login history) may display "Requires Administrator Privileges" if the script is run as a standard user. This is by design to respect Windows security boundaries.
