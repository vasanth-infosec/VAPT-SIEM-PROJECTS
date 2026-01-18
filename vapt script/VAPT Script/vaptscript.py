import subprocess
import re
from datetime import datetime
import shutil

GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"  # Reset color to default
YELLOW = "\033[33m"
RED = "\033[31m"

def run_command(command):
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        error_output = result.stderr
    except subprocess.CalledProcessError as e:
        output = e.stdout
        error_output = e.stderr

    # Remove color codes
    output = remove_words(output)
    error_output = remove_words(error_output)

    # Filter out lines containing typical error patterns or messages
    error_keywords = ["error", "fail", "unable", "not found", "could not", "failed", "no such file",
                      "command not found"]

    filtered_output = []
    for line in output.splitlines():
        if not any(keyword in line.lower() for keyword in error_keywords):  # Skip error lines
            filtered_output.append(line)

    # Optionally, also filter error output if it's not useful
    for line in error_output.splitlines():
        if not any(keyword in line.lower() for keyword in error_keywords):
            filtered_output.append(line)

    return "\n".join(filtered_output) if filtered_output else "No relevant output."

def remove_words(output):
    # Regular expression to remove all ANSI escape sequences (including colors and other codes)
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')  # General pattern to match ANSI escape codes
    output = ansi_escape.sub('', output)  # Remove all ANSI escape sequences

    # Additionally, remove specific [K if needed
    word_remove_content = re.compile(r'\[K')
    output = word_remove_content.sub('', output)  # Removing the specific [K pattern

    return output

# Function to get terminal width
def get_terminal_width():
    return shutil.get_terminal_size().columns

# Function to center and print text
def print_centered(text):
    terminal_width = get_terminal_width()
    # Split the text by lines and center each line
    centered_text = "\n".join([line.strip().center(terminal_width) for line in text.splitlines()])
    print(centered_text)

# Function to filter tool results based on unwanted line starts
def filter_tool_output(output):
    # Filter out lines that start with *, |, or -
    filtered_output = []
    filt = ["*", " |", "  -", "  _", " (https", "Read", "An exception", "Searching", "Job", "Good", " (The analysis",
            "Starting Nmap", "[*] Target: ", "[*] Searching", "Target ==>", "    "]  # List of prefixes to filter out
    for line in output.splitlines():
        if not any(line.startswith(prefix) for prefix in filt):  # Check each prefix
            filtered_output.append(line)

    return "\n".join(filtered_output) if filtered_output else "No relevant output."


def filter_dirb_output(output):
    filtered_output = []
    for line in output.splitlines():
        if "DIRECTORY" in line:
            filtered_output.append(line)
    return "\n".join(filtered_output)


def extract_current_db(sqlmap_output):
    if sqlmap_output:
        # Loop through the output and find the line containing the current database
        for line in sqlmap_output.splitlines():
            if "current database" in line.lower():
                return line.strip()  # Return the current database line
    return "Database not found"


def extract_full_versions(nmap_output):
    full_versions = []

    # Regex to capture the full version info (service + version)
    version_regex = re.compile(r"\d{1,5}/tcp\s+open\s+(\S+)\s+(.+)")

    # Find all matches (service name and full version)
    matches = version_regex.findall(nmap_output)

    # Append full service + version information
    for match in matches:
        service = match[0]  # Service name (e.g., Apache, OpenSSH)
        version = match[1]  # Full version (e.g., 2.4.29, 7.6p1 Ubuntu 4ubuntu0.7)
        full_versions.append(f"{service} {version}")

    return full_versions


def find_exploits(nmap_output):
    if nmap_output == "No relevant output.":
        print("No output or relevant result from Nmap scan.")
        return ""

    full_versions = extract_full_versions(nmap_output)
    exploits_info = ""

    for full_version in full_versions:
        service, version = full_version.split(' ', 1)
        # Use service and version to find exploits
        exploits = run_command(["searchsploit", f"{service} {version}"])
        exploits_info += f"\nExploits for {service} {version}:\n{exploits}"

    return exploits_info


def is_valid_domain(domain):
    pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None


def generate_html(filtered_humble_output, filtered_theharvester_output, filtered_findomain_output, filtered_nmap_output,
                  filtered_nikto_output, filtered_sslscan_output, filtered_dirb_output, current_db, exploits_info,
                  filtered_wafw00f_output, domain):
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AuroPentrix Security Report</title>
        <style>
            body {{ font-family: 'Arial', sans-serif; background-color: #f5f5f5; padding: 40px; margin: 0; color: #333; }}
            .container {{ max-width: 900px; margin: auto; padding: 30px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 0 15px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ text-align: center; color: #34495e; font-size: 2em; margin-bottom: 10px; }}
            h4 {{ color: #2980b9; font-size: 1.2em; margin-bottom: 5px; }}
            .summary-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            .summary-table th, .summary-table td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            .summary-table th {{ background-color: #3498db; color: #fff; font-weight: bold; }}
            .summary-table td {{ background-color: #f9f9f9; }}
            pre {{ background-color: #ecf0f1; padding: 15px; border-radius: 5px; font-size: 0.95em; overflow-x: auto; }}
            footer {{ text-align: center; padding: 15px; font-size: 0.9em; color: #7f8c8d; background-color: #ecf0f1; margin-top: 20px; border-radius: 0 0 8px 8px; }}
            .header-bar {{ padding: 15px; background-color: #2980b9; color: #fff; border-radius: 8px 8px 0 0; text-align: center; font-size: 1.5em; }}
            .link {{ color: #3498db; text-decoration: none; }}
            .link:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header-bar">
                KairaPentrix Security Report
            </div>
            <h3>Target: <a href="https://{domain}" target="_blank" class="link">{domain}</a></h3>
            <p><strong>Scan Date:</strong> {current_datetime}</p>
            <hr>
            <h4>Summary of Findings</h4>
            <table class="summary-table">
                <thead>
                    <tr>
                        <th>Tool</th>
                        <th>Findings</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td>Humble</td><td>{'Issues Found' if filtered_humble_output else 'No Issues'}</td></tr>
                    <tr><td>theHarvester</td><td>{'Issues Found' if filtered_theharvester_output else 'No Issues'}</td></tr>
                    <tr><td>Findomain</td><td>{'Issues Found' if filtered_findomain_output else 'No Issues'}</td></tr>
                    <tr><td>wafw00f</td><td>{'Issues Found' if "is behind" in filtered_wafw00f_output else 'No Issues'}</td></tr>
                    <tr><td>Nmap</td><td>{'Issues Found' if filtered_nmap_output else 'No Issues'}</td></tr>
                    <tr><td>Exploits</td><td>{'Issues Found' if "Exploit Title" in exploits_info else 'No Issues'}</td></tr>
                    <tr><td>Nikto</td><td>{'Issues Found' if filtered_nikto_output else 'No Issues'}</td></tr>
                    <tr><td>Sslscan</td><td>{'Issues Found' if filtered_sslscan_output else 'No Issues'}</td></tr>
                    <tr><td>Dirb</td><td>{'Issues Found' if filtered_dirb_output else 'No Issues'}</td></tr>
                    <tr><td>SqlMap</td><td>{'Issues Found' if "current database" in current_db else 'No Issues'}</td></tr>
                </tbody>
            </table>
            <hr>
            <h3>Humble Findings</h3>
            <pre>{filtered_humble_output}</pre>
            <h3>theHarvester Findings</h3>
            <pre>{filtered_theharvester_output}</pre>
            <h3>Findomain Findings</h3>
            <pre>{filtered_findomain_output}</pre>
            <h3>Wafw00f Findings</h3>
            <pre>{filtered_wafw00f_output}</pre>
            <h3>Nmap Findings</h3>
            <pre>{filtered_nmap_output}</pre>
            <h3>Exploits Findings</h3>
            <pre>{exploits_info}</pre>
            <h3>Nikto Findings</h3>
            <pre>{filtered_nikto_output}</pre>
            <h3>Sslscan Findings</h3>
            <pre>{filtered_sslscan_output}</pre>
             <h3>Dirb Findings</h3>
            <pre>{filtered_dirb_output}</pre>
             <h3>Sqlmap Findings</h3>
            <pre>{current_db}</pre>

            <footer>
                <p>&copy; {datetime.now().year} KairaPentrix | Confidential Report</p>
            </footer>
        </div>
    </body>
    </html>
    """
    return html_content

domain = input(f"{GREEN} Enter the domain: {RESET}")
while not is_valid_domain(domain):
    print(f"{RED}Error: {domain} is not a valid domain.")
    domain = input(f"Please enter a valid domain: {RESET}")

clear = run_command(["clear"])
print(clear)


def print_banner():
    # Banner text with color
    banner = f""" {YELLOW}
*******************************************************************
*                                                                 *
*                          KairaPentrix                           *
*                                                                 *
*      Vulnerability Assessment and Penetration Testing Tool      *
*                                                                 *
******************************************************************* 
{RESET}{GREEN}"""
    print_centered(banner)

# Example usage:
print_banner()


# Prompt user for a valid domain
print_centered(domain)



start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
print_centered(f" Start Date And Time : {start_time}")

print_centered(" Starting Reconnaissance Phase...")

url = f"https://{domain}"
url1 = f"http://{domain}"

# Run the reconnaissance tools
humble_output = run_command(["humble", "-u", url])
theharvester_output = run_command(["theHarvester", "-d", domain, "-b", "yahoo"])
findomain_output = run_command(["findomain", "-t", domain])
wafw00f_output = run_command(["wafw00f", url, "-a", "-v", "--no-colors"])

# Filter the tool outputs
filtered_humble_output = filter_tool_output(humble_output)
filtered_theharvester_output = filter_tool_output(theharvester_output)
filtered_findomain_output = filter_tool_output(findomain_output)
filtered_wafw00f_output = filter_tool_output(wafw00f_output)

print_centered("  Starting Vulnerability Scanning...")

# Run vulnerability scanning tools
nmap_output = run_command(["nmap", "-sV", domain])
nikto_output = run_command(["nikto", "-h", url])
sslscan_output = run_command(["sslscan", domain])
exploits_info = find_exploits(nmap_output)

filtered_nmap_output = filter_tool_output(nmap_output)
filtered_nikto_output = filter_tool_output(nikto_output)
filtered_sslscan_output = filter_tool_output(sslscan_output)

print_centered("Starting Exploitation Phase...")

# Run exploitation tools
dirb_output = run_command(["dirb", url])
sql_output = run_command(["sqlmap", "-u", url1, "--current-db", "--crawl=3", "--batch"])

filtered_dirb_output = filter_dirb_output(dirb_output)
current_db = extract_current_db(sql_output)

# Generate the HTML report
html_output = generate_html(filtered_humble_output, filtered_theharvester_output, filtered_findomain_output,
                            filtered_nmap_output, filtered_nikto_output, filtered_sslscan_output,
                            filtered_dirb_output, current_db, exploits_info, filtered_wafw00f_output, domain)

# Save the HTML report to a file
output_file = domain + ".security_report.html"
with open(output_file, "w") as file:
    file.write(html_output)

print_centered(f"   Report saved to {output_file}")
end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
print_centered(f"  End Date And Time: {end_time}{RESET}")
