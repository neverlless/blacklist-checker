import argparse
import dns.resolver
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from ipaddress import ip_address, IPv4Address

# Constants
DEFAULT_BLACKLIST_FILE = "blacklists.txt"
DEFAULT_DNS_DURATION = 3
EMAIL_HOST = 'smtp.example.com'
EMAIL_PORT = 465
EMAIL_USER = 'you@example.com'
EMAIL_PASS = 'yourpassword'

# Function to load blacklists from file
def load_blacklists(file_path):
    try:
        with open(file_path, 'r') as file:
            blacklists = [line.strip() for line in file if line.strip()]
        print(f"Loaded {len(blacklists)} blacklists.")
        return blacklists
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return []

# Function to resolve DNS queries
def resolve_dns(domain, record_type='A'):
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=DEFAULT_DNS_DURATION)
        return [answer.to_text() for answer in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return []

# Function to check if an IP is blacklisted
def is_blacklisted(ip, blacklist):
    try:
        reversed_ip = '.'.join(reversed(ip.split('.'))) + '.' + blacklist
        return bool(resolve_dns(reversed_ip))
    except Exception as e:
        print(f"Error checking blacklist for {ip}: {e}")
        return False

# Function to send report via email
def send_email_report(report, recipient_email):
    message = MIMEMultipart("alternative")
    message['Subject'] = 'Blacklisting Check Report'
    message['From'] = EMAIL_USER
    message['To'] = recipient_email

    html_content = f"""
    <html>
    <head>
        <style>
            table {{ 
                font-family: Arial, sans-serif;
                border-collapse: collapse;
                width: 100%;
            }}
            th, td {{
                border: 1px solid #dddddd;
                text-align: left;
                padding: 8px;
            }}
            tr:nth-child(even) {{
                background-color: #f2f2f2;
            }}
            .blacklisted {{
                background-color: #f8d7da;
                color: #721c24;
            }}
        </style>
    </head>
    <body>
        <h2>Blacklisting Check Report</h2>
        {report}
    </body>
    </html>
    """

    message.attach(MIMEText(html_content, "html"))

    try:
        with smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(message)
            print(f"Report sent to {recipient_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Function to load targets from file or single target
def load_targets(target):
    try:
        with open(target, 'r') as file:
            targets = [line.strip() for line in file if line.strip()]
        print(f"Loaded {len(targets)} targets.")
        return targets
    except FileNotFoundError:
        print(f"File {target} not found. Assuming single target.")
        return [target]

# Generate HTML report only for blacklisted items
def generate_html_report(target, results):
    if results:
        rows = "".join(f"<tr class='blacklisted'><td>{result}</td></tr>" for result in results)
        return f"""
        <h3>Results for {target}</h3>
        <table>
            <tr>
                <th>Check Result</th>
            </tr>
            {rows}
        </table>
        """
    return ""  # Return empty string if no blacklisted results

# Main function
def main():
    parser = argparse.ArgumentParser(description='Check domains or IPs against multiple blacklists.')
    parser.add_argument('target', type=str, help='Domain or IP to check, or a file with list of targets')
    parser.add_argument('-l', '--list', type=str, default=DEFAULT_BLACKLIST_FILE, help='File with blacklists')
    parser.add_argument('-e', '--email', type=str, help='Email to send the report to', default=None)
    args = parser.parse_args()

    blacklists = load_blacklists(args.list)
    targets = load_targets(args.target)

    all_reports = []
    for target in targets:
        print(f"Checking target: {target}")
        
        try:
            ip = str(ip_address(target))
            is_ip = True
            print(f"Target {target} is an IP address.")
        except ValueError:
            is_ip = False
            print(f"Target {target} is a domain.")

        if is_ip:
            ip_list = [ip]
        else:
            ip_list = resolve_dns(target)

        if not ip_list:
            report = f"No DNS record found for {target}"
            print(report)
            all_reports.append(f"<p>{report}</p>")
            continue

        ip = ip_list[0]
        blacklisted_results = []
        for bl in blacklists:
            if is_blacklisted(ip, bl):
                blacklisted_results.append(f"{ip} is blacklisted on {bl}")

        report = generate_html_report(target, blacklisted_results)
        if report:
            all_reports.append(report)

    if args.email and all_reports:
        full_report = "<br><br>".join(all_reports)
        send_email_report(full_report, args.email)
    elif not all_reports:
        print("No blacklisted results to report via email.")

if __name__ == "__main__":
    main()
