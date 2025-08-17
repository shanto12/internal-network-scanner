import sys
import os
import platform
import subprocess
import threading
import queue
import socket
import ipaddress
import time
import getpass
import json
import webbrowser

# Function to install module if missing
def ensure_module(module_name, package_name=None, index_url=None):
    if package_name is None:
        package_name = module_name
    try:
        __import__(module_name)
        return True
    except ImportError:
        print(f"{module_name} not found. Attempting install.")
        cmd = [sys.executable, '-m', 'pip', 'install', package_name]
        if index_url:
            cmd.extend(['--index-url', index_url])
        else:
            internal = input("Enter internal PyPI index URL (or press Enter for PyPI/default): ").strip()
            if internal:
                cmd.extend(['--index-url', internal])
            else:
                try:
                    # Check if internet available
                    socket.create_connection(("pypi.org", 443), timeout=2)
                except:
                    print("No internet. Provide internal index URL.")
                    internal = input("Internal PyPI index URL: ").strip()
                    if internal:
                        cmd.extend(['--index-url', internal])
                    else:
                        print(f"Cannot install {package_name}. Script may fail.")
                        return False
        try:
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{package_name} installed.")
            return True
        except:
            print(f"Failed to install {package_name}. Proceed without?")
            if input("y/n: ").lower() != 'y':
                sys.exit(1)
            return False

# Ensure minimal modules
ensure_module('requests')
ensure_module('bs4', 'beautifulsoup4')
import requests
from bs4 import BeautifulSoup

# Optional: No atlassian, pysnow - use requests instead

# Get local IP
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return input("Enter local IP: ")

# Ping sweep for host discovery
def ping_host(ip, q):
    sys_os = platform.system().lower()
    if sys_os == 'windows':
        cmd = ['ping', '-n', '1', '-w', '500', ip]
    else:
        cmd = ['ping', '-c', '1', '-W', '1', ip]
    response = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if response == 0:
        q.put(ip)

def discover_hosts(cidr):
    network = ipaddress.ip_network(cidr)
    q = queue.Queue()
    threads = []
    for ip in network.hosts():
        ip_str = str(ip)
        t = threading.Thread(target=ping_host, args=(ip_str, q))
        t.start()
        threads.append(t)
        if len(threads) > 100:  # Limit threads
            for th in threads:
                th.join()
            threads = []
    for t in threads:
        t.join()
    hosts = []
    while not q.empty():
        hosts.append(q.get())
    return hosts

# Port check
common_ports = [80, 443, 8080, 8443, 7990, 8090, 5000]  # HTTP variants, Jira/Conf/Bitbucket

tool_signatures = {
    'Jira': ['/secure/Dashboard.jspa', 'atlassian-jira', 'JIRA'],
    'Confluence': ['/login.action', 'atlassian-confluence', 'Confluence'],
    'ServiceNow': ['/navpage.do', 'ServiceNow', 'Glide'],
    'GitLab': ['/users/sign_in', 'GitLab'],
    'Bitbucket': ['/login', 'Bitbucket'],
    'Jenkins': ['/login', 'Jenkins'],
    'Artifactory': ['/ui/login', 'Artifactory'],
}

def detect_tool(host, port):
    scheme = 'https' if port in [443, 8443] else 'http'
    url = f"{scheme}://{host}:{port}"
    try:
        r = requests.get(url, timeout=3, verify=False, allow_redirects=True)
        if r.status_code >= 400:
            return None, None
        soup = BeautifulSoup(r.text, 'html.parser')
        title = soup.title.string.lower() if soup.title else ''
        content = r.text.lower()
        for tool, sigs in tool_signatures.items():
            if any(sig.lower() in title or sig.lower() in content for sig in sigs):
                return tool, url
    except:
        pass
    return None, None

def scan_host(host, results):
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((host, port)) == 0:
            tool, url = detect_tool(host, port)
            if tool:
                results[tool] = url
        sock.close()

# Main discovery
local_ip = get_local_ip()
default_cidr = '/'.join(local_ip.rsplit('.', 1)[0] + ['0/24'])
cidr = input(f"Enter network CIDR (default {default_cidr}): ") or default_cidr
print("Discovering hosts... This may take time.")
hosts = discover_hosts(cidr)
print(f"Discovered {len(hosts)} hosts: {hosts}")

results = {}
threads = []
for host in hosts:
    t = threading.Thread(target=scan_host, args=(host, results))
    t.start()
    threads.append(t)
for t in threads:
    t.join()

print("Detected tools:")
for tool, url in results.items():
    print(f"{tool}: {url}")

# Generic API interaction with token/auth
def get_auth(tool):
    print(f"For {tool}: Generate API token or use credentials.")
    auth_type = input("Auth type (bearer/basic/pat/username_password): ").lower()
    if auth_type == 'bearer' or auth_type == 'pat':
        token = getpass.getpass("Enter token: ")
        return {'Authorization': f'Bearer {token}'}
    elif auth_type == 'basic':
        user = input("Username: ")
        pwd = getpass.getpass("Password: ")
        return requests.auth.HTTPBasicAuth(user, pwd)
    elif auth_type == 'username_password':
        user = input("Username: ")
        pwd = getpass.getpass("Password: ")
        return user, pwd
    return None

def assist_login(url):
    print("Opening browser for login...")
    webbrowser.open(url)
    print("Log in, then copy token/cookie from dev tools (F12 > Application > Cookies).")
    time.sleep(5)
    return input("Paste token or cookie value: ")

# Confluence
if 'Confluence' in results:
    conf_url = results['Confluence'].rstrip('/') 
    print(f"Confluence at {conf_url}")
    need_login = input("Need to login via browser? (y/n): ") == 'y'
    if need_login:
        token = assist_login(conf_url + '/login.action')
    else:
        auth = get_auth('Confluence')
    question = input("Question to search in Confluence: ")
    try:
        headers = auth if isinstance(auth, dict) else {'Authorization': f'Bearer {token}'}
        params = {'cql': f'text ~ "{question}"'}
        r = requests.get(f"{conf_url}/rest/api/content/search", headers=headers, params=params, verify=False)
        print("Results:", r.json())
    except Exception as e:
        print("Error:", e)

# Similar for Jira
if 'Jira' in results:
    jira_url = results['Jira'].rstrip('/')
    print(f"Jira at {jira_url}")
    need_login = input("Need to login via browser? (y/n): ") == 'y'
    if need_login:
        token = assist_login(jira_url + '/login.jsp')
    else:
        auth = get_auth('Jira')
    question = input("JQL query (e.g., text ~ 'question'): ")
    try:
        headers = auth if isinstance(auth, dict) else {'Authorization': f'Bearer {token}'}
        params = {'jql': question}
        r = requests.get(f"{jira_url}/rest/api/2/search", headers=headers, params=params, verify=False)
        print("Results:", r.json())
    except Exception as e:
        print("Error:", e)

# ServiceNow
if 'ServiceNow' in results:
    sn_url = results['ServiceNow'].rstrip('/')
    print(f"ServiceNow at {sn_url}")
    instance = sn_url.split('//')[1].split('.')[0]
    user, pwd = get_auth('ServiceNow') if isinstance(get_auth('ServiceNow'), tuple) else (input("Username: "), getpass.getpass("Password: "))
    table = input("Table to query (e.g., incident): ")
    query = input("Query (e.g., active=true): ")
    try:
        auth = requests.auth.HTTPBasicAuth(user, pwd)
        r = requests.get(f"{sn_url}/api/now/table/{table}?sysparm_query={query}", auth=auth, verify=False)
        print("Results:", r.json())
    except Exception as e:
        print("Error:", e)

# Git tools - basic detect, no deep interaction
for tool in ['GitLab', 'Bitbucket']:
    if tool in results:
        git_url = results[tool]
        print(f"{tool} at {git_url}")
        need_login = input("Open browser for login? (y/n): ") == 'y'
        if need_login:
            assist_login(git_url + '/login' if tool == 'Bitbucket' else git_url + '/users/sign_in')

print("Script complete.")
