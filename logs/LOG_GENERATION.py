import random
import datetime

# List of possible HTTP methods with weights
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]
METHOD_WEIGHTS = [50, 30, 10, 10]

# List of possible HTTP status codes with weights
HTTP_STATUS_CODES = [200, 201, 204, 400, 401, 403, 404, 500]
STATUS_CODE_WEIGHTS = [30, 20, 10, 10, 5, 5, 10, 10]

# List of sample URLs with weights
URLS = [
    "/home",
    "/about",
    "/products",
    "/contact",
    "/login",
    "/signup",
    "/admin",
    "/api/data",
    "/blog/post1",
    "/images/logo.png"
]
URL_WEIGHTS = [20, 15, 15, 10, 10, 10, 5, 5, 5, 5]

# List of sample IP addresses
IP_ADDRESSES = [
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "123.45.67.89",
    "98.76.54.32"
]

# List of sample user agents with weights
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 Edge/14.14393",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 Edge/14.14393",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
]
USER_AGENT_WEIGHTS = [40, 25, 15, 10, 10]

# Function to generate a random timestamp within a time window
def random_timestamp():
    now = datetime.datetime.now()
    delta = datetime.timedelta(seconds=random.randint(1, 3600))  # Random time within 1 hour
    return now - delta

# Function to generate a random log entry
def generate_log_entry():
    timestamp = random_timestamp().strftime("%Y-%m-%d %H:%M:%S")
    ip_address = random.choice(IP_ADDRESSES)
    method = random.choices(HTTP_METHODS, weights=METHOD_WEIGHTS)[0]
    url = random.choices(URLS, weights=URL_WEIGHTS)[0]
    status_code = random.choices(HTTP_STATUS_CODES, weights=STATUS_CODE_WEIGHTS)[0]
    user_agent = random.choices(USER_AGENTS, weights=USER_AGENT_WEIGHTS)[0]
    
    return f"{timestamp} {ip_address} - - \"{method} {url} HTTP/1.1\" {status_code} - \"{user_agent}\""

# Number of log entries to generate
NUM_ENTRIES = 10000

# Generate log entries
log_entries = [generate_log_entry() for _ in range(NUM_ENTRIES)]

# Sort log entries based on timestamp
log_entries.sort()

# Write sorted log entries to file
with open("sample_log_file.log", "w") as f:
    for log_entry in log_entries:
        f.write(log_entry + "\n")

print("Log file generated successfully.")
