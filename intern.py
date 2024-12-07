import re
import csv
from collections import defaultdict, Counter

FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = r"C:\Users\chand\OneDrive\Desktop\sample_log.txt"
CSV_OUTPUT_FILE = r"C:\Users\chand\OneDrive\Desktop\log_analysis_results.csv"


def read_log_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def parse_log_data(log_lines):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    for line in log_lines:
        ip_match = re.search(r'^(\\d+\\.\\d+\\.\\d+\\.\\d+)', line)
        if ip_match:
            ip = ip_match.group(0)
            ip_requests[ip] += 1

        endpoint_match = re.search(r'\"(?:GET|POST|PUT|DELETE) (\\S+)', line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_requests[endpoint] += 1

        if "401" in line or "Invalid credentials" in line:
            if ip_match:
                failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def write_to_csv(ip_requests, most_accessed_endpoint, suspicious_activities):
    with open(CSV_OUTPUT_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)

        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        writer.writerow([])

        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow([most_accessed_endpoint[0], f"Accessed {most_accessed_endpoint[1]} times"])

        writer.writerow([])

        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

def analyze_log_file():
    log_lines = read_log_file(LOG_FILE)
    ip_requests, endpoint_requests, failed_logins = parse_log_data(log_lines)

    if endpoint_requests:
        most_accessed_endpoint = endpoint_requests.most_common(1)[0]
    else:
        most_accessed_endpoint = ("None", 0)

    suspicious_activities = {
        ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD
    }

    print("IP Address           Request Count")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed_endpoint[0] != "None":
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    else:
        print("No endpoint data available.")

    print("\nSuspicious Activity Detected:")
    if suspicious_activities:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activities.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    write_to_csv(ip_requests, most_accessed_endpoint, suspicious_activities)

if __name__ == "__main__":
    analyze_log_file()