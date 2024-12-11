import re
import csv
from collections import Counter

def count_requests_per_ip(log_file):
    ip_counts = Counter()
    with open(log_file, 'r') as file:
        for line in file:
            ip = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if ip:
                ip_counts[ip.group()] += 1
    return ip_counts

def most_frequent_endpoint(log_file):
    endpoint_counts = Counter()
    with open(log_file, 'r') as file:
        for line in file:
            endpoint = re.search(r'"(?:GET|POST)\s(\S+)', line)
            if endpoint:
                endpoint_counts[endpoint.group(1)] += 1
    return endpoint_counts.most_common(1)[0] if endpoint_counts else None

def detect_suspicious_activity(log_file, threshold=10):
    failed_attempts = Counter()
    with open(log_file, 'r') as file:
        for line in file:
            if '401' in line or 'Invalid credentials' in line:
                ip = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
                if ip:
                    failed_attempts[ip.group()] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}

def write_results_to_csv(ip_counts, most_accessed, suspicious_activities, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        writer.writerow([]) 
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])

        writer.writerow([])  
        writer.writerow(['Suspicious IP Address', 'Failed Login Attempts'])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

def main():
    log_file = 'sample.log'
    output_file = 'log_analysis_results.csv'

    ip_counts = count_requests_per_ip(log_file)
    most_accessed = most_frequent_endpoint(log_file)
    suspicious_activities = detect_suspicious_activity(log_file)

    print("Requests per IP Address:")
    for ip, count in ip_counts.items():
        print(f"{ip}: {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activities.items():
        print(f"{ip}: {count} failed login attempts")

    write_results_to_csv(ip_counts, most_accessed, suspicious_activities, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == '__main__':
    main()
