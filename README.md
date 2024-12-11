# Log-Analysis-Script
This is a Python log analysis tool to extract insights from server logs, including request counts, most accessed endpoints, and suspicious activities. Outputs results to the terminal and a CSV file for easy analysis.
Log Analysis Script

Features
Request Count per IP: Analyzes the log to count the number of requests made by each IP address.
Most Accessed Endpoint: Identifies the endpoint (e.g., URL or resource path) that was accessed the most frequently.
Suspicious Activity Detection: Flags IP addresses with excessive failed login attempts, indicating potential brute-force attacks.
CSV Report Generation: Saves the results into a well-structured CSV file for easy sharing and archiving.
How It Works
Reads a log file containing HTTP request data.
Uses Python's re module for pattern matching and collections.Counter for efficient counting.
Outputs results to the terminal and saves a summary in log_analysis_results.csv.
Technologies Used
Python 3
Regular Expressions (re)
CSV Handling (csv module)
collections.Counter for data aggregation
Usage
Place your server log file in the project directory (e.g., sample.log).
Run the script: python log_analysis.py.
View results in the terminal or the generated log_analysis_results.csv file.
Sample Outputs
Requests per IP: Displays each IP and its request count.
Most Accessed Endpoint: Shows the most accessed endpoint and the number of times it was accessed.
Suspicious Activities: Lists flagged IPs and their failed login attempt counts.
This tool is ideal for gaining insights into server traffic and detecting potential security issues efficiently.

##Explaining the code indetail:
____________________________________________________________________________________
1. count_requests_per_ip(log_file)
This function counts the number of requests made by each unique IP address in the log file.

Input: A log file containing entries where each line corresponds to a logged HTTP request.
Process:
It uses the re.search function to extract the IP address at the beginning of each log entry using a regular expression (^(\d+\.\d+\.\d+\.\d+)).
A Counter object is used to track how many times each IP address appears in the file.
If an IP address is found, its count is incremented in the Counter.
Output: A Counter object containing IP addresses as keys and their corresponding request counts as values.
Purpose: This function helps identify which IPs are most active, which is useful for monitoring usage patterns or identifying potentially malicious IPs.
____________________________________________________________________________________
2. most_frequent_endpoint(log_file)
This function determines the most frequently accessed endpoint (e.g., /home, /login, /dashboard) in the log file.

Input: A log file containing HTTP request entries.
Process:
It scans each line to find HTTP methods (e.g., GET or POST) followed by a resource path, using the regular expression "(?:GET|POST)\s(\S+)".
Extracted endpoints are stored in a Counter object, which tracks their frequency.
The most_common(1) method of the Counter returns the endpoint with the highest access count.
Output: A tuple containing the most accessed endpoint and its count, or None if no endpoints are found.
Purpose: Identifying frequently accessed endpoints can highlight popular features of a website or services that are under heavy usage.
____________________________________________________________________________________
3. detect_suspicious_activity(log_file, threshold=10)
This function identifies IP addresses with excessive failed login attempts, potentially indicating brute-force attacks.

Input:
A log file with entries that may include failed login attempts.
A threshold value (default is 10) to flag suspicious activity.
Process:
It searches each line for indications of failed logins, such as HTTP status code 401 or the message "Invalid credentials."
If a failed login is detected, the IP address is extracted and its count is incremented in a Counter.
After processing all lines, IPs with failed attempts exceeding the threshold are flagged as suspicious.
Output: A dictionary with flagged IP addresses as keys and their respective failed login attempt counts as values.
Purpose: This function is critical for detecting potential security threats and identifying compromised or attacking IPs.
____________________________________________________________________________________
4. write_results_to_csv(ip_counts, most_accessed, suspicious_activities, output_file)
This function writes the analysis results to a CSV file, making it easier to share and archive the findings.

Input:
ip_counts: A Counter object containing requests per IP.
most_accessed: A tuple containing the most accessed endpoint and its count.
suspicious_activities: A dictionary of suspicious IP addresses and their failed login counts.
output_file: The name of the CSV file where results will be saved.
Process:
Opens the specified CSV file in write mode.
Writes three sections to the file:
Requests per IP: Lists IP addresses and their request counts.
Most Accessed Endpoint: Provides the endpoint and its access count.
Suspicious Activities: Lists flagged IPs and their failed login attempts.
Each section is separated by an empty line for readability.
Output: A CSV file summarizing the analysis results.
Purpose: Creating a portable and well-structured report of the analysis results for further review or integration with other systems.
____________________________________________________________________________________
