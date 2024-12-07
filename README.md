# Log Analysis Script

## Overview
This Python script processes web server log files to extract meaningful insights, including:
- Counting requests per IP address.
- Identifying the most frequently accessed endpoint.
- Detecting suspicious activity (e.g., brute force login attempts).

The script outputs results in a clear terminal format and saves them to a CSV file for further analysis.

---

## Features
1. **Requests Per IP Address**:
   - Counts and sorts the number of requests made by each IP address.

2. **Most Accessed Endpoint**:
   - Determines the endpoint accessed most frequently, along with its count.

3. **Suspicious Activity Detection**:
   - Flags IPs exceeding a configurable threshold of failed login attempts.

4. **CSV Output**:
   - Saves results to a CSV file for easy sharing and reporting.

---
