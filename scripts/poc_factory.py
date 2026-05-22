#!/usr/bin/env python3


import os
import subprocess
import sys


class POCFactory:
    
    
    def __init__(self, poc_path=None):
        
        self.poc_path = poc_path
        self.pre_patch_log_file = "/tmp/pre_patch.log"  # Temp file for pre-patch log
        if os.path.exists(self.pre_patch_log_file):
            os.remove(self.pre_patch_log_file)  # Clean up old log file if exists
    def extract_vulnerability_type_from_poc(self, poc_path=None):
        
        if poc_path is None:
            poc_path = self.poc_path
            
        if not poc_path:
            return 'Unknown'
            
        try:
            with open(poc_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Look for [TYPE] in the docstring
            lines = content.split('\n')
            for line in lines:
                if '[TYPE]' in line:
                    # Extract text after [TYPE]
                    type_part = line.split('[TYPE]')[-1].strip()
                    return type_part if type_part else 'Unknown'
            
            return 'Unknown'
        except Exception as e:
            print(f"Warning: Could not extract vulnerability type from {poc_path}: {e}")
            return 'Unknown'
    
    def run_poc_verification(self, poc_path=None, context="", timeout=30):
        
        if poc_path is None:
            poc_path = self.poc_path
            
        if not poc_path or not os.path.exists(poc_path):
            print(f"Warning - POC file not found: {poc_path}")
            return False, -1, "", "POC file not found"
        
        print(f"Running POC{' (' + context + ')' if context else ''} from {poc_path}...")
        
        try:
            # Set environment variable to help POC distinguish between phases
            env = os.environ.copy()
            env['POC_PHASE'] = context.lower().replace('-', '') if context else 'unknown'
            
            poc_cmd = ['python3.8', poc_path]
            result = subprocess.run(poc_cmd, capture_output=True, text=True, timeout=timeout, env=env)
            
            # Check POC exit code to determine vulnerability status
            vulnerability_detected = False
            if result.returncode == 1:
                vulnerability_detected = True
                status_msg = "DETECTED"
            elif result.returncode == 0:
                vulnerability_detected = False
                status_msg = "NOT DETECTED"
            elif result.returncode == 2:
                vulnerability_detected = True
                status_msg = "REQUEST FAILED"
            else:
                vulnerability_detected = True
                status_msg = f"UNEXPECTED EXIT CODE: {result.returncode}"
            
            print(f"POC execution completed: {status_msg}")
            
            # Print POC output for debugging
            if result.stdout:
                print("POC Output:")
                print(result.stdout)
            if result.stderr:
                print("POC Error Output:")
                print(result.stderr)
            
            return vulnerability_detected, result.returncode, result.stdout, result.stderr
                
        except subprocess.TimeoutExpired:
            print("Warning: POC execution timed out")
            return False, -2, "", "POC execution timed out"
        except subprocess.CalledProcessError as e:
            print(f"Warning: POC execution failed: {e}")
            return False, e.returncode, "", str(e)
        except Exception as e:
            print(f"Warning: POC execution error: {e}")
            return False, -3, "", str(e)
    
    def verify_pre_patch_vulnerability(self, poc_path=None, prompt_user=True):
        
        vulnerability_detected, exit_code, stdout, stderr = self.run_poc_verification(
            poc_path, "pre-patch"
        )

        # Store pre-patch pre patch log content in temp file for later comparison
        vul_log_content = self._read_vul_log()
        if vul_log_content:
            self._save_vul_log(vul_log_content)
            print(f"[PRE-PATCH] Stored pre patch log in temp file {self.pre_patch_log_file} (first 200 chars): {vul_log_content[:200]}...")

        if (not vulnerability_detected or exit_code != 1) and prompt_user:
            print("WARNING: No vulnerability detected in pre-patch verification!")
            print("This may indicate that the POC is not working correctly or the vulnerability is not present.")
            print("Exiting...")
            return False, vulnerability_detected, exit_code, stdout, stderr
        
        return True, vulnerability_detected, exit_code, stdout, stderr
    
    def verify_post_patch_vulnerability(self, poc_path=None):
        
        # Run standard POC verification first
        vulnerability_detected, exit_code, stdout, stderr = self.run_poc_verification(poc_path, "post-patch")
        
        # Check for log similarity comparison
        pre_patch_log_content = self._load_pre_patch_log()
        if pre_patch_log_content is not None:
            print(f"[POST-PATCH] Pre-patch had log, checking post-patch similarity...")

            post_patch_log_content = self._read_vul_log()

            if post_patch_log_content is not None:
                print(f"[POST-PATCH] Found log in post-patch phase")
                print(f"[POST-PATCH] Post-patch log content (first 200 chars): {post_patch_log_content[:200]}...")

                # Calculate similarity between pre and post patch logs
                similarity = self._calculate_log_similarity(
                    pre_patch_log_content, 
                    post_patch_log_content
                )

                print(f"[POST-PATCH] Log similarity: {similarity:.1f}%")

                # If similarity is less than 80%, consider vulnerability as fixed
                if similarity < 80.0:
                    print(f"[POST-PATCH] Log similarity ({similarity:.1f}%) < 80%, advance to next phase")
                    vulnerability_detected = False
                    exit_code = 0  # Override exit code to indicate no vulnerability
                else:
                    print(f"[POST-PATCH] Log similarity ({similarity:.1f}%) >= 80%, vulnerability still EXISTS")
                    vulnerability_detected = True
                    exit_code = 1  # Override exit code to indicate vulnerability exists
            elif exit_code != 2:
                print(f"[POST-PATCH] No log found in post-patch phase")
                print(f"[POST-PATCH] Considering vulnerability as FIXED (no log generated)")
                vulnerability_detected = False
                exit_code = 0  # Override exit code to indicate no vulnerability
        else:
            print(f"[POST-PATCH] No pre-patch log stored, using standard verification result")
        
        return vulnerability_detected, exit_code, stdout, stderr
    
    def analyze_patch_effectiveness(self, pre_patch_vulnerability, post_patch_vulnerability):
        
        if pre_patch_vulnerability and not post_patch_vulnerability:
            return "SUCCESS", "Vulnerability was present before patching and is now fixed."
        elif pre_patch_vulnerability and post_patch_vulnerability:
            return "FAILED", "Vulnerability is still present after patching."
        elif not pre_patch_vulnerability and not post_patch_vulnerability:
            return "INCONCLUSIVE", "No vulnerability was detected before or after patching."
        else:
            return "UNEXPECTED", "Vulnerability was not detected initially but appeared after patching."
    
    def print_patch_verification_results(self, pre_patch_vulnerability, post_patch_vulnerability):
        
        patch_status, status_message = self.analyze_patch_effectiveness(
            pre_patch_vulnerability, post_patch_vulnerability
        )
        
        print(f"\nPATCH VERIFICATION {patch_status}!")
        print(status_message)
        print(f"Final Patch Status: {patch_status}")
        print("="*60)
    
    def extract_poc_metadata(self, poc_path=None):
        
        if poc_path is None:
            poc_path = self.poc_path
            
        if not poc_path:
            return {'app': '', 'cve': '', 'type': '', 'method': '', 'description': '', 'crash_fields': [], 'target_url': '', 'params': ''}
        
        try:
            # Try to use the standardized metadata extraction if utils is available
            import sys
            import os
            
            # Add the poces directory to path to import utils
            poces_dir = os.path.join(os.path.dirname(os.path.dirname(poc_path)), 'poces')
            if os.path.exists(poces_dir) and poces_dir not in sys.path:
                sys.path.insert(0, poces_dir)
            
            try:
                from utils import get_poc_metadata_from_file
                metadata = get_poc_metadata_from_file(poc_path)
                return metadata
            except ImportError:
                # Fallback to the original method
                return self._extract_metadata_fallback(poc_path)
                
        except Exception as e:
            print(f"Warning: Could not extract metadata from {poc_path}: {e}")
            return {'app': '', 'cve': '', 'type': '', 'method': '', 'description': '', 'crash_fields': [], 'target_url': '', 'params': ''}
    
    def _extract_metadata_fallback(self, poc_path):
        
        try:
            with open(poc_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            metadata = {'app': '', 'cve': '', 'type': '', 'method': '', 'description': '', 'crash_fields': [], 'target_url': '', 'params': ''}
            
            # Look for metadata in the docstring
            lines = content.split('\n')
            for line in lines:
                if '[APP]' in line:
                    metadata['app'] = line.split('[APP]')[-1].strip()
                elif '[CVE]' in line:
                    metadata['cve'] = line.split('[CVE]')[-1].strip()
                elif '[TYPE]' in line:
                    metadata['type'] = line.split('[TYPE]')[-1].strip()
                elif '[METHOD]' in line:
                    metadata['method'] = line.split('[METHOD]')[-1].strip()
                elif '[CRASH_FIELDS]' in line:
                    crash_fields_str = line.split('[CRASH_FIELDS]')[-1].strip()
                    if crash_fields_str:
                        metadata['crash_fields'] = [field.strip() for field in crash_fields_str.split(',') if field.strip()]
                elif '[TARGET_URL]' in line:
                    metadata['target_url'] = line.split('[TARGET_URL]')[-1].strip()
                elif '[PARAMS]' in line:
                    metadata['params'] = line.split('[PARAMS]')[-1].strip()
            
            return metadata
        except Exception as e:
            print(f"Warning: Fallback metadata extraction failed for {poc_path}: {e}")
            return {'app': '', 'cve': '', 'type': '', 'method': '', 'description': '', 'crash_fields': [], 'target_url': '', 'params': ''}

    def is_standardized_poc(self, poc_path=None):
        
        if poc_path is None:
            poc_path = self.poc_path
            
        if not poc_path or not os.path.exists(poc_path):
            return False
        
        try:
            with open(poc_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for standardized imports and patterns
            standardized_patterns = [
                'from utils import create_standard_poc_runner',
                'from utils import get_poc_metadata_from_file',
                'create_standard_poc_runner(',
                'get_poc_metadata_from_file(',
                'poc_runner.run_test('
            ]
            
            return any(pattern in content for pattern in standardized_patterns)
            
        except Exception as e:
            print(f"Warning: Could not check if POC is standardized: {e}")
            return False

    def run_standardized_poc_test(self, target_url, poc_config, context=""):
        
        try:
            # Add the poces directory to path to import utils
            poces_dir = os.path.join(os.path.dirname(__file__), 'poces')
            if os.path.exists(poces_dir) and poces_dir not in sys.path:
                sys.path.insert(0, poces_dir)
                
            from utils import create_standard_poc_runner
            
            # Extract metadata from config
            cve_id = poc_config.get('cve', 'Unknown')
            app_name = poc_config.get('app', 'Unknown')
            vuln_type = poc_config.get('type', 'Unknown')
            
            # Create POC runner
            poc_runner = create_standard_poc_runner(cve_id, app_name, vuln_type)
            
            # Set environment for phase tracking
            env = os.environ.copy()
            env['POC_PHASE'] = context.lower().replace('-', '') if context else 'unknown'
            
            print(f"Running standardized POC{' (' + context + ')' if context else ''}: {app_name} {cve_id}")
            
            # Run the test
            method = poc_config.get('method', 'GET')
            params = poc_config.get('params', {})
            data = poc_config.get('data', {})
            
            if method.upper() == 'POST' and data:
                exit_code = poc_runner.run_test(target_url, method='POST', data=data)
            else:
                exit_code = poc_runner.run_test(target_url, method='GET', params=params)
            
            vulnerability_detected = (exit_code == 1)
            return vulnerability_detected, exit_code, "", ""
            
        except Exception as e:
            print(f"Error running standardized POC: {e}")
            return False, -1, "", str(e)

    @staticmethod
    def create_poc_factory(poc_path=None):
        
        return POCFactory(poc_path)

    def get_poc_request_data(self, poc_path=None):
        
        metadata = self.extract_poc_metadata(poc_path)
        
        # Parse parameters from string format to dict
        parsed_params = {}
        if metadata.get('params'):
            try:
                # Handle URL query string format like "option=com_fields&view=fields&layout=modal&list[fullordering]=*"
                import urllib.parse
                parsed_params = dict(urllib.parse.parse_qsl(metadata['params']))
            except Exception as e:
                print(f"Warning: Could not parse POC params '{metadata['params']}': {e}")
        
        return {
            'url': metadata.get('target_url', 'http://localhost/slice_analysis'),
            'method': metadata.get('method', 'GET'),
            'params': parsed_params,
            'crash_fields': metadata.get('crash_fields', [])
        }

    def _calculate_log_similarity(self, content1, content2):
        
        if not content1 or not content2:
            return 0.0
        
        # Convert to strings if they're bytes
        if isinstance(content1, bytes):
            try:
                content1 = content1.decode('utf-8', errors='replace')
            except:
                content1 = str(content1)
        
        if isinstance(content2, bytes):
            try:
                content2 = content2.decode('utf-8', errors='replace')
            except:
                content2 = str(content2)
        
        # Take first 200 characters as specified
        content1 = content1[:200]
        content2 = content2[:200]
        
        # Simple character-by-character comparison
        if len(content1) == 0 and len(content2) == 0:
            return 100.0
        
        min_length = min(len(content1), len(content2))
        max_length = max(len(content1), len(content2))
        
        if max_length == 0:
            return 100.0
        
        matches = 0
        for i in range(min_length):
            if content1[i] == content2[i]:
                matches += 1
        
        # Calculate similarity considering both matching characters and length difference
        similarity = (matches / max_length) * 100
        
        return similarity
    
    def _read_vul_log(self):
        
        if os.path.exists('/tmp/sqli.log'):
            vul_log_path = '/tmp/sqli.log'
        elif os.path.exists('/tmp/cmdi.log'):
            vul_log_path = '/tmp/cmdi.log'
        else:
            print("No vulnerability log file found.")
            return None
        try:
            if os.path.exists(vul_log_path) and os.path.getsize(vul_log_path) > 0:
                with open(vul_log_path, 'rb') as f:
                    log_bytes = f.read()
                
                # Try to decode the binary content
                try:
                    log_content = log_bytes.decode('utf-8', errors='replace')
                except UnicodeDecodeError:
                    log_content = log_bytes.decode('latin1')
                
                return log_content
            return None
        except Exception as e:
            print(f"Error reading vulnerability log: {e}")
            return None

    def _save_vul_log(self, content):
        
        try:
            with open(self.pre_patch_log_file, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception as e:
            print(f"Error saving pre-patch log to {self.pre_patch_log_file}: {e}")
    
    def _load_pre_patch_log(self):
        
        try:
            if os.path.exists(self.pre_patch_log_file) and os.path.getsize(self.pre_patch_log_file) > 0:
                with open(self.pre_patch_log_file, 'r', encoding='utf-8') as f:
                    return f.read()
            return None
        except Exception as e:
            print(f"Error loading pre-patch log from {self.pre_patch_log_file}: {e}")
            return None


# Convenience functions for direct use
def run_poc_verification(poc_path, context="", timeout=30):
    
    factory = POCFactory(poc_path)
    return factory.run_poc_verification(poc_path, context, timeout)


def extract_vulnerability_type(poc_path):
    
    factory = POCFactory(poc_path)
    return factory.extract_vulnerability_type_from_poc(poc_path)


def get_poc_metadata(poc_path):
    
    factory = POCFactory(poc_path)
    return factory.extract_poc_metadata(poc_path)


if __name__ == "__main__":
    # Example usage and testing
    if len(sys.argv) > 1:
        poc_path = sys.argv[1]
        factory = POCFactory(poc_path)
        
        print("=== POC Metadata ===")
        metadata = factory.extract_poc_metadata()
        for key, value in metadata.items():
            print(f"{key}: {value}")
        
        print(f"\nStandardized POC: {factory.is_standardized_poc()}")
        
        print("\n=== Running POC ===")
        vulnerability_detected, exit_code, stdout, stderr = factory.run_poc_verification()
        print(f"Vulnerability Detected: {vulnerability_detected}")
        print(f"Exit Code: {exit_code}")
    else:
        print("Usage: python poc_factory.py <poc_script_path>")