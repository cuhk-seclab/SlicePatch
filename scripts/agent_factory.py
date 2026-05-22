import json
import os
import shutil
import openai
import subprocess
import sys
import tempfile
import shlex
import time
from utils import *
from utils import *

class VulnerabilityLocator(TokenTracker, LLMApiHelper, FileOperationHelper, JsonOperationHelper):
    
    
    def __init__(self, assembled_dir, poc_path, model_choice=['deepseek-chat']):
        TokenTracker.__init__(self, use_global_budget=True)  # Use global budget manager
        LLMApiHelper.__init__(self)
        self.assembled_dir = assembled_dir
        self.poc_path = poc_path
        self.model_choice = model_choice if isinstance(model_choice, list) else [model_choice]
    
    def generate_tree_structure(self):
        
        try:
            # Change to the working directory first
            original_cwd = os.getcwd()
            os.chdir(self.assembled_dir)
            
            # Execute find command with tree formatting
            cmd = f"find . -print | sed -e 's;[^/]*/;|____;g;s;____|; |;g'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Error generating tree structure: {result.stderr}")
                return None
                
            tree_output = result.stdout
            # Replace + with / in the tree structure
            tree_output = tree_output.replace('+', '/')
            
            return tree_output
            
        except Exception as e:
            print(f"Error generating tree structure: {e}")
            return None
        finally:
            os.chdir(original_cwd)
    
    def read_poc_content(self):
        
        return self.read_file_content(self.poc_path)
    
    def query_llm_for_file_path(self, tree_structure, poc_content, model_choice=None):
        
        if model_choice is None:
            model_choice = self.model_choice
        elif not isinstance(model_choice, list):
            model_choice = [model_choice]
            
        prompt = f"""
=== VULNERABILITY FILE IDENTIFICATION TASK ===

OBJECTIVE: Analyze the directory structure and POC script to identify which file contains the vulnerable logic.

DIRECTORY TREE STRUCTURE:
{tree_structure}

POC SCRIPT CONTENT:
{poc_content}

ANALYSIS REQUIREMENTS:
Please analyze the POC script to understand:
1. What type of vulnerability it's testing for
2. What endpoints/files it's targeting  
3. What parameters or inputs it's using

TASK:
Based on your analysis, identify the file path that most likely contains the final vulnerable logic that gets triggered by the POC.

OUTPUT FORMAT:
Your response must be in JSON format with no additional text or explanations:

```json
{{
    "file_path": "path/to/vulnerable/file.php"
}}
```
"""

        # Estimate input tokens
        estimated_input_tokens = self.estimate_tokens(prompt)
        
        # Check budget before making LLM calls
        self.abort_if_budget_exceeded(estimated_input_tokens, "vulnerability_file_identification")

        for model in model_choice:
            print(f"Attempting to identify file path with model: {model}")
            try:
                client = self.get_client(model)
                
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "You are an expert security researcher specializing in vulnerability analysis. Analyze the provided information to identify vulnerable code locations."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=1.0,
                    timeout=180
                )
                
                content = response.choices[0].message.content.strip()
                
                # Extract token usage information
                usage = response.usage
                input_tokens = usage.prompt_tokens if hasattr(usage, 'prompt_tokens') else estimated_input_tokens
                output_tokens = usage.completion_tokens if hasattr(usage, 'completion_tokens') else self.estimate_tokens(content)
                
                # Calculate and log token cost
                cost, input_cost, output_cost = self.calculate_token_cost(model, input_tokens, output_tokens)
                self.log_token_usage(model, input_tokens, output_tokens, cost, "file_path_detection")
                
                # Extract JSON from response
                content = self.extract_json_from_response(content)
                
                try:
                    result = self.parse_json_string(content)
                    if result and 'file_path' in result:
                        print(f"Successfully identified file path with model: {model}")
                        return result['file_path']
                    else:
                        print(f"Model {model} response missing 'file_path' key")
                        continue
                except Exception as e:
                    print(f"Error parsing JSON response from {model}: {e}")
                    print(f"Raw response: {content}")
                    continue
                    
            except Exception as e:
                print(f"Error querying {model} for file path: {e}")
                continue
        
        print("All models failed to identify file path")
        return None
    
    def query_llm_for_vulnerable_line(self, file_content, file_path, poc_content, model_choice=None):
        
        if model_choice is None:
            model_choice = self.model_choice
        elif not isinstance(model_choice, list):
            model_choice = [model_choice]
            
        prompt = f"""
=== VULNERABLE LINE IDENTIFICATION TASK ===

OBJECTIVE: Analyze the file content and POC script to identify the specific vulnerable line or determine if another file should be examined.

FILE INFORMATION:
File Path: {file_path}

FILE CONTENT:
{file_content}

POC SCRIPT CONTENT:
{poc_content}

ANALYSIS TASK:
Please analyze this file to determine if it contains the vulnerable line(s), i.e., final sinks that the POC exploits.

RESPONSE OPTIONS:

Option 1 - If you can identify the specific vulnerable line:
```json
{{
    "vul_lines": ["content of the vulnerable line1", "content of the vulnerable line2", ...]
}}
```

Option 2 - If this file doesn't contain the vulnerable line or you need to examine another file:
```json
{{
    "file_path": "path/to/next/file.php"
}}
```

OUTPUT FORMAT:
Your response must be in JSON format with no additional text or explanations.
"""

        # Estimate input tokens
        estimated_input_tokens = self.estimate_tokens(prompt)
        
        # Check budget before making LLM calls
        self.abort_if_budget_exceeded(estimated_input_tokens, "vulnerability_line_identification")

        for model in model_choice:
            print(f"Attempting to identify vulnerable line with model: {model}")
            try:
                client = self.get_client(model)
                
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "You are an expert security researcher specializing in vulnerability analysis. Analyze code to identify specific vulnerable lines."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=1.0,
                    timeout=180
                )
                
                content = response.choices[0].message.content.strip()
                
                # Extract token usage information
                usage = response.usage
                input_tokens = usage.prompt_tokens if hasattr(usage, 'prompt_tokens') else estimated_input_tokens
                output_tokens = usage.completion_tokens if hasattr(usage, 'completion_tokens') else self.estimate_tokens(content)
                
                # Calculate and log token cost
                cost, input_cost, output_cost = self.calculate_token_cost(model, input_tokens, output_tokens)
                self.log_token_usage(model, input_tokens, output_tokens, cost, "vulnerable_line_detection")
                
                # Extract JSON from response
                content = self.extract_json_from_response(content)
                
                try:
                    result = self.parse_json_string(content)
                    if result:
                        print(f"Successfully got response from model: {model}")
                        return result
                    else:
                        print(f"Model {model} returned empty result")
                        continue
                except Exception as e:
                    print(f"Error parsing JSON response from {model}: {e}")
                    print(f"Raw response: {content}")
                    continue
                    
            except Exception as e:
                print(f"Error querying {model} for vulnerable line: {e}")
                continue
        
        print("All models failed to identify vulnerable line")
        return None
    
    def find_line_number(self, file_path, vulnerable_line):
        
        return self.find_line_number_in_file(file_path, vulnerable_line)

    def is_complete_statement(self, file_path, line_number):
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            if line_number <= 0 or line_number > len(lines):
                return False
            
            line_content = lines[line_number - 1].rstrip('\n\r')
            
            # Empty line is not complete
            if not line_content.strip():
                return False
            
            # Create a temporary PHP file to test the statement
            with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as temp_file:
                # Wrap the line in PHP tags and try to parse it
                test_code = f"<?php\n{line_content}\n?>"
                temp_file.write(test_code)
                temp_file_path = temp_file.name
            
            try:
                # Use PHP to check syntax of the statement
                result = subprocess.run(
                    ['php', '-l', temp_file_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # If PHP syntax check passes, the statement is syntactically complete
                if result.returncode == 0:
                    # Additional check: try to parse it as a complete statement
                    # by wrapping it in a function context
                    function_test_code = f"<?php\nfunction test() {{\n{line_content}\n}}\n?>"
                    
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as func_temp_file:
                        func_temp_file.write(function_test_code)
                        func_temp_file_path = func_temp_file.name
                    
                    try:
                        func_result = subprocess.run(
                            ['php', '-l', func_temp_file_path],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        
                        # If both tests pass, it's a complete statement
                        return func_result.returncode == 0
                        
                    finally:
                        os.unlink(func_temp_file_path)
                else:
                    # If basic syntax check fails, try to determine if it's incomplete
                    # vs. actually erroneous by testing with a semicolon
                    if not line_content.strip().endswith((';', '}', '{')):
                        test_with_semicolon = f"<?php\n{line_content};\n?>"
                        
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as semi_temp_file:
                            semi_temp_file.write(test_with_semicolon)
                            semi_temp_file_path = semi_temp_file.name
                        
                        try:
                            semi_result = subprocess.run(
                                ['php', '-l', semi_temp_file_path],
                                capture_output=True,
                                text=True,
                                timeout=10
                            )
                            
                            # If adding semicolon makes it valid, original was incomplete
                            if semi_result.returncode == 0:
                                return False
                            
                        finally:
                            os.unlink(semi_temp_file_path)
                    
                    return False
                    
            finally:
                os.unlink(temp_file_path)
                
        except subprocess.TimeoutExpired:
            print(f"PHP syntax check timed out for line {line_number}")
            return False
        except Exception as e:
            print(f"Error checking statement completeness with PHP: {e}")
            # Fallback to basic heuristic if PHP check fails
            try:
                line_content = lines[line_number - 1].strip()
                return line_content.endswith((';', '}', '{')) and bool(line_content)
            except:
                return False

    def find_statement_start_line(self, file_path, current_line):
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            if current_line <= 0 or current_line > len(lines):
                return [current_line]
            
            # First, find the previous statement ending
            prev_statement_end = self._find_previous_statement_end(lines, current_line)
            
            if prev_statement_end is None:
                # No previous statement end found, start from beginning
                start_line = 1
            else:
                # Start from the line after the previous statement end
                start_line = prev_statement_end + 1
            
            # Find the next statement ending after current_line
            next_statement_end = self._find_next_statement_end(lines, current_line)
            
            if next_statement_end is None:
                # No next statement end found, use end of file
                end_line = len(lines)
            else:
                end_line = next_statement_end
            
            # Extract the code block from start_line to end_line
            if start_line <= current_line <= end_line:
                code_lines = []
                for i in range(start_line - 1, end_line):
                    if i < len(lines):
                        code_lines.append(lines[i].rstrip('\n\r'))
                
                if code_lines:
                    # Test if this forms a valid PHP statement block
                    code_snippet = '\n'.join(code_lines)
                    if self._test_php_code_validity(code_snippet):
                        # Return all non-empty lines from start_line to current_line
                        result_lines = []
                        for line_num in range(start_line, current_line + 1):
                            if line_num <= len(lines):
                                line_content = lines[line_num - 1].strip()
                                # Include non-empty lines and lines with meaningful content
                                if line_content and not line_content.startswith('//') and not line_content.startswith('/*'):
                                    result_lines.append(line_num)
                        return result_lines if result_lines else [start_line]
            
            # If the block validation fails, fallback to heuristic method
            heuristic_start = self._find_statement_start_heuristic(lines, current_line)
            # Return all non-empty lines from heuristic start to current line
            result_lines = []
            for line_num in range(heuristic_start, current_line + 1):
                if line_num <= len(lines):
                    line_content = lines[line_num - 1].strip()
                    if line_content and not line_content.startswith('//') and not line_content.startswith('/*'):
                        result_lines.append(line_num)
            return result_lines if result_lines else [heuristic_start]
            
        except Exception as e:
            print(f"Error finding statement start: {e}")
            return [current_line]

    def _find_previous_statement_end(self, lines, current_line):
        
        import re
        
        # Look backwards from current_line - 1
        for line_num in range(current_line - 1, 0, -1):
            line_content = lines[line_num - 1].strip()
            
            # Skip empty lines and comments
            if not line_content or line_content.startswith('//') or line_content.startswith('/*'):
                continue
            
            # Check for statement endings
            if line_content.endswith((';', '}', '{')):
                return line_num
            
            # Check for control structure endings that don't need semicolons
            control_endings = [
                r'^\s*}\s*$',                    # Closing brace alone
                r'^\s*}\s*else\s*{\s*$',        # } else {
                r'^\s*}\s*elseif\s*\([^)]*\)\s*{\s*$',  # } elseif (...) {
                r'^\s*}\s*catch\s*\([^)]*\)\s*{\s*$',   # } catch (...) {
                r'^\s*}\s*finally\s*{\s*$',     # } finally {
            ]
            
            for pattern in control_endings:
                if re.match(pattern, line_content, re.IGNORECASE):
                    return line_num
        
        return None

    def _find_next_statement_end(self, lines, current_line):
        
        import re
        
        # Look forward from current_line + 1
        for line_num in range(current_line + 1, len(lines) + 1):
            if line_num > len(lines):
                break
                
            line_content = lines[line_num - 1].strip()
            
            # Skip empty lines and comments
            if not line_content or line_content.startswith('//') or line_content.startswith('/*'):
                continue
            
            # Check for statement endings
            if line_content.endswith((';', '}', '{')):
                return line_num
            
            # Check for control structure endings
            control_endings = [
                r'^\s*}\s*$',                    # Closing brace alone
                r'^\s*}\s*else\s*{\s*$',        # } else {
                r'^\s*}\s*elseif\s*\([^)]*\)\s*{\s*$',  # } elseif (...) {
                r'^\s*}\s*catch\s*\([^)]*\)\s*{\s*$',   # } catch (...) {
                r'^\s*}\s*finally\s*{\s*$',     # } finally {
            ]
            
            for pattern in control_endings:
                if re.match(pattern, line_content, re.IGNORECASE):
                    return line_num
        
        return None

    def _test_php_code_validity(self, code_snippet):
        
        try:
            # Wrap the code in a function context for testing
            test_code = f"<?php\nfunction test() {{\n{code_snippet}\n}}\n?>"
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as temp_file:
                temp_file.write(test_code)
                temp_file_path = temp_file.name
            
            try:
                result = subprocess.run(
                    ['php', '-l', temp_file_path],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                return result.returncode == 0
                
            finally:
                os.unlink(temp_file_path)
                
        except Exception as e:
            print(f"Error testing PHP code validity: {e}")
            return False

    def _find_statement_start_heuristic(self, lines, current_line):
        
        import re
        
        # Look backwards from current line
        for line_num in range(current_line, 0, -1):
            line_content = lines[line_num - 1].strip()
            
            # Skip empty lines and comments
            if not line_content or line_content.startswith('//') or line_content.startswith('/*'):
                continue
            
            # Check for obvious statement starters
            statement_starters = [
                r'^\s*\$\w+\s*=',      # Variable assignment
                r'^\s*\$\w+\s*\.',     # String concatenation assignment
                r'^\s*\$\w+\s*\[',     # Array assignment
                r'^\s*if\s*\(',        # Control structures
                r'^\s*while\s*\(',
                r'^\s*for\s*\(',
                r'^\s*foreach\s*\(',
                r'^\s*switch\s*\(',
                r'^\s*echo\s+',        # Echo statements
                r'^\s*print\s+',       # Print statements
                r'^\s*return\s+',      # Return statements
                r'^\s*function\s+',    # Function definition
                r'^\s*class\s+',       # Class definition
            ]
            
            # Check if this line starts a statement
            is_starter = any(re.match(pattern, line_content, re.IGNORECASE) for pattern in statement_starters)
            
            # Check if previous line clearly ends a statement
            if line_num > 1:
                prev_line = lines[line_num - 2].strip()
                statement_enders = [';', '}', '{']
                
                if any(prev_line.endswith(ender) for ender in statement_enders):
                    if is_starter:
                        return line_num
            elif line_num == 1 and is_starter:
                return line_num
        
        # If nothing found, return original line
        return current_line

    def save_targets_csv(self, file_path, line_numbers):
        
        try:
            targets_csv_path = os.path.join(self.assembled_dir, 'targets.csv')
            for line_number in line_numbers:
                target_entry = f"{file_path}:{line_number}"
                with open(targets_csv_path, 'a') as f:
                    f.write(f"{target_entry}\n")

            print(f"Saved vulnerable locations to {targets_csv_path}")
            return True
            
        except Exception as e:
            print(f"Error saving targets.csv: {e}")
            return False
    
    def locate_vulnerability(self, max_iterations=5):
        
        print("Starting vulnerability localization...")
        
        # Step 1: Generate tree structure
        tree_structure = self.generate_tree_structure()
        if not tree_structure:
            print("Failed to generate tree structure")
            return False, None
        
        # Read POC content
        poc_content = self.read_poc_content()
        if not poc_content:
            print("Failed to read POC content")
            return False, None
        
        # Step 2: Get initial file path from LLM
        current_file_path = self.query_llm_for_file_path(tree_structure, poc_content)
        init_file_path = current_file_path
        if not current_file_path:
            print("Failed to get initial file path from LLM")
            return False, None

        print(f"LLM suggested initial file: {current_file_path}")
        
        # Step 3: Iteratively examine files until vulnerable line is found
        for iteration in range(max_iterations):
            print(f"\nIteration {iteration + 1}: Examining {current_file_path}")
            
            # Convert / back to + for file system path
            fs_file_path = current_file_path.replace('/', '+')
            if (not fs_file_path.startswith('+')):
                fs_file_path = '+' + fs_file_path
            full_file_path = os.path.join(self.assembled_dir, fs_file_path)
            
            if not os.path.exists(full_file_path):
                print(f"File does not exist: {full_file_path}")
                file_content = f'The file {current_file_path} you are trying to access does not exist. Please still try {init_file_path}'
            else:
                # Read file content
                file_content = self.read_file_content(full_file_path)
                if not file_content:
                    print(f"Error reading file {full_file_path}")
                    file_content = f'The file {current_file_path} you are trying to access does not exist. Please still try {init_file_path}'
            
            # Query LLM for vulnerable line or next file
            llm_response = self.query_llm_for_vulnerable_line(file_content, current_file_path, poc_content)
            if not llm_response:
                print("Failed to get response from LLM")
                return False, None
            
            if 'vul_lines' in llm_response:
                # Found vulnerable line
                vulnerable_lines = llm_response['vul_lines']
                print(f"Found vulnerable lines: {vulnerable_lines}")

                # Find line numbers and check for statement completeness
                line_numbers = []
                info = ""
                for vul_line in vulnerable_lines:
                    line_number = self.find_line_number(full_file_path, vul_line)
                    if line_number:
                        print(f"Found line {line_number} for: {vul_line}")
                        
                        # Check if this is a complete statement
                        if self.is_complete_statement(full_file_path, line_number):
                            print(f"Line {line_number} is a complete statement")
                            final_line_numbers = [line_number]
                        else:
                            print(f"Line {line_number} is incomplete, finding statement lines...")
                            final_line_numbers = self.find_statement_start_line(full_file_path, line_number)
                            print(f"Statement includes lines: {final_line_numbers}")
                        
                        # Add all lines to the result
                        line_numbers.extend(final_line_numbers)
                        if len(final_line_numbers) == 1:
                            info += f"{vul_line} in {full_file_path} at line {final_line_numbers[0]}\n"
                        else:
                            info += f"{vul_line} in {full_file_path} at lines {final_line_numbers}\n"

                if line_numbers:
                    # Save to targets.csv
                    target_file_path = fs_file_path  # Keep + format for targets.csv
                    if not target_file_path.startswith(self.assembled_dir):
                        target_file_path = os.path.join(self.assembled_dir.split('/')[-1], target_file_path)
                    success = self.save_targets_csv(target_file_path, line_numbers)
                    if success:
                        print(f"Successfully located vulnerability: {target_file_path}:{line_numbers}")
                        
                        # Print final usage summary
                        self.print_usage_summary("VULNERABILITY LOCALIZATION")
                        
                        # Save token usage log
                        self.save_usage_log(operation_name="vulnerability_locator")
                        return True, info.strip()
                    else:
                        print("Failed to save targets.csv")
                        return False, None
                else:
                    print("Failed to find line number for vulnerable line")
                    return False, None
                    
            elif 'file_path' in llm_response:
                # LLM wants to examine another file
                current_file_path = llm_response['file_path']
                print(f"LLM suggests examining next file: {current_file_path}")
                continue
            else:
                print("LLM response missing both 'vul_line' and 'file_path'")
                return False, None
        
        print(f"Reached maximum iterations ({max_iterations}) without finding vulnerable line")
        
        # Print final usage summary even if failed
        self.print_usage_summary("VULNERABILITY LOCALIZATION")
        
        # Save token usage log
        self.save_usage_log(operation_name="vulnerability_locator")
        return False, None

class PatchFactory(TokenTracker, LLMApiHelper, FileOperationHelper, JsonOperationHelper):

    def __init__(self, app_name, vul_type, working_dir, poc_path):
        TokenTracker.__init__(self, use_global_budget=True)  # Always use global budget
        LLMApiHelper.__init__(self)
        self.app_name = app_name
        self.vul_type = vul_type
        self.working_dir = working_dir
        self.poc_path = poc_path

    def _generate_patch(self, code_content, prompt_intro, feedback="", model_choice=['deepseek'], all_previous_patches="", attempt_num=1):
        
        if not self.deepseek_api_key and not self.vapi_key:
            print("API key not provided. Skipping patch generation.")
            return {"error": "API key not provided"}, None

        print("\nGenerating patch via LLM...")
        poc_content = self.read_file_content(self.poc_path) if self.poc_path else ""

        prompt = f"""
=== VULNERABILITY PATCH GENERATION TASK ===

{prompt_intro}

REQUIREMENTS:
Analyze the code and provide a vulnerability patch with the following requirements:

1. OUTPUT FORMAT: Pure JSON only, no additional text or explanations.

2. OBJECTIVE: Analyze the PoC and identify ALL vulnerable sink points that could lead to exploitation, and apply EFFECTIVE fixes to mitigate risks.

3. JSON STRUCTURE:
```json
{{
    "reason": "Brief explanation of vulnerability cause (1-2 sentences)",
    "countermeasure": "Key changes needed to fix the vulnerability (be specific about fields and methods)",
    "feedback": "My feedback about previous patches",
    "type": "file or lines - use 'lines' for minimal changes or large files, 'file' for complete file replacement",
    "patch": {{
        "full_file_path_1.php": "Complete patched content (if type=file) OR line mapping object (if type=lines)",
        "full_file_path_2.php": "Complete patched content (if type=file) OR line mapping object (if type=lines)",
        # Add more files as needed
    }}
}}
```

4. PATCH REQUIREMENTS:
   ✓ Ensure JSON validity (proper escaping for newlines/quotes by using backslashes)
   ✓ Choose appropriate type:
     - Use "lines" for minimal changes (few lines modified) or large files
     - Use "file" for extensive changes or small files
   ✓ For type="file": Include complete file content with modifications
   ✓ For type="lines": Use line mapping format where each key is original code content, value is replacement content. Make sure the keys are exact matches to the original lines.
   ✓ Preserve ALL original whitespace/indentation EXACTLY
   ✓ Include modified files ONLY, DO NOT include unchanged files
   ✓ Add new comments in format /* [Patch] <comment here> */ if you modify any lines
   ✓ If query prepare statements are used, ensure they are properly binded
   ✓ Ensure no syntax errors in patched code
   ✓ Keep correct fixes presented in previous patches in your patch exactly, if any, as we restart from original unmodified app code each time
   ✓ DO NOT define any whitelists (e.g., allowed fields) or blacklists (e.g., disallowed fields) by yourself, as this could break the app functionality

5. FILE TYPE PATCH FORMAT EXAMPLE:
    "patch": {{
        "full_file_path.php": "Complete patched file content here"
    }}
   
6. LINES TYPE PATCH FORMAT EXAMPLE:
    "patch": {{
        "full_file_path.php": {{
            "original code content of one or multiple lines" : "replacement code content /* [Patch] Description */"
        }}
    }}

7. TYPE SELECTION GUIDELINES:
   - Use type="lines" when:
     * Making minimal changes (few lines modified)
     * Working with large files
     * Only specific lines need modification
   - Use type="file" when:
     * Making extensive changes
     * Working with small files
     * Adding new functions or major structural changes
     * Multiple scattered changes throughout the file

CODE TO PATCH:
```
{code_content}
```

POC USED TO TRIGGER THE VULNERABILITY:
{poc_content}"""

        if len(all_previous_patches) > 0:
            prompt += f"""

PREVIOUS PATCHES YOU HAVE GENERATED IN THIS ROUND (INCLUDING MY FEEDBACK):
```
{all_previous_patches}
```"""

        if len(feedback) > 0 and len(all_previous_patches) == 0:
            # Only show separate feedback if no previous patches (i.e., first attempt with feedback)
            prompt += f"""

MY FEEDBACK ON THE LAST PATCH:
{feedback}"""

        # Estimate input tokens
        estimated_input_tokens = self.estimate_tokens(prompt)
        
        # Check budget limits before making API call
        self.abort_if_budget_exceeded(estimated_input_tokens, f"patch_generation_attempt_{attempt_num}")

        # log the prompt for debugging
        with open('/tmp/patch_prompt.log', 'a+') as f:
            f.write(f"Prompt for model {model_choice} (Attempt #{attempt_num}):\n{prompt}\n\n------------\n\n")

        if not isinstance(model_choice, list):
            model_choice = [model_choice]

        for model in model_choice:
            print(f"\nAttempting to generate patch with model: {model} (Attempt #{attempt_num})")
            
            client = self.get_client(model)
            
            start_time = time.time()
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "system", "content": "You are an expert security engineer specializing in PHP vulnerability analysis and patching. Your primary goal is to produce secure, robust, and production-ready code patches. You must follow all security best practices."},
                              {"role": "user", "content": prompt}],
                    temperature=1.0,
                    max_tokens=16000,
                    stream=False,
                    timeout=600
                )
                content = response.choices[0].message.content
                
                # Extract token usage information
                usage = response.usage
                input_tokens = usage.prompt_tokens if hasattr(usage, 'prompt_tokens') else estimated_input_tokens
                output_tokens = usage.completion_tokens if hasattr(usage, 'completion_tokens') else self.estimate_tokens(content)
                
                # Calculate and log token cost
                cost, input_cost, output_cost = self.calculate_token_cost(model, input_tokens, output_tokens)
                self.log_token_usage(model, input_tokens, output_tokens, cost, attempt_num)
                
            except Exception as e:
                print(f"Error calling {model} API (timeout or other error): {str(e)}")
                continue
            finally:
                end_time = time.time()
                print(f"Model {model} execution time: {end_time - start_time:.2f} seconds")

            try:
                content = self.extract_json_from_response(content)
                if content.startswith('{') and content.endswith('}'):
                    content = content.strip()
                else:
                    print(f"Warning: Response from {model} does not contain valid JSON format. Attempting to parse as is.")
                
                try:
                    patch_data = self.parse_json_string(content)
                    if not patch_data or 'patch' not in patch_data or not isinstance(patch_data['patch'], dict) or not patch_data['patch']:
                        print(f"Invalid patch structure from {model}. Missing or empty 'patch' field.")
                        patch_data = self.fix_json_format(content)
                        if not patch_data or 'patch' not in patch_data or not isinstance(patch_data['patch'], dict) or not patch_data['patch']:
                            print(f"Failed to fix JSON format for {model}.")
                            continue
                        else:
                            print(f"Successfully fixed JSON format for {model}.")

                    # Validate type field
                    patch_type = patch_data.get('type', 'file')  # Default to 'file' for backward compatibility
                    if patch_type not in ['file', 'lines']:
                        print(f"Invalid patch type from {model}: {patch_type}. Must be 'file' or 'lines'.")
                        continue

                    print(f"Successfully generated patch with model: {model} (type: {patch_type})")
                    print("\n=== Vulnerability Reason ===")
                    print(patch_data.get('reason', 'No reason provided'))
                    print("\n=== Countermeasure ===")
                    print(patch_data.get('countermeasure', 'No countermeasure provided'))
                    print("\n=== Feedback ===")
                    print(patch_data.get('feedback', 'No feedback provided'))
                    
                    patch_info_path = os.path.join(self.working_dir, 'generated_patch_info.json')
                    patched_file_paths = list(patch_data.get('patch', {}).keys())
                    if not patched_file_paths:
                        print("No files to patch found in the response.")
                        continue

                    # Validate patch structure based on type
                    if patch_type == 'lines':
                        # For lines type, validate that each file contains line mappings
                        for file_path, line_mappings in patch_data['patch'].items():
                            if not isinstance(line_mappings, dict):
                                print(f"Invalid lines patch structure for {file_path}. Expected dict of line mappings.")
                                continue
                    
                    patch_dir = os.path.join(self.working_dir, 'patched')
                    if os.path.exists(patch_dir):
                        shutil.rmtree(patch_dir)
                    os.makedirs(patch_dir)
                    
                    if patch_type == 'file':
                        # For file type, save complete file content
                        for file_path, patch_content in patch_data['patch'].items():
                            full_path = os.path.join(patch_dir, os.path.basename(file_path))
                            self.write_file_content(full_path, patch_content)
                            print(f"\nPatched file saved: {full_path}")
                    else:
                        # For lines type, save line mappings as JSON
                        for file_path, line_mappings in patch_data['patch'].items():
                            mapping_file = os.path.join(patch_dir, os.path.basename(file_path) + '.mappings.json')
                            self.save_json_file(line_mappings, mapping_file)
                            print(f"\nLine mappings saved: {mapping_file}")
                    
                    self.save_json_file(patch_data, patch_info_path)
                    print(f"Patch info saved to {patch_info_path}")
                    
                    return patch_data, model

                except Exception as e:
                    print(f"Error: Failed to parse JSON response from {model}. Error: {e}")
                    print(f"Full response: {content}")
                    continue

            except Exception as e:
                print(f"An unexpected error occurred while processing the response from {model}: {str(e)}")
                continue
        
        print("All models failed to generate a valid patch.")
        return {"error": "All models failed to generate a valid patch."}, None

    def generate_patch_from_slice(self, slice_path, **kwargs):
        
        code_content = self.read_file_content(slice_path)
        if not code_content:
            return {"error": f"Failed to read slice file: {slice_path}"}, None
        
        prompt_intro = (
            f"The code snippet I will give you is taken from an unpatched app and contains a {self.vul_type} vulnerability. "
            "The provided code includes only the critical code necessary to trigger the vulnerability."
        )
        return self._generate_patch(code_content, prompt_intro, **kwargs)

    def generate_patch_from_one_func(self, one_func_path, **kwargs):
        
        code_content = self.read_file_content(one_func_path)
        if not code_content:
            return {"error": f"Failed to read function file: {one_func_path}"}, None
        
        prompt_intro = (
            f"The code snippet I am giving you is taken from {self.app_name} and contains a {self.vul_type} vulnerability. "
            "The provided code includes only the vulnerable function that trigger the vulnerability."
        )
        return self._generate_patch(code_content, prompt_intro, **kwargs)

    def generate_patch_from_full_profile(self, full_profile_path, **kwargs):
        
        code_content = self.read_file_content(full_profile_path)
        if not code_content:
            return {"error": f"Failed to read profile file: {full_profile_path}"}, None
        
        prompt_intro = (
            f"The code snippet I am giving you is taken from {self.app_name} and contains a {self.vul_type} vulnerability. "
            "The provided code includes the executed code during the request that triggers the vulnerability."
        )
        return self._generate_patch(code_content, prompt_intro, **kwargs)

    def generate_patch_via_llm(self, full_slice_path, **kwargs):
        
        return self.generate_patch_from_slice(full_slice_path, **kwargs)

    def restore_app_after_validation(self):
        
        restore_app_from_baks()

    def apply_patch(self, original_path, patch_content, output_path, patch_type='file'):
        
        bak_file_name = original_path + '.bak'
        if os.path.exists(bak_file_name):
            os.unlink(bak_file_name)
        shutil.copy(original_path, bak_file_name)
        # Read existing backup files first
        existing_backups = set()
        if os.path.exists('/tmp/patch_bak.log'):
            with open('/tmp/patch_bak.log', 'r') as f:
                existing_backups = set(line.strip() for line in f.readlines())
        
        # Append new backup if not already logged
        if bak_file_name not in existing_backups:
            with open('/tmp/patch_bak.log', 'a') as f:
                f.write(f"{bak_file_name}\n")
        
        try:
            if patch_type == 'lines':
                # For lines type, create a JSON file with line mappings
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp_mapping:
                    json.dump(patch_content, tmp_mapping, indent=2)
                    tmp_mapping_path = tmp_mapping.name
                
                # Execute the line-based patch command
                cmd = ['php', 'patch_lines.php', original_path, tmp_mapping_path, output_path]
                result = run_command_with_progress(cmd, f"Applying line-based patch to {os.path.basename(output_path)}")
                print(result.stdout)
                print(f"Successfully applied line-based patch to {output_path}")
                return True
            else:
                # For file type, use the original method
                # Create a temporary file to store the patch content
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.php', delete=False) as tmp_patch:
                    # Ensure patch_content is a string
                    if isinstance(patch_content, dict):
                        # If it's a dict, extract the 'content' field or convert to string
                        if 'content' in patch_content:
                            content_to_write = patch_content['content']
                        else:
                            # Fallback: convert dict to JSON string (shouldn't happen for file type)
                            content_to_write = json.dumps(patch_content, indent=2)
                    else:
                        content_to_write = str(patch_content)
                    
                    tmp_patch.write(content_to_write)
                    tmp_patch_path = tmp_patch.name
                
                # Execute the merge command
                cmd = ['php', 'patch.php', original_path, tmp_patch_path, output_path]
                result = run_command_with_progress(cmd, f"Applying file patch to {os.path.basename(output_path)}")
                print(result.stdout)
                print(f"Successfully applied file patch to {output_path}")
                return True
                
        except subprocess.CalledProcessError as e:
            print(f"Error applying patch: {e.stderr}")
            return False
        finally:
            # Clean up the temporary file
            if 'tmp_patch_path' in locals():
                os.unlink(tmp_patch_path)
            if 'tmp_mapping_path' in locals():
                os.unlink(tmp_mapping_path)

    def apply_patch_from_string(self, original_path, patch_content, output_path, patch_type='file'):
        
        return self.apply_patch(original_path, patch_content, output_path, patch_type)

    def fix_json_format(self, json_content):
        
        try:
            # Remove any trailing text after the last }
            last_brace = json_content.rfind('}')
            if last_brace != -1:
                json_content = json_content[:last_brace + 1]
            
            # Remove any leading text before the first {
            first_brace = json_content.find('{')
            if first_brace != -1:
                json_content = json_content[first_brace:]
            
            # Fix common issues
            fixes = [
                # Remove trailing commas before } or ]
                (r',(\s*[}\]])', r'\1'),
                # Fix missing quotes around keys (common LLM error)
                (r'([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":'),
                # Fix single quotes to double quotes
                (r"'([^']*)'", r'"\1"'),
                # Remove extra closing braces
                (r'}\s*}$', r'}'),
                # Fix missing commas between objects
                (r'}\s*{', r'},{'),
                # Fix missing commas between array elements
                (r']\s*\[', r'],['),
                # Remove comments (/* */ and //)
                (r'/\*.*?\*/', ''),
                (r'//.*?$', ''),
            ]
            
            import re
            for pattern, replacement in fixes:
                json_content = re.sub(pattern, replacement, json_content, flags=re.MULTILINE | re.DOTALL)
            
            # Try to parse and reformat
            import json
            try:
                parsed = json.loads(json_content)
                return json.dumps(parsed)  # This will ensure proper formatting
            except json.JSONDecodeError:
                # If still invalid, try more aggressive fixes
                
                # Count braces and brackets to fix imbalance
                open_braces = json_content.count('{')
                close_braces = json_content.count('}')
                open_brackets = json_content.count('[')
                close_brackets = json_content.count(']')
                
                # Add missing closing braces
                if open_braces > close_braces:
                    json_content += '}' * (open_braces - close_braces)
                elif close_braces > open_braces:
                    # Remove extra closing braces
                    extra_braces = close_braces - open_braces
                    for _ in range(extra_braces):
                        json_content = json_content.rsplit('}', 1)[0]
                
                # Add missing closing brackets
                if open_brackets > close_brackets:
                    json_content += ']' * (open_brackets - close_brackets)
                elif close_brackets > open_brackets:
                    # Remove extra closing brackets
                    extra_brackets = close_brackets - open_brackets
                    for _ in range(extra_brackets):
                        json_content = json_content.rsplit(']', 1)[0]
                
                # Try parsing again
                try:
                    parsed = json.loads(json_content)
                    return json.dumps(parsed)
                except json.JSONDecodeError as e:
                    print(f"Warning: Could not auto-fix JSON format. Error: {e}")
                    return json_content  # Return original if we can't fix it
            
        except Exception as e:
            print(f"Error in JSON auto-fix: {e}")
            return json_content  # Return original if any error occurs
