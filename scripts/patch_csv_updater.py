import os
import pandas as pd
from csv_manager import CSVManager
import difflib
import re

class PatchCSVUpdater:
    def __init__(self, working_dir, app_dir, out_dir):
        self.working_dir = working_dir
        self.app_dir = app_dir
        self.csv_manager = CSVManager(working_dir)
        self.out_dir = out_dir
        
    def read_instr_info_csv(self, file_path):
        
        instr_data = {}
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
            
        # Skip header
        for line in lines[1:]:
            parts = line.strip().split('\t')
            if len(parts) >= 4:
                node_id = parts[0]
                node_type = parts[1]
                lineno = parts[2]
                value = parts[3]
                
                instr_data[node_id] = {
                    'type': node_type,
                    'lineno': lineno,
                    'value': value
                }
                
        return instr_data
    
    def get_file_path_mapping(self, instr_data):
        
        file_mapping = {}
        
        for node_id, data in instr_data.items():
            if data['type'] == 'f':  # File entry
                original_path = data['value']
                # Get filename by splitting on '/' and taking last part
                filename = original_path.split('/')[-1]
                # Replace '+' with '/' in filename
                patched_filename = filename.replace('+', '/')
                file_mapping[original_path] = patched_filename
                
        return file_mapping
    
    def read_file_content(self, file_path):
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.readlines()
        except (FileNotFoundError, UnicodeDecodeError):
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    return f.readlines()
            except FileNotFoundError:
                print(f"Warning: Could not find file {file_path}")
                return []
    
    def normalize_line_for_bracket_matching(self, line):
        
        # Remove trailing { } ( ) and whitespace, be more aggressive
        normalized = line.rstrip()
        # Keep removing brackets and whitespace until no more changes
        while True:
            new_normalized = normalized.rstrip('{}()').rstrip()
            if new_normalized == normalized:
                break
            normalized = new_normalized
        return normalized
    
    def find_matching_line_number(self, original_content, patched_content, original_lineno):
        
        if original_lineno <= 0 or original_lineno > len(original_content):
            return original_lineno
            
        # Get the original line content (stripped)
        original_line = original_content[original_lineno - 1].strip()
        
        # Skip empty lines to avoid noise
        if not original_line:
            return original_lineno
        
        # Normalize original line for bracket-flexible matching
        normalized_original = self.normalize_line_for_bracket_matching(original_line)
        
        # Create hash maps for different types of matching
        line_positions = {}              # Exact match
        bracket_flexible_positions = {}  # Match ignoring trailing brackets
        
        for i, patched_line in enumerate(patched_content):
            stripped_line = patched_line.strip()
            if stripped_line:  # Only process non-empty lines
                # Store exact matches
                if stripped_line not in line_positions:
                    line_positions[stripped_line] = []
                line_positions[stripped_line].append((i + 1, stripped_line))
                
                # Store bracket-flexible matches
                normalized_patched = self.normalize_line_for_bracket_matching(stripped_line)
                if normalized_patched not in bracket_flexible_positions:
                    bracket_flexible_positions[normalized_patched] = []
                bracket_flexible_positions[normalized_patched].append((i + 1, stripped_line))
        
        # First try exact match
        if original_line in line_positions:
            exact_matches = line_positions[original_line]
            if len(exact_matches) == 1:
                best_match_line = exact_matches[0][0]
                best_match_content = exact_matches[0][1]
                best_similarity = 1.0
            else:
                # Multiple exact matches, use context to decide
                best_match_line, best_match_content = self.choose_best_match_by_context(
                    original_content, patched_content, original_lineno, exact_matches
                )
                best_similarity = 1.0
                
            return best_match_line
        
        # Try bracket-flexible match (ignoring trailing brackets)
        elif normalized_original and normalized_original in bracket_flexible_positions:
            flexible_matches = bracket_flexible_positions[normalized_original]
            if len(flexible_matches) == 1:
                best_match_line = flexible_matches[0][0]
                best_match_content = flexible_matches[0][1]
                best_similarity = 1.0
            else:
                # Multiple bracket-flexible matches, use context to decide
                best_match_line, best_match_content = self.choose_best_match_by_context(
                    original_content, patched_content, original_lineno, flexible_matches
                )
                best_similarity = 1.0
                
            return best_match_line
        
        # No exact or bracket-flexible match, search entire file for best similarity
        best_similarity = 0.0
        best_matches = []
        
        
        # Search all lines but only calculate similarity for non-empty lines
        processed_lines = 0
        for i, patched_line in enumerate(patched_content):
            stripped_line = patched_line.strip()
            if stripped_line:  # Only process non-empty lines
                similarity = difflib.SequenceMatcher(None, stripped_line, original_line).ratio()
                
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_matches = [(i + 1, stripped_line)]
                elif similarity == best_similarity and similarity > 0:
                    best_matches.append((i + 1, stripped_line))
                
                processed_lines += 1
        
        # Choose best match
        if len(best_matches) == 1:
            best_match_line = best_matches[0][0]
            best_match_content = best_matches[0][1]
        else:
            # Multiple matches with same similarity, use context to decide
            best_match_line, best_match_content = self.choose_best_match_by_context(
                original_content, patched_content, original_lineno, best_matches
            )
                
                
        return best_match_line
    
    def is_code_line(self, line):
        
        stripped = line.strip()
        if not stripped:
            return False
        
        comment_patterns = [
            r'^\s*//.*$',           # Single-line comment starting with //
            r'^\s*/\*.*?\*/\s*$',   # Single-line /* comment */
            r'^\s*#.*$',            # Shell-style comment
            r'^\s*\*.*$',           # Multi-line comment continuation
            r'^\s*/\*.*$',          # Start of multi-line comment (without closing)
            r'^\s*\*/\s*$',         # End of multi-line comment
            r'^\s*<!--.*?-->\s*$',  # HTML comment on single line
            r'^\s*<!--.*$',         # Start of HTML comment
            r'^\s*.*?-->\s*$'       # End of HTML comment
        ]
        
        for pattern in comment_patterns:
            if re.match(pattern, line):
                return False
        
        return True

    def get_non_empty_lines_around(self, content, line_index, range_size=5):
        
        lines = []
        
        # Get lines before
        for i in range(max(0, line_index - range_size), line_index):
            if i < len(content) and self.is_code_line(content[i]):
                lines.append(content[i].strip())
        
        # Get lines after
        for i in range(line_index + 1, min(len(content), line_index + range_size + 1)):
            if i < len(content) and self.is_code_line(content[i]):
                lines.append(content[i].strip())
                
        return lines
    
    def choose_best_match_by_context(self, original_content, patched_content, original_lineno, best_matches):
        
        # Limit the number of candidates to avoid excessive computation
        if len(best_matches) > 10:
            # print(f"      Too many matches ({len(best_matches)}), using first 20 for context comparison")
            best_matches = best_matches[:10]
            
        # Get context around original line
        original_context = self.get_non_empty_lines_around(original_content, original_lineno - 1)
        
        best_context_score = -1
        best_match = best_matches[0]  # Default to first match
        
        # print(f"      Original context: {len(original_context)} lines")
        
        # Compare context for each candidate
        for line_num, content in best_matches:
            # Get context around this candidate line
            candidate_context = self.get_non_empty_lines_around(patched_content, line_num - 1)
            
            # Calculate context similarity score
            context_score = 0
            for orig_ctx in original_context:
                best_match_score = 0
                for cand_ctx in candidate_context:
                    similarity = difflib.SequenceMatcher(None, orig_ctx, cand_ctx).ratio()
                    best_match_score = max(best_match_score, similarity)
                context_score += best_match_score
            
            # print(f"      Candidate line {line_num}: context score: {context_score:.3f}")
            
            if context_score > best_context_score:
                best_context_score = context_score
                best_match = (line_num, content)
        
        # print(f"      Selected line {best_match[0]} with best context score: {best_context_score:.3f}")
        return best_match
    
    def update_instrumentation_info(self):
        
        instr_file_path = os.path.join(self.out_dir, 'instr-info.csv')
        
        if not os.path.exists(instr_file_path):
            print(f"Error: {instr_file_path} not found")
            return False
            
        # Read original instrumentation data
        print("Reading original instrumentation data...")
        original_instr_data = self.read_instr_info_csv(instr_file_path)
        
        # Create new dictionary by copying original
        updated_instr_data = original_instr_data.copy()
        
        # Get file path mapping
        file_mapping = self.get_file_path_mapping(original_instr_data)
        print(f"Found {len(file_mapping)} files to process")
        
        # Process each file
        for original_file_path, patched_filename in file_mapping.items():
            print(f"Processing: {original_file_path} -> {patched_filename}")
            
            # Construct full paths
            original_full_path = original_file_path
            patched_full_path = patched_filename
            
            # Read file contents
            original_content = self.read_file_content(original_full_path)
            patched_content = self.read_file_content(patched_full_path)
            
            if not original_content or not patched_content:
                continue
                
            # Update line numbers for this file's entries
            for node_id, data in original_instr_data.items():
                if data['type'] != 'f':  # Skip file entries, process instrumentation entries
                    # Find the file entry for this instrumentation entry
                    file_node_id = None
                    current_file_path = None
                    
                    # Find the file this instrumentation belongs to by looking at node IDs
                    for check_node_id, check_data in original_instr_data.items():
                        if check_data['type'] == 'f' and int(check_node_id) <= int(node_id):
                            if file_node_id is None or int(check_node_id) > int(file_node_id):
                                file_node_id = check_node_id
                                current_file_path = check_data['value']
                    
                    # If this instrumentation entry belongs to the current file being processed
                    if current_file_path == original_file_path:
                        original_lineno = int(data['lineno'])
                        new_lineno = self.find_matching_line_number(
                            original_content, patched_content, original_lineno
                        )
                        
                        # Update the line number in the new data
                        updated_instr_data[node_id]['lineno'] = str(new_lineno)
                        
                        # print(f"  Node {node_id}: line {original_lineno} -> {new_lineno}")
            
            # Update file path in file entries
            for node_id, data in updated_instr_data.items():
                if data['type'] == 'f' and data['value'] == original_file_path:
                    updated_instr_data[node_id]['value'] = patched_filename
                    
        # Save updated data to new CSV file
        output_file = os.path.join(self.out_dir, 'instr-info_patch.csv')
        self.save_updated_csv(updated_instr_data, output_file)
        
        print(f"Updated instrumentation info saved to {output_file}")
        return True
        
    def save_updated_csv(self, instr_data, output_file):
        
        with open(output_file, 'w') as f:
            f.write("\t".join(['id', 'type', 'lineno', 'value']) + "\n")
            
            # Sort by node ID to maintain order
            sorted_items = sorted(instr_data.items(), key=lambda x: int(x[0]) if x[0].isdigit() else float('inf'))
            
            for node_id, data in sorted_items:
                f.write("\t".join([
                    node_id,
                    data['type'],
                    data['lineno'],
                    data['value']
                ]) + "\n")
