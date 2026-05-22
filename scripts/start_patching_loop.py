import sys
import argparse
import time
import os
import json
import subprocess
import shutil
import re
from os.path import basename

from utils import *
from utils import *
from corpus_builder import *
from distance_calculator import *
from graphs import *
from data_flow_analyzer import *
from csv_manager import *
from slicer import *
from agent_factory import *
from patch_csv_updater import *
from cov_trace_blender import *
from code_assembler import *
from debugger import *
from poc_factory import *
from df_factory import *

def get_arg_parser():
    
    parser = argparse.ArgumentParser(description="Patch Generation Pipeline")
    parser.add_argument('-w', '--target_assembled_dir', type=str, default=os.path.join(os.getcwd(), 'assembled'),
                        help="Directory containing nodes.csv/rels.csv/cpg_edges.csv/targets.csv (default: assembled)")
    parser.add_argument('-a', '--ori_app_dir', type=str, default="/app/joomla",
                        help="Directory of the application (default: /app/joomla)")
    parser.add_argument('-o', '--instr_dir', type=str, default=os.path.join(os.getcwd(), "instrument-info"),
                        help="Path to output file containing distance for each node (default: instrument-info)")
    parser.add_argument('-p', '--poc_path', type=str, default=os.path.join(os.getcwd(), "poces/joomla/joomla-2017-8917.py"),
                        help="Path to the POC Python script to execute")
    parser.add_argument('-r', '--restart', action='store_true',
                        help="Flag to indicate if the process should be restarted")
    parser.add_argument('-n', '--runs', type=int, default=1,
                        help="Number of times to run the patching pipeline (default: 1)")
    
    return parser

def main():
    
    sys.setrecursionlimit(100000)

    timer_all = time.time()
    parser = get_arg_parser()
    args = parser.parse_args()
    
    # Create log directory
    log_dir = "/tmp/patching_logs"
    os.makedirs(log_dir, exist_ok=True)
    
    # Generate timestamp for this session
    session_timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    print(f"Starting {args.runs} run(s) of the patching pipeline...")
    print(f"Logs will be saved to: {log_dir}")
    
    total_successful_runs = 0
    total_failed_runs = 0
    cleanup_coverage_files()
    
    for run_number in range(1, args.runs + 1):
        print(f"\n{'='*80}")
        print(f"STARTING RUN #{run_number}/{args.runs}")
        print(f"{'='*80}")
        
        # Create log file for this run
        log_file = os.path.join(log_dir, f"run_{run_number}_{session_timestamp}.log")
        
        # Redirect stdout and stderr to log file while keeping console output
        import contextlib
        import io
        
        # Create a custom context manager to capture output
        class TeeOutput:
            def __init__(self, log_file_path):
                self.log_file_path = log_file_path
                self.log_file = open(log_file_path, 'w')
                self.original_stdout = sys.stdout
                self.original_stderr = sys.stderr
                
            def __enter__(self):
                sys.stdout = self
                sys.stderr = self
                return self
                
            def __exit__(self, exc_type, exc_val, exc_tb):
                sys.stdout = self.original_stdout
                sys.stderr = self.original_stderr
                self.log_file.close()
                
            def write(self, text):
                self.original_stdout.write(text)  # Show on console
                self.log_file.write(text)         # Save to log
                self.log_file.flush()
                
            def flush(self):
                self.original_stdout.flush()
                self.log_file.flush()
        
        try:
            with TeeOutput(log_file):
                print(f"[RUN {run_number}] Starting at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                run_success = execute_single_run(args, run_number)
                
                if run_success:
                    total_successful_runs += 1
                    print(f"[RUN {run_number}] COMPLETED SUCCESSFULLY")
                else:
                    total_failed_runs += 1
                    print(f"[RUN {run_number}] FAILED")
                    
                print(f"[RUN {run_number}] Finished at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                
        except Exception as e:
            total_failed_runs += 1
            print(f"[RUN {run_number}] EXCEPTION: {e}")
            with open(log_file, 'a') as f:
                f.write(f"\n[RUN {run_number}] EXCEPTION: {e}\n")
                import traceback
                traceback.print_exc(file=f)
        
        print(f"[RUN {run_number}] Log saved to: {log_file}")
        
        # Brief pause between runs (except for the last run)
        if run_number < args.runs:
            print(f"Waiting 5 seconds before next run...")
            time.sleep(5)
    
    # Print final summary
    print(f"\n{'='*80}")
    print(f"FINAL SUMMARY AFTER {args.runs} RUN(S)")
    print(f"{'='*80}")
    print(f"Total runs: {args.runs}")
    print(f"Successful runs: {total_successful_runs}")
    print(f"Failed runs: {total_failed_runs}")
    if args.runs > 0:
        success_rate = (total_successful_runs / args.runs) * 100
        print(f"Success rate: {success_rate:.1f}%")
    print(f"Total time (mins): {round((time.time() - timer_all) / 60, 2)}")
    print(f"Logs saved in: {log_dir}")
    
    # Save summary to file
    summary_file = os.path.join(log_dir, f"summary_{session_timestamp}.txt")
    with open(summary_file, 'w') as f:
        f.write(f"Patching Pipeline Summary - {session_timestamp}\n")
        f.write(f"{'='*50}\n")
        f.write(f"Total runs: {args.runs}\n")
        f.write(f"Successful runs: {total_successful_runs}\n")
        f.write(f"Failed runs: {total_failed_runs}\n")
        if args.runs > 0:
            f.write(f"Success rate: {success_rate:.1f}%\n")
        f.write(f"Total time (mins): {round((time.time() - timer_all) / 60, 2)}\n")
        f.write(f"Session timestamp: {session_timestamp}\n")
    
    print(f"Summary saved to: {summary_file}")

def execute_single_run(args, run_number):
    
    run_start_time = time.time()
    # Record start time for slice completion tracking
    global_start_time = time.time()
    
    try:
        # Initialize global budget at the beginning of each run
        MAX_TOTAL_TOKENS = 3000000
        MAX_TOTAL_COST = 10.0
        
        # Reset the global budget manager for each run
        GlobalBudgetManager.reset()
        budget_manager = GlobalBudgetManager(MAX_TOTAL_TOKENS, MAX_TOTAL_COST)
        print(f"[RUN {run_number}] Initialized global budget: {MAX_TOTAL_TOKENS} tokens, ${MAX_TOTAL_COST}")
        
        # Always restart for multiple runs (except if explicitly managing state)
        if run_number > 1:
            args.restart = True
            print(f"[RUN {run_number}] Auto-enabling restart for run #{run_number}")
        
        if args.restart:
            print("Restarting the process from the beginning...\n")
    
        # Initialize POC Factory
        poc_factory = POCFactory(args.poc_path)
        # add poc_path and vul_type into witcher_config.json if not exists
        config_content = json.load(open('witcher_config.json', 'r'))
        if config_content.get('differential_testing'):
            config_content['differential_testing']['poc_path'] = args.poc_path
            # Extract vulnerability type from POC metadata
            poc_metadata = poc_factory.extract_poc_metadata()
            vul_type = poc_metadata.get('type', 'Unknown')
            config_content['differential_testing']['vul_type'] = vul_type
            with open('witcher_config.json', 'w') as f:
                json.dump(config_content, f, indent=4)
        
        # Initialize monitoring and create directories
        init_dirs_files(args)
        touch_cc_switch(False)
        
        # Install composer dependencies
        cmd = ['composer', 'require', 'nikic/php-parser']
        try:
            subprocess.run(cmd, check=True)
            print(f"Composer command executed successfully: {' '.join(cmd)}")
        except subprocess.CalledProcessError as e:
            print(f"Error executing composer command: {e}")
            
        # Parse application directory path
        ori_app_dir_parts = args.ori_app_dir.strip('/').split('/')
        parent_dir = '/' + '/'.join(ori_app_dir_parts[:-1]) if len(ori_app_dir_parts) > 1 else '/'
        app_name = ori_app_dir_parts[-1]
        
        print(f"Parent directory: {parent_dir}")
        print(f"App name: {app_name}")

        # Restore original app files from backup
        restore_app_from_baks()

        # Generate AST and CPG for original application
        original_cwd = os.getcwd()
        if args.restart or not os.path.exists(os.path.join(args.ori_app_dir, 'cpg_edges.csv')):
            try:
                os.chdir(parent_dir)
                # Execute php2ast analysis
                php2ast_cmd = ['/static-tools/phpjoern/php2ast', app_name]
                print(f"Running: {' '.join(php2ast_cmd)}")
                result = run_command_with_progress(php2ast_cmd, f"Executing php2ast analysis for {app_name}")
                print("php2ast completed successfully")
                
                # Generate CPG from AST
                phpast2cpg_cmd = ['/static-tools/oldjoern/phpast2cpg', 'nodes.csv', 'rels.csv']
                print(f"Running: {' '.join(phpast2cpg_cmd)}")
                result = run_command_with_progress(phpast2cpg_cmd, "Executing phpast2cpg to generate CPG")
                print("phpast2cpg completed successfully")
                
                # Move generated files to application directory
                files_to_move = ['nodes.csv', 'rels.csv', 'cpg_edges.csv']
                for file_name in files_to_move:
                    if os.path.exists(file_name):
                        dest_path = os.path.join(args.ori_app_dir, file_name)
                        subprocess.run(['mv', file_name, dest_path], check=True)
                        print(f"Moved {file_name} to {dest_path}")
                    else:
                        print(f"Warning: {file_name} not found")
                        
            except subprocess.CalledProcessError as e:
                print(f"Error running command: {e}")
            except Exception as e:
                print(f"Error: {e}")
            finally:
                os.chdir(original_cwd)
                
        pre_patch_vulnerability = True 
        if args.restart or not os.path.exists(args.target_assembled_dir):
            # Clean up coverage and trace files
            print("Cleaning up coverage and trace files...")
            try:
                cleanup_coverage_files()
            except Exception as e:
                print(f"Warning: Coverage cleanup failed: {e}")
            # Execute POC script (pre-patch verification)
            # Create start monitoring file
            touch_cc_switch(True)
            with open('/tmp/start_test.dat', 'w') as f:
                f.write('Start monitoring at ' + time.strftime('%Y-%m-%d %H:%M:%S') + '\n')
            print("Preprocessing...\nCreated /tmp/start_test.dat")
            should_continue, pre_patch_vulnerability, pre_exit_code, pre_stdout, pre_stderr = poc_factory.verify_pre_patch_vulnerability()
            if os.path.exists('/tmp/start_test.dat'):
                os.remove('/tmp/start_test.dat')  # Remove the file after use
            touch_cc_switch(False)
            time.sleep(1)        
            if not should_continue:
                return False
            # Process coverage and assemble code
            print("Running coverage and code assembler scripts...")
            SOURCE_DIR = "/dev/shm/coverages"
            DEST_DIR = "/tmp/xdebug"
            TRACE_DIR = "/dev/shm/traces"

            blender = CovTraceBlender(SOURCE_DIR, DEST_DIR, TRACE_DIR)
            try:
                blender.process_coverage_file()
            except Exception as e:
                print(f"Processing error: {str(e)}")
                raise
            
            # Run code assembler
            print("Running code assembler...")
            try:
                assembler = CodeAssembler(args.ori_app_dir, args.target_assembled_dir)
                json_dir = DEST_DIR
                working_dir = args.ori_app_dir
                
                if os.path.exists(json_dir):
                    assembler.load_data(json_dir, working_dir)
                    print("Assembling execution flow...")
                    assembler.assemble_execution_flow()
                    print("Code assembler processing completed")
                else:
                    print(f"Warning: JSON directory not found: {json_dir}")
            except Exception as e:
                print(f"Warning: Code assembler failed: {e}")
        
        if args.restart or not os.path.exists(os.path.join(args.target_assembled_dir, 'cpg_edges.csv')):
            # Generate AST for assembled directory
            print("Running php2ast for assembled directory...")
            try:
                os.chdir(original_cwd)
                php2ast_assembled_cmd = ['/static-tools/phpjoern/php2ast', 'assembled']
                result = run_command_with_progress(php2ast_assembled_cmd, "Executing php2ast for assembled directory")
                print("php2ast for assembled directory completed successfully")
            except subprocess.CalledProcessError as e:
                print(f"Warning: php2ast for assembled failed: {e}")
            except Exception as e:
                print(f"Warning: php2ast for assembled error: {e}")
            
            # Generate CPG for assembled data
            print("Running phpast2cpg for assembled...")
            try:
                phpast2cpg_assembled_cmd = ['/static-tools/oldjoern/phpast2cpg', 'nodes.csv', 'rels.csv']
                result = run_command_with_progress(phpast2cpg_assembled_cmd, "Executing phpast2cpg for assembled data")
                print("phpast2cpg for assembled completed successfully")
            except subprocess.CalledProcessError as e:
                print(f"Warning: phpast2cpg for assembled failed: {e}")
            except Exception as e:
                print(f"Warning: phpast2cpg for assembled error: {e}")
            
            # Copy generated files to assembled directory
            print("Copying generated files to assembled directory...")
            try:
                assembled_dir = args.target_assembled_dir
                if not os.path.exists(assembled_dir):
                    os.makedirs(assembled_dir)
                    print(f"Created assembled directory: {assembled_dir}")
                
                files_to_copy = ['nodes.csv', 'rels.csv', 'cpg_edges.csv']
                for file_name in files_to_copy:
                    if os.path.exists(file_name):
                        dest_path = os.path.join(assembled_dir, basename(file_name))
                        shutil.copy(file_name, dest_path)
                        print(f"Copied {file_name} to {dest_path}")
                    else:
                        print(f"Warning: {file_name} not found for copying to assembled directory")
                        
            except Exception as e:
                print(f"Warning: Error copying files to assembled directory: {e}")
        
        # Start complete patching loop (includes vulnerability localization, analysis, slicing, and patching)
        try:
            final_success = patching_loop_with_retry(
                args, poc_factory, pre_patch_vulnerability, 
                max_patching_attempts=3, max_patch_attempts_per_round=10,
                global_start_time=global_start_time
            )
        except BudgetExceededException as e:
            print(f"\nBUDGET EXCEEDED: {e}")
            print("Patching process stopped due to budget constraints.")
            final_success = False
        
        if not final_success:
            print("\nFINAL RESULT: Unable to generate a working patch after all attempts.")
            print("The vulnerability remains unfixed.")
        else:
            print("\nFINAL RESULT: Patch successfully applied and vulnerability fixed!")

        print(f"\n[RUN {run_number}] Run time (mins): {round((time.time() - run_start_time) / 60, 2)}")
        return final_success
        
    except Exception as e:
        print(f"\n[RUN {run_number}] Exception occurred: {e}")
        import traceback
        traceback.print_exc()
        return False

def generate_and_apply_patch_with_factory(full_slice_path, poc_factory, args, pre_patch_vulnerability, patch_factory, attempt_num=1, feedback="", all_previous_patches=""):
    
    print(f"\n{'='*60}")
    print(f"PATCH GENERATION ATTEMPT #{attempt_num}")
    print(f"{'='*60}")
    
    # Prepare feedback for retry attempts
    if feedback == "" and attempt_num > 1:
        feedback = f"Previous patch attempt #{attempt_num-1} failed. The vulnerability still exists. Please analyze the issue and provide a different approach."
    
    model_choice = ['gpt-5']
    
    returned_patch, used_model = patch_factory.generate_patch_from_slice(
        full_slice_path, 
        feedback=feedback, 
        model_choice=model_choice,
        all_previous_patches=all_previous_patches,
        attempt_num=attempt_num
    )

    if 'error' in returned_patch.keys():
        print(f"ERROR! generating patch: {returned_patch['error']}")
        return False, f"Patch generation failed: {returned_patch['error']}", ""
    
    # Format current patch content for collection
    current_patch_formatted = format_patch_content(returned_patch)

    print(f"Patch generated successfully via model {used_model}.")
    
    # Print token usage summary
    usage_summary = patch_factory.get_usage_summary()
    print(f"\n=== TOKEN USAGE SUMMARY (Attempt #{attempt_num}) ===")
    print(f"Total tokens used: {usage_summary['total_tokens_used']}/{usage_summary['max_total_tokens']}")
    print(f"Total cost: ${usage_summary['total_cost']:.4f}/${usage_summary['max_total_cost']}")
    print(f"Remaining tokens: {usage_summary['tokens_remaining']}")
    print(f"Remaining budget: ${usage_summary['budget_remaining']:.4f}")
    
    # Check if we're approaching limits
    if usage_summary['tokens_remaining'] < 10000:
        print("WARNING: Approaching token limit!")
    if usage_summary['budget_remaining'] < 1.0:
        print("WARNING: Approaching budget limit!")
    
    # Restore original files before applying new patch (for retry attempts)
    if attempt_num > 1:
        print("Restoring original files before applying new patch...")
        restore_app_from_baks()
    
    # Apply generated patches
    succ_patch = True
    for file_name, patch_content in returned_patch.get('patch', {}).items():
        file_name = file_name.replace('+', '/')
        if not file_name.startswith('/'):
            file_name = '/' + file_name
        print(f"Applying patch to {file_name}...")
        # backup original file
        try:
            patch_factory.apply_patch_from_string(file_name, patch_content, file_name, returned_patch.get('type', 'file'))
        except Exception as e:
            print(f"Error applying patch to {file_name}: {e}")
            succ_patch = False
    if not succ_patch:
        print("Failed to apply patch to one or more files. Aborting patching attempt.")
        return False, "Patch application failed for one or more files. Please check the file paths.", current_patch_formatted

    # Post-patch POC verification
    print("\n" + "="*60)
    print(f"POST-PATCH VERIFICATION (Attempt #{attempt_num})")
    print("="*60)
    
    post_patch_vulnerability, post_exit_code, post_stdout, post_stderr = poc_factory.verify_post_patch_vulnerability()
    
    # Analyze and print patch effectiveness
    poc_factory.print_patch_verification_results(pre_patch_vulnerability, post_patch_vulnerability)
    
    # Check if patch was successful
    if (not post_patch_vulnerability) and post_exit_code == 0:
        print(f"Patch attempt #{attempt_num} SUCCESSFUL! Vulnerability has been fixed.")
        
        # Update instrumentation info for patched files
        print("\nUpdating instrumentation info for patched files...")
        patch_csv_updater = PatchCSVUpdater(args.target_assembled_dir, args.target_assembled_dir, args.instr_dir)
        if patch_csv_updater.update_instrumentation_info():
            print("Instrumentation info updated successfully.")
        else:
            print("Failed to update instrumentation info.")

        # Perform differential fuzzing verification after successful POC verification
        print("\n" + "="*60)
        print("DIFFERENTIAL FUZZING VERIFICATION")
        print("="*60)
        if os.path.exists('WICHR'):
            os.system('sudo rm -rf WICHR')
            time.sleep(2)
        
        try:
            # Create Predator instance for differential fuzzing
            predator = create_predator(working_directory=os.getcwd(), poc_factory_inst=poc_factory)
            
            # Run differential fuzzing with 5-minute timeout
            config_file = os.path.join(os.getcwd(), 'witcher_config.json')
            jconfig = json.load(open(config_file, 'r'))
            timeout = jconfig.get('timeout', 3600)
            cores = jconfig.get('cores', 10)
            print(f"Differential timeout: {timeout} seconds, cores: {cores}")
            
            df_success, df_reason, df_found_files = predator.verify_differential_fuzzing(timeout=timeout)
            
            if df_success:
                print("Differential fuzzing verification PASSED!")
                
                # Save successful patch to succeed_patches directory
                try:
                    # Extract CVE ID from POC metadata
                    poc_metadata = poc_factory.extract_poc_metadata()
                    cve_id = poc_metadata.get('cve', '')
                    if not cve_id:
                        cve_id = f"unknown_cve_{int(time.time())}"
                    
                    # Create succeed_patches directory if it doesn't exist
                    succeed_patches_dir = "/test/succeed_patches"
                    os.makedirs(succeed_patches_dir, exist_ok=True)
                    
                    # Destination directory with CVE name
                    dest_dir = os.path.join(succeed_patches_dir, cve_id)
                    
                    # If destination already exists, remove it first
                    if os.path.exists(dest_dir):
                        shutil.rmtree(dest_dir)
                    
                    # Create the destination directory
                    os.makedirs(dest_dir, exist_ok=True)
                    
                    # 1. Save the assembled/patched directory (original functionality)
                    source_patched_dir = "/test/assembled/patched"
                    if os.path.exists(source_patched_dir):
                        assembled_dest = os.path.join(dest_dir, "assembled_patched")
                        shutil.copytree(source_patched_dir, assembled_dest)
                        print(f"✓ Assembled patched data saved to: {assembled_dest}")
                    else:
                        print(f"⚠ Warning: Source patched directory not found: {source_patched_dir}")
                    
                    # 2. Save the actual patched PHP files from the application directory
                    patched_files_dir = os.path.join(dest_dir, "patched_files")
                    os.makedirs(patched_files_dir, exist_ok=True)

                    # Get the list of patched files from the returned_patch
                    patched_file_count = 0
                    if 'patch' in returned_patch:
                        for file_name, patch_content in returned_patch['patch'].items():
                            original_file_name = file_name.replace('+', '/')
                            if not original_file_name.startswith('/'):
                                original_file_name = '/' + original_file_name
                            
                            if os.path.exists(original_file_name):
                                # Create subdirectory structure to preserve the original path
                                relative_path = original_file_name.lstrip('/')
                                dest_file_path = os.path.join(patched_files_dir, relative_path.replace('/', f'+'))
                                dest_file_dir = os.path.dirname(dest_file_path)
                                os.makedirs(dest_file_dir, exist_ok=True)
                                
                                # Copy the patched file
                                shutil.copy2(original_file_name, dest_file_path)
                                patched_file_count += 1
                                print(f"✓ Patched file saved: {relative_path}")
                            else:
                                print(f"⚠ Warning: Patched file not found: {original_file_name}")

                    print(f"✓ Total {patched_file_count} patched PHP files saved to: {patched_files_dir}")

                    # 3. Save a metadata file with additional information
                    metadata_file = os.path.join(dest_dir, "patch_metadata.json")
                    metadata = {
                        "cve_id": cve_id,
                        "poc_path": poc_factory.poc_path,
                        "poc_metadata": poc_metadata,
                        "patch_timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                        "patch_attempt": attempt_num,
                        "assembled_source_directory": source_patched_dir,
                        "patched_files_count": patched_file_count,
                        "verification_status": "PASSED",
                        "differential_fuzzing": "PASSED",
                        "patch_details": returned_patch.get('patch', {})
                    }
                    
                    with open(metadata_file, 'w') as f:
                        json.dump(metadata, f, indent=2)
                    print(f"✓ Patch metadata saved to: {metadata_file}")
                    
                    print(f"✓ Complete successful patch archive saved to: {dest_dir}")
                        
                except Exception as e:
                    print(f"⚠ Warning: Failed to save successful patch: {e}")
                    import traceback
                    traceback.print_exc()
                
                return True, "", current_patch_formatted
            else:
                print(f"Differential fuzzing verification FAILED: {df_reason}")
                # if df_found_files:
                #     print("Files that caused failure:")
                #     for file_path in df_found_files:
                #         print(f"  - {file_path}")
                
                feedback = df_reason
                return False, feedback, current_patch_formatted
                
        except Exception as e:
            print(f"Error during differential fuzzing verification: {e}")
            feedback = f"Differential fuzzing verification encountered an error: {e}"
            return False, feedback, current_patch_formatted
    else:
        print(f"Patch attempt #{attempt_num} FAILED. Vulnerability still exists.")
        feedback = f"Failed to fix the vulnerability as the POC still triggers it."
        return False, feedback, current_patch_formatted

def patching_loop_with_retry(args, poc_factory, pre_patch_vulnerability, max_patching_attempts=3, max_patch_attempts_per_round=3, global_start_time=None):
    
    
    # Use the global budget manager (no need to create another one)
    budget_manager = GlobalBudgetManager()  # This will return the existing singleton
    
    # Initialize timing tracking for first slice completion
    first_slice_completed = False
    
    # Initialize patch factory for the entire process (using global budget)
    app_name = args.target_assembled_dir.split('/')[-1] if args.target_assembled_dir else 'unknown_app'
    vul_type = poc_factory.extract_vulnerability_type_from_poc()
    patch_factory = PatchFactory(app_name, vul_type, args.target_assembled_dir, args.poc_path)
    
    try:
        for patching_round in range(1, max_patching_attempts + 1):
            print(f"\n{'='*60}")
            print(f"PATCHING ROUND #{patching_round}/{max_patching_attempts}")
            print(f"{'='*60}")
            
            # Check budget limits before each round
            usage_summary = patch_factory.get_usage_summary()
            print(f"Current usage: {usage_summary['total_tokens_used']}/{usage_summary['max_total_tokens']} tokens, ${usage_summary['total_cost']:.4f}/${usage_summary['max_total_cost']}")
            
            # Abort if budget limits would be exceeded
            patch_factory.abort_if_budget_exceeded(0, f"patching_round_{patching_round}")
            
            print(f"\n--- Step 1: Vulnerability Localization (Round #{patching_round}) ---")
            
            # Remove existing targets.csv to force re-localization
            targets_csv_path = os.path.join(args.target_assembled_dir, 'targets.csv')
            if os.path.exists(targets_csv_path):
                os.remove(targets_csv_path)
                print("Removed existing targets.csv for re-localization")
            
            from agent_factory import VulnerabilityLocator
            
            # Use the same model choice as PatchFactory for consistency
            model_choice = ['gpt-5']

            locator = VulnerabilityLocator(args.target_assembled_dir, args.poc_path, model_choice)
            success, vul_line_content = locator.locate_vulnerability()
            
            if not success:
                print(f"Warning: Failed to locate vulnerability in round #{patching_round}.")
                if patching_round < max_patching_attempts:
                    print("Retrying with different approach in next round...")
                    continue
                else:
                    print("Failed to locate vulnerability after all attempts.")
                    return False
            
            print("Vulnerability localization completed successfully!")

            print(f"\n--- Step 2: Static Code Slicing (Round #{patching_round}) ---")
            
            csv_manager = CSVManager(args.target_assembled_dir)
            nodes_df, rels_df, cpg_edges_df, targets_df = csv_manager.read_csvs()
            nodes_df_dict = nodes_df.set_index('id:int').to_dict('index')
            target_nodes = map_targets_to_nodes(targets_df, nodes_df, nodes_df_dict)
            
            if not target_nodes:
                print(f"No target nodes found in round #{patching_round}. Skipping to next round.")
                continue
            
            timer_step = time.time()
            graphs = Graphs(rels_df, nodes_df, nodes_df_dict, cpg_edges_df, target_nodes)
            graphs.build_all()
            instrumented_callee_nodes = graphs.check_callees()
            
            distance_calculator = DistanceCalculator(target_nodes, graphs)
            dist = distance_calculator.calculate()
            
            print(f"Block distance calculation time (mins): {round((time.time() - timer_step) / 60, 2)}")
            
            timer_step = time.time()
            
            data_flow_analyst = DataFlowAnalyst(graphs.idg_data, graphs.icfg_distance, dist, nodes_df, nodes_df_dict, graphs.ast)
            data_flow, data_flow_origins = data_flow_analyst.data_flow_backtrack(target_nodes)
            map_externals(nodes_df, nodes_df_dict, data_flow_origins, args.instr_dir)
            
            nodes_to_instrument = {
                'dist': dist,
                'data_flow': data_flow
            }
            instrumented_files = csv_manager.save_to_csv(nodes_to_instrument, nodes_df, nodes_df_dict, instrumented_callee_nodes, args.instr_dir)
            print("Number of entries:", len(instrumented_files))
            
            print(f"URL and inputs extraction time (mins): {round((time.time() - timer_step) / 60, 2)}")
            
            print(f"\n--- Step 3: Code Slice Generation (Round #{patching_round}) ---")
            
            slicer = Slicer(nodes_df, nodes_df_dict, graphs, distance_calculator, data_flow_analyst, args.target_assembled_dir, args.target_assembled_dir)
            full_slice_path = slicer.slice()
            if not full_slice_path:
                print(f"No slice generated in round #{patching_round}. Skipping to next round.")
                continue
            
            # Track first slice completion time
            if not first_slice_completed:
                first_slice_completed = True
                slice_completion_time = time.time()
                elapsed_time = slice_completion_time - global_start_time
                print(f"✓ first slice time cost: {elapsed_time:.2f} seconds")
                
            print(f"\n--- Step 3.5: Left/Right Value Extraction (Round #{patching_round}) ---")
            
            slice_directory = os.path.dirname(full_slice_path)
            request_data_file = extract_left_right_values_with_php_parser(slice_directory, poc_factory)
            
            if request_data_file:
                print(f"✓ Successfully generated request_data.json at: {request_data_file}")
            else:
                print("⚠ Warning: Failed to generate request_data.json, but continuing with patching...")
                
            print(f"\n--- Step 4: Patch Generation and Application (Round #{patching_round}) ---")

            patch_success = apply_patch_with_retry_loop_internal(
                full_slice_path, poc_factory, args, pre_patch_vulnerability, patch_factory,
                max_patch_attempts_per_round, patching_round, vul_line_content
            )
            
            if patch_success:
                print(f"\nPatching successful in round #{patching_round}!")
                
                # Print final usage summary
                final_summary = patch_factory.get_usage_summary()
                print(f"\n=== FINAL TOKEN USAGE SUMMARY ===")
                print(f"Total tokens used: {final_summary['total_tokens_used']}")
                print(f"Total cost: ${final_summary['total_cost']:.4f}")
                print(f"Patching rounds: {patching_round}")
                
                # Save token usage log
                patch_factory.save_usage_log(f'/tmp/complete_patching_usage_log_round_{patching_round}.json')

                return True
            
            print(f"Patching failed in round #{patching_round}. Preparing for next round...")
            
            # Restore original files before next round
            if patching_round < max_patching_attempts:
                print("Restoring original files for next patching round...")
                restore_app_from_baks()
    
    except BudgetExceededException as e:
        print(f"Budget exceeded during patching: {e}")
        print(f"Stopping patching process due to budget constraints.")
        return False
    except Exception as e:
        print(f"Unexpected error during patching: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Print final usage summary even if failed
    final_summary = patch_factory.get_usage_summary()
    print(f"\n=== FINAL TOKEN USAGE SUMMARY ===")
    print(f"Total tokens used: {final_summary['total_tokens_used']}")
    print(f"Total cost: ${final_summary['total_cost']:.4f}")
    print(f"Patching rounds attempted: {max_patching_attempts}")
    
    # Save token usage log
    patch_factory.save_usage_log('/tmp/complete_patching_usage_log_final.json')
    
    return False

def apply_patch_with_retry_loop_internal(full_slice_path, poc_factory, args, pre_patch_vulnerability, patch_factory, max_attempts, patching_round, vul_line_content):
    
    feedback = ""
    all_previous_patches = ""
    patches_with_feedback = []  # Store (patch_content, feedback) tuples
    
    for attempt in range(1, max_attempts + 1):
        print(f"\n{'='*60}")
        print(f"PATCH ATTEMPT #{attempt}/{max_attempts} (Patching Round #{patching_round})")
        print(f"{'='*60}")
        
        # Check budget limits before each attempt
        usage_summary = patch_factory.get_usage_summary()
        print(f"Current usage: {usage_summary['total_tokens_used']}/{usage_summary['max_total_tokens']} tokens, ${usage_summary['total_cost']:.4f}/${usage_summary['max_total_cost']}")
        
        # Abort if budget limits would be exceeded
        try:
            patch_factory.abort_if_budget_exceeded(0, f"patch_attempt_{attempt}_round_{patching_round}")
        except BudgetExceededException as e:
            print(f"Budget limit exceeded before patch attempt #{attempt}: {e}")
            print(f"Stopping patch generation due to budget constraints.")
            return False
            
        if feedback != "":
            feedback = feedback + f"\nPlease try again with a different approach."
            
        success, new_feedback, current_patch_content = generate_and_apply_patch_with_factory(
            full_slice_path, poc_factory, args, pre_patch_vulnerability, patch_factory, 
            attempt, feedback, all_previous_patches
        )

        if 'Please check the targets and try again.' in new_feedback:
            while True:
                print("Wrong configuration or targets. Please check the targets and try again.")
                time.sleep(5)
        
        # Collect current patch content for future attempts in this round
        if current_patch_content:
            current_patch_with_attempt = f"=== Patch Attempt #{attempt} ===\n{current_patch_content}"
            
            # Always add the patch first
            patches_with_feedback.append(current_patch_with_attempt)
            
            # If this attempt failed and there's feedback, append it to the current patch
            if not success and new_feedback:
                patches_with_feedback[-1] += f"\n\n=== Feedback on this attempt ===\n{new_feedback}"
            
            all_previous_patches = "\n\n".join(patches_with_feedback)
        
        # Update feedback for next iteration
        feedback = new_feedback
        
        if success:
            print(f"\nPatch successfully applied and verified after {attempt} attempt(s) in round #{patching_round}!")
            return True
        
        if attempt < max_attempts:
            print(f"\nPreparing for patch attempt #{attempt + 1} in round #{patching_round}...")
            time.sleep(2)  # Brief pause between attempts
        else:
            print(f"\nAll {max_attempts} patch attempts failed in round #{patching_round}.")
    
    return False

if __name__ == '__main__':
    main()
