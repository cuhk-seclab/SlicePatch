#!/usr/bin/env python3


import json
import argparse
import os
import sys

def generate_secondary_url(primary_url, config):
    
    if not config.get("enabled", False):
        return None
        
    # URL pattern replacement
    if "url_pattern" in config:
        pattern = config["url_pattern"]
        if "from" in pattern and "to" in pattern:
            return primary_url.replace(pattern["from"], pattern["to"])
    
    # Port pattern replacement
    if "port_pattern" in config:
        port_pattern = config["port_pattern"]
        if "from" in port_pattern and "to" in port_pattern:
            return primary_url.replace(f":{port_pattern['from']}", f":{port_pattern['to']}")
    
    # Default patterns based on secondary type
    secondary_type = config.get("secondary_type", "")
    if "pre-patch" in secondary_type:
        if "/app/" in primary_url:
            return primary_url.replace("/app/", "/app-old/")
        elif "localhost/" in primary_url:
            return primary_url.replace("localhost/", "localhost:8081/")
    elif "port-shift" in secondary_type:
        # Default port shift from 80 to 8081
        if "localhost/" in primary_url:
            return primary_url.replace("localhost/", "localhost:8081/")
        elif ":80/" in primary_url:
            return primary_url.replace(":80/", ":8081/")
    
    return None

def update_request_data_file(file_path, dual_url_config, backup=True):
    
    print(f"Updating {file_path}...")
    
    # Create backup if requested
    if backup:
        backup_path = file_path + ".backup"
        if not os.path.exists(backup_path):
            os.system(f"cp '{file_path}' '{backup_path}'")
            print(f"Created backup at {backup_path}")
    
    # Load the existing data
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    # Update each request
    updated_count = 0
    if "requestsFound" in data:
        for req_key, req_data in data["requestsFound"].items():
            if "_url" in req_data and "_secondary_url" not in req_data:
                secondary_url = generate_secondary_url(req_data["_url"], dual_url_config)
                if secondary_url:
                    req_data["_secondary_url"] = secondary_url
                    updated_count += 1
                    print(f"  Added secondary URL for {req_data['_url']} -> {secondary_url}")
    
    # Save the updated data
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Updated {updated_count} requests in {file_path}")
    return updated_count

def main():
    parser = argparse.ArgumentParser(description="Update request_data.json files with dual URL support")
    parser.add_argument("request_data_files", nargs="+", help="Paths to request_data.json files to update")
    parser.add_argument("--config", required=True, help="Path to dual URL configuration JSON file")
    parser.add_argument("--no-backup", action="store_true", help="Don't create backup files")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    
    args = parser.parse_args()
    
    # Load dual URL configuration
    try:
        with open(args.config, 'r') as f:
            full_config = json.load(f)
            dual_url_config = full_config.get("dual_url", {})
    except Exception as e:
        print(f"Error loading config file {args.config}: {e}")
        sys.exit(1)
    
    if not dual_url_config.get("enabled", False):
        print("Dual URL is not enabled in configuration")
        sys.exit(1)
    
    print(f"Using dual URL config: {dual_url_config}")
    
    total_updated = 0
    for file_path in args.request_data_files:
        if not os.path.exists(file_path):
            print(f"Warning: File {file_path} does not exist, skipping")
            continue
        
        if args.dry_run:
            print(f"[DRY RUN] Would update {file_path}")
            # Load and analyze without saving
            with open(file_path, 'r') as f:
                data = json.load(f)
            count = 0
            if "requestsFound" in data:
                for req_key, req_data in data["requestsFound"].items():
                    if "_url" in req_data and "_secondary_url" not in req_data:
                        secondary_url = generate_secondary_url(req_data["_url"], dual_url_config)
                        if secondary_url:
                            count += 1
                            print(f"  [DRY RUN] Would add: {req_data['_url']} -> {secondary_url}")
            print(f"[DRY RUN] Would update {count} requests")
        else:
            count = update_request_data_file(file_path, dual_url_config, not args.no_backup)
            total_updated += count
    
    if not args.dry_run:
        print(f"\nTotal updated requests: {total_updated}")

if __name__ == "__main__":
    main()
