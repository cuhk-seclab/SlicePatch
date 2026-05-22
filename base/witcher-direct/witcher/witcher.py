import stat
import threading
import queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from phuzzer.reporter import Reporter
from urllib.parse import urlparse, urlunparse
from datetime import datetime
from phuzzer import Phuzzer
import subprocess
import pathlib
import random
import requests
import shutil
import signal
import time
import json
import glob
import pwd
import sys
import os
import re

WITCH_FAIL = "[\033[31mWitcher\033[0m]"
WITCH_GO = "[\033[32mWitcher\033[0m]"

class Witcher():
    AFLR, AFLHR, WICH, WICR, WICHR, EXWIC, EXWICH, EXWICHR, DEV = "AFLR", "AFLHR", "WICH", "WICR", "WICHR", "EXWIC", "EXWICH", "EXWICHR", "DEV"
    CONFIGURATIONS = ["AFLR", "AFLHR", "WICH", "WICR", "WICHR", "EXWIC", "EXWICH", "EXWICHR", "DEV"]
    WORKING_DIR = os.path.join("/tmp", "output")

    def __init__(self, args):
        random.seed(90210)
        self.testloc = args.testloc # replaced BASETESTDIR
        self.testver = args.testver
        self.dictionary_fn = os.path.join(self.testloc, self.testver,"dict.txt")
        self.seed_path = os.path.join(self.testloc, self.testver, "input")
        self.work_dir = os.path.join(self.testloc, self.testver, "work")
        self.appdir = args.appdir

        path = pathlib.Path(self.seed_path)
        path.mkdir(parents=True, exist_ok=True)
        self.config_loc = os.path.join(self.testloc,args.config)
        if not os.path.isfile(self.config_loc):
            raise ValueError(f"The configuration does not exist at {self.config_loc}, a configuration file is required")

        self.jconfig = json.load(open(self.config_loc,"r", encoding='utf-8'))
        self.fuzzer_target_binary = ""
        self.single_target = args.target
        self.use_reqr = False
        self.affinity = args.affinity

        self.no_fault_escalation = args.no_fault_escalation

        self.env = self.initialize_env()

        self.report_dir = "/results" if os.path.exists("/results") else os.path.join(self.testloc, self.testver)
        self.report_dir = os.path.join(self.report_dir,f"{self.jconfig['testname']}-{self.testver}")
        path = pathlib.Path(self.report_dir)
        path.mkdir(parents=True, exist_ok=True)

        self.fuzz_campaign_status_fn = os.path.join(self.report_dir, "fuzz_campaign_status.json")
        self.fuzz_campaign_status = None
        if os.path.exists(self.fuzz_campaign_status_fn):
            self.fuzz_campaign_status = json.load(open(self.fuzz_campaign_status_fn,"r"))

        self.request_data_fn = os.path.join(self.testloc,"request_data.json")
        self.request_data = json.load(open(self.request_data_fn,"r", encoding='latin-1'))

        self.cores = int(self.jconfig.get("cores", args.cores))
        self.timeout = self.jconfig.get("timeout", args.timeout)
        self.memory = self.jconfig.get("memory", args.memory)
        self.first_crash = self.jconfig.get("first_crash", args.first_crash)
        self.run_timeout = int(self.jconfig.get("run_timeout", 200))
        self.use_qemu = self.jconfig.get("use_qemu")
        self.server_cmd = self.jconfig.get("server_cmd", None)
        self.init_info_shm = self.jconfig.get("init_info_shm", None)
        self.war_path = self.jconfig.get("war_path",None)
        self.server_base_port = self.jconfig.get("server_base_port", 14000)

        self.server_env_vars = self.jconfig.get("server_env_vars", {})
        print(self.server_env_vars)
        self.binary_options = self.jconfig.get("binary_options").split(" ")
        self.server_up_msg = self.jconfig.get("server_up_msg")
        self.server_procs = []
        self.kill = False

        self.saved_seeds = set()

        if args.container_name:
            self.container_info = {'name': args.container_name}
        else:
            self.container_info = None

        self.create_war_filter()
        self.url_filter = args.url_filter
        
        # Initialize differential testing configuration
        self.differential_config = self.jconfig.get("differential_testing", {})
        self.differential_enabled = self.differential_config.get("enabled", False)
        self.vul_type = self.differential_config.get("vul_type", "").lower()
        
        # Check if XSS detection should be enabled based on vulnerability type
        self.xss_detection_enabled = any(keyword in self.vul_type for keyword in ['xss', 'cross-site', 'cross site'])
        
        if self.differential_enabled:
            print(f"[Predator] Differential testing mode enabled")
            url_pattern = self.differential_config.get("url_pattern", {})
            print(f"[Predator] URL pattern: {url_pattern.get('from', 'N/A')} -> {url_pattern.get('to', 'N/A')}")
        else:
            print(f"[Predator] Differential testing mode disabled")
        
        if self.xss_detection_enabled:
            print(f"[Predator] XSS detection enabled for vulnerability type: {self.vul_type}")
        else:
            print(f"[Predator] XSS detection disabled for vulnerability type: {self.vul_type}")
        
        # Initialize real-time response processing
        self.response_monitor_active = False
        self.response_observers = []  # Multiple observers, one per core
        self.response_queues = []     # Multiple queues, one per core
        self.response_processor_threads = []  # Multiple processor threads, one per core
        self.log_file_path = f"/tmp/pred_moni_{int(time.time())}.log"
        self.processing_stats = {
            'total_files_processed': 0,
            'xss_detected': 0,
            'errors': 0
        }
        self.stats_lock = threading.Lock()  # Thread-safe statistics updates

    def get_http_url_from_file_path(self, file_path):
        """Convert file path to HTTP URL by finding matching request in request data."""
        # Extract relative path from file_path
        if file_path.startswith(self.appdir):
            relative_path = file_path[len(self.appdir):].lstrip('/')
        else:
            # Try to extract from any potential app directory structure
            relative_path = None
            for reqkey, req in self.request_data["requestsFound"].items():
                url = urlparse(req["_url"])
                url_path = url.path.lstrip('/')
                if file_path.endswith(url_path):
                    return req["_url"]
        
        if relative_path:
            # Search for matching HTTP URL in request data
            for reqkey, req in self.request_data["requestsFound"].items():
                url = urlparse(req["_url"])
                url_path = url.path.lstrip('/')
                if url_path == relative_path:
                    return req["_url"]
        
        return None

    def get_unpatched_url_for_differential_test(self, target_path):
        """Get unpatched URL for differential testing based on configuration."""
        if not self.differential_enabled:
            return None
        
        # Apply pattern replacement for differential testing
        if "url_pattern" in self.differential_config:
            pattern = self.differential_config["url_pattern"]
            from_pattern = pattern["from"]
            to_pattern = pattern["to"]
            
            if from_pattern in target_path:
                unpatched_path = target_path.replace(from_pattern, to_pattern)
                return unpatched_path
            else:
                print(f"[Predator] Pattern '{from_pattern}' not found in target path: {target_path}")
                return None
        else:
            print(f"[Predator] No url_pattern configured for differential testing")
            return None


    def save_filesdata(self):
        json.dump(self.fuzz_campaign_status,open(self.fuzz_campaign_status_fn,"w"))

    def initialize_env(self):
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = self.jconfig["ld_library_path"] if "ld_library_path" in self.jconfig else ""
        env["AFL_PRELOAD"] = self.jconfig["afl_preload"] if "afl_preload" in self.jconfig else ""
        env["DOCUMENT_ROOT"] = self.appdir
        if self.affinity is not None:
            env["AFL_SET_AFFINITY"] = self.affinity

        direct = self.jconfig.get("direct",{})
        if "mandatory_cookie" in direct:
            env["MANDATORY_COOKIE"] = direct["mandatory_cookie"]
        if "mandatory_get" in direct:
            env["MANDATORY_GET"] = direct["mandatory_get"]
        if "mandatory_post" in direct:
            env["MANDATORY_POST"] = direct["mandatory_post"]

        env["SERVER_NAME"] = env.get("SERVER_NAME","witcher")
        if not self.no_fault_escalation:
            env["STRICT"] = "1"
        self.use_reqr = True if "R" in self.testver else False
        env["AFL_PATH"] = self.jconfig.get("afl_path", "/afl")
        if "H" in self.testver:
            env["AFL_HTTP_DICT"] = "1"
        if self.testver == Witcher.AFLR or self.testver == Witcher.AFLHR:
            if "afl_inst_interpreter_binary" not in self.jconfig:
                raise ValueError("Configuration file is missing 'afl_inst_interpreter_binary'")
            self.fuzzer_target_binary = self.jconfig["afl_inst_interpreter_binary"]
            env["NO_WC_EXTRA"] = "1"
        else:
            if "wc_inst_interpreter_binary" not in self.jconfig:
                raise ValueError("Configuration file is missing 'wc_inst_interpreter_binary'")
            self.fuzzer_target_binary = self.jconfig["wc_inst_interpreter_binary"]
            if self.testver.startswith("WIC"):
                env["WC_INSTRUMENTATION"] = "1"
                env["NO_WC_EXTRA"] = "1"
            elif self.testver.startswith("EX"):
                env["WC_INSTRUMENTATION"] = "1"
        return env

    @staticmethod
    def find_path(urlpath, prior_rootpaths):
        fname = os.path.basename(urlpath)

        for rootpath in prior_rootpaths:
            tmppath = os.path.join(rootpath, urlpath)
            if os.path.exists(tmppath):
                return tmppath

        cmd = ["find", "/", "-path", "/p", "-prune", "-o", "-path", "/proc", "-prune",
               "-o", "-path", "/test", "-prune", "-o", "-path", "/etc", "-prune",
               "-o", "-path", "/var/log", "-prune", "-o", "-path", "/var/spool", "-prune",
               "-o", "-path", "/var/cache", "-prune",
               "-o", "-path", "/var/lib", "-prune", "-o", "-path", "/root", "-prune",
               "-o", "-name", fname]

        #print(f"Command = {' '.join(cmd)}")

        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        results, _ = p.communicate()
        #print(f"RESULTS from find = {results}")
        for fpath in sorted(results.split(b'\n'), key=len):
            fpath = fpath.decode("latin-1")
            if fpath.find(urlpath) > -1:
                return fpath
        return ""


    def init_fuzz_campaign_status(self, trial_index):
        if self.fuzz_campaign_status is None:
            self.fuzz_campaign_status = []

        assert (trial_index <= len(self.fuzz_campaign_status))

        if len(self.fuzz_campaign_status) == trial_index:
            last_rootpath = set()
            fcnt = 0
            targets_added = {}
            start_time = datetime.now().strftime("%Y_%m_%d_%H_%M")
            self.fuzz_campaign_status.append({"trial_start": start_time, "trial_complete": False, "targets": []})
            trial = self.fuzz_campaign_status[trial_index]

            for reqkey, req in self.request_data["requestsFound"].items():

                if self.url_filter and re.search(self.url_filter, req["_url"]):
                    pass
                elif not self.url_filter:
                    pass
                else:
                    # did not match filter, will not add url
                    continue

                match_found = False

                is_soapaction = False
                if match_found:
                    url = urlparse(req["_url"])
                else:
                    if re.match(r"http://.*/[a-zA-Z0-9_\-\.]+\.(css|js|toff|woff|jpg|gif|png)\?[0-9a-zA-Z ]*", req["_url"]):
                        print(f"[*] Skipping {req['_url']} b/c static extension")
                        continue

                    if "_headers" in req and ("soapaction" in req["_headers"] or "SOAPACTION" in req["_headers"]):
                        retr_url = req["_headers"].get("soapaction", None)
                        if retr_url is None:
                            retr_url = req["_headers"].get("SOAPACTION", None)
                        url = urlparse(retr_url)
                        is_soapaction = True
                    else:
                        url = urlparse(req["_url"])

                    # if req["_method"].upper() == "GET":
                    #     if len(url.query) + len(req.get("_postData",[])) < 1 :
                    #         print(f"[*] Skipping {reqkey} b/c {url.query} is {len(url.query)} and less than 1")
                    #         continue

                    if url.path.endswith("/") and req["_url"].find("/?") > -1:
                        print(f"[*] Skipping {reqkey} b/c looks like dir listing")
                        continue

                    if req.get("response_status", 200) == 999:
                        print(f"[*] Skipping {reqkey} response status was set to 999")
                        continue


                    if req["_method"].upper() == "POST":
                        if len(url.query) + len(req.get("_postData",[])) < 1:
                            print(f"[*] Skipping {reqkey} b/c no post Data")
                            continue

                if self.container_info:
                    target_path = urlunparse(url)
                else:
                    if self.server_cmd:
                        url = url._replace(query="")
                        target_path = urlunparse(url)
                    else:
                        if self.jconfig.get("afl_inst_interpreter_binary", "").find("php-cgi") > -1:
                            url = urlparse(req["_url"])
                            urlpath = url.path
                            if urlpath.startswith("/"):
                                urlpath = urlpath[1:]

                            target_path = os.path.join(self.appdir, urlpath)
                            if not os.path.exists(target_path):
                                target_path = Witcher.find_path(urlpath, last_rootpath)
                                last_rootpath.add(target_path.replace(urlpath,""))
                            print(f"target_path={target_path}")

                            if url.path.find(".php") == -1 and not url.path.endswith("/"):
                                print(
                                    f"Skipping {url} because php-cgi being used to evaluate but request url is for non php item target_path={target_path}")
                                continue
                        else:
                            target_path = req['_url']


                method = req.get("_method", "GET").upper()
                if 400 <= req.get("response_status", 200) < 500:
                    print(f"[WC] Skipping {req['_url']} b/c of response status during crawling")
                    continue

                if target_path:
                    if target_path.find("HNAP1/Login") > -1:
                        continue
                else:
                    target_path = req["_url"]

                # if request has user input, this only checks if query params or post data is passed in
                if req["_url"].find("?") or req["_url"].find("&") or len(req["_postData"]) > 0:
                    print(f" Fuzzing #{fcnt} at '{target_path}'")
                    fcnt += 1
                    if not self.single_target or target_path.find(self.single_target) > -1:
                        if target_path in targets_added:
                            index = targets_added[target_path]
                            trial["targets"][index]["requests"].append(reqkey)
                            trial["targets"][index]["is_soapaction"] = is_soapaction
                            if method in trial["targets"][index]["methods"]:
                                trial["targets"][index]["methods"][method] += 1
                        else:
                            targets_added[target_path] = len(trial["targets"])
                            trial["targets"].append({"target_path": target_path, "requests": [reqkey],
                                                     "methods": {method: 1}, "is_soapaction": is_soapaction,
                                                     "last_completed_trial": -1, "last_completed_refuzz": -1})
                else:
                    print(f"Skipping {req['_url']} b/c no query or post data.")

            self.save_campaign_status()

    def save_campaign_status(self):

        json.dump(self.fuzz_campaign_status, open(self.fuzz_campaign_status_fn, "w"))

    def create_seeds(self, requests):
        seed_name_stub = os.path.join(self.seed_path,"seed-")
        seeds = []
        if len(requests) > 50:
            requests = requests[:10]
        for reqkey in requests:

            req = self.request_data["requestsFound"].get(reqkey,None)
            if req is None:
                print(f"[Witcher]\033[32m Did not find {reqkey} in request data. \033[0m")
                continue
                #req = self.request_data["requestsFound"].get(reqkey, None)

            strid = req["_id"]
            url = urlparse(req["_url"])

            cookie_data = req.get('_cookieData','').encode("utf-8")
            urlquery = url.query.encode("utf-8")
            post_data = req.get('_postData','').encode("utf-8")

            headers = req.get('_headers',{})
            headers_out = ""
            for k,v in headers.items():
                if k.upper() == "SOAPACTION" or k.upper() == "HNAP_AUTH":
                    headers_out += f"{k}:{v}\n"

            strout = b"%s\x00%s\x00%s\x00%s" % (cookie_data, urlquery, post_data, headers_out.encode('utf-8'))
            if len(strout) > 3:
                seeds.append(strout)
        if len(seeds) == 0:
            seeds.append(b"cookie=flour\x00query=search\x00post=hole")
        return seeds

    def create_dictionary(self, target):
        dictionary_vars = []
        inputlist = self.request_data['inputSet']
        if self.request_data['requestsFound'][target['requests'][0]].get('_inputSet') is not None:
            inputlist = inputlist + self.request_data['requestsFound'][target['requests'][0]]['_inputSet']
        for inputvar in inputlist:
            inputvar.replace("\\","")
            if len(inputvar) > 127:
                continue
            if inputvar.find("&") == len(inputvar) - 1:
                inputvar = inputvar[:-1]
            dictionary_vars.append(b"%s&" % inputvar.encode("utf-8"))
#            dictionary_vars.append(b"%s'(&" % inputvar.encode("utf-8"))
        if len(dictionary_vars) > 0:
            print(f"Wrote out dictionary vars {len(inputlist)} totals bytes {len(dictionary_vars)} {dictionary_vars[0]}")
        else:
            print(f"No dictionary vars found")

        #open(self.dictionary_fn,"w").write(dictionary_vars)
        return dictionary_vars

    def init_shared_memory(self):
        if self.init_info_shm:
            subprocess.check_call(self.init_info_shm.split(" "))
            print(f"Initalized Shared Memory using '{self.init_info_shm}'")

    def start_external_servers(self):
        print(f"cmd={self.server_cmd}")

        if self.server_cmd is not None and len(self.server_cmd) > 1:
            print("Starting up servers")
            increasing_port = self.server_base_port

            for icnt in range(0, self.cores):
                server_cmd = []
                for cmd in self.server_cmd:
                    cmd = cmd.replace("@@PORT@@", str(self.server_base_port))
                    cmd = cmd.replace("@@PORT_INCREMENT@@", str(increasing_port))

                    server_cmd.append(cmd)

                server_env_vars = os.environ.copy()

                for envkey, envval in self.server_env_vars.items():
                    if "@@PORT_INCREMENT@@" in envval:
                        envval = envval.replace("@@PORT_INCREMENT@@", str(increasing_port))
                    server_env_vars[envkey] = envval
                print(f"CMD = {' '.join(server_cmd)}")
                #print(f"SERVER_ENV_VARS={server_env_vars}")
                logfpath = f"/tmp/server_{increasing_port}.out"
                outfile = open(logfpath,"w")

                proc_info = {"server_cmd":server_cmd, "logfile": logfpath, "port":increasing_port, "attempts":0,
                             "up":False, "env": server_env_vars}

                proc_info["proc"] = subprocess.Popen(server_cmd, env=server_env_vars, stdout=outfile,
                                                     stderr=outfile, close_fds=True)
                #print(f"Starting up {proc_info}")
                self.server_procs.append(proc_info)
                increasing_port = increasing_port + 1

            wait_cnt = 0
            all_servers_up = False
            time.sleep(2)
            while not all_servers_up:
                all_servers_up = True
                for si in self.server_procs:
                    if si["attempts"] > 3:
                        print("Error trying to bring up servers, exiting...")
                        exit(99)
                    p = si["proc"]
                    if si["up"]:
                        continue
                    if p.poll() is None:  # process is still running
                        if os.path.exists(si["logfile"]):
                            with open(si["logfile"], "r") as lf:
                                data = lf.read()
                                if data.find(self.server_up_msg) > -1:
                                    si["up"] = True
                    else: # process is stopped
                        if not si["up"]:
                            print(f"DOING: pkill -P {p.pid}")
                            os.system(f"pkill -P {p.pid}")
                            print(f"DOING: pkill -9 -f {si['port']}")
                            os.system(f"pkill -9 -f {si['port']}")
                            print("attempting to bring up again.")
                            outfile = open(si["logfile"], "a")
                            si["proc"] = subprocess.Popen(si["server_cmd"], env=si["env"], stdout=outfile, stderr=outfile, close_fds=True)
                        else:
                            assert(not si["up"])

                    all_servers_up = all_servers_up and si["up"]

                if wait_cnt > 120:
                    print("Error, waited for too long, exiting")
                    exit(98)
                if not all_servers_up:
                    print("All the servers are not up, sleeping and will try again")
                    time.sleep(2)
                wait_cnt += 1

            if len(self.server_up_msg) == 0:
                print("Giving servers a chance to come up")
                time.sleep(10)

            print("Servers, should be up")

    def kill_servers(self):
        print("Bringing down external servers")

        # First, try to terminate server processes gracefully
        for si in self.server_procs:
            p = si["proc"]
            if p and p.poll() is None:  # Process is still running
                try:
                    print(f"\tTerminating server on port {si['port']} (PID: {p.pid})")
                    p.terminate()
                except Exception as ex:
                    print(f"ERROR terminating process {p.pid}: {ex}")
        
        # Give servers time to terminate gracefully
        time.sleep(2)
        
        # Force kill any remaining server processes
        for si in self.server_procs:
            p = si["proc"]
            if p and p.poll() is None:  # Still running after graceful termination
                try:
                    print(f"\tForce killing server on port {si['port']} (PID: {p.pid})")
                    p.kill()
                except Exception as ex:
                    print(f"ERROR force killing process {p.pid}: {ex}")
            
            # Kill any child processes and processes bound to the port
            print(f"\tCleaning up port {si['port']} processes")
            os.system(f"pkill -KILL -f 'port={si['port']}'")
            os.system(f"pkill -KILL -f '{si['port']}'")

        self.server_procs = []



    def start_fuzzer(self, do_resume, target_path, method_map, dictionary_str, seeds):

        os.environ["method_map"] = method_map
        os.environ["SCRIPT_FILENAME"] = target_path
        
        # Remove dual URL environment variables setup - no longer using shadow fuzzer
        # Differential testing will be handled separately in perform_differential_test method

        # with open("/tmp/start_test.dat","w") as wf:
        #     wf.write("Trace me if you can, little one.")

        if target_path.startswith("http"):
            binary_options = self.change_url_to_target(target_path)
            print(f"NEW BIN OPTS {binary_options}")
        else:
            binary_options = self.binary_options

        fuzzer = Phuzzer.phactory(phuzzer_type=Phuzzer.WITCHER_AFL, target=self.fuzzer_target_binary, target_opts=binary_options,
                                  work_dir=self.work_dir, seeds=seeds, afl_count=self.cores,
                                  create_dictionary=False, timeout=self.timeout, memory=self.memory,
                                  run_timeout=self.run_timeout, dictionary=dictionary_str,
                                  use_qemu=self.use_qemu, resume=do_resume, login_json_fn=self.config_loc,
                                  base_port=self.server_base_port, container_info=self.container_info, 
                                  fault_escalation=not self.no_fault_escalation)

        def chown_files():
            # by default, AFL creates all files and dirs with permissions of 700
            # as a result, unless running witcher as root, it cannot access the files unless they are
            # owned by the current user, which is what this is meant to do. It runs in reporter,
            if self.container_info:

                fuzzer.chown_container_files(pwd.getpwuid( os.getuid() ).pw_uid)

        start_results = {"totalfail": False, "timeout": False }
        reporter = Reporter(self.fuzzer_target_binary, self.report_dir, self.cores, self.first_crash, self.timeout,
                            fuzzer.work_dir, chown_files=chown_files)

        reporter.set_script_filename(target_path)
        try:
            fuzzer.start()
        except ValueError as ve:
            print(f"Error starting fuzzer {ve}")
            start_results["totalfail"] = True
            return start_results

        reporter.start()
        print("Starting Reporter...")
        
        # Start real-time response file monitoring
        print("[*] Starting real-time response monitoring...")

        self.start_response_monitoring()
        print(f"[*] Real-time monitoring started with {self.cores} workers. Log file: {self.log_file_path}")
        
        # Monitor phuzzer's execution
        try:
            crash_seen = False
            reporter.enable_printing()
            verified_start = False
            run_time = 0

            while True:
                if not verified_start:
                    chown_files()
                    start_results = fuzzer.startup_status()
                    totalcnt = start_results["totalcnt"]
                    successcnt = start_results["successcnt"]
                    forkfailcnt = start_results["forkfail"]
                    failedseeds = start_results['failedseeds']
                    weakseeds = start_results['weakseeds']
                    logfilesize = start_results['logfilesize']
                    reporter.set_startup_values(successcnt, len(failedseeds), len(weakseeds), logfilesize)
                    if forkfailcnt >= 1:
                        print(f"[*]\033[31mError at least 1 instance failed to communicate with fork server \033[0m")
                        import ipdb
                        ipdb.set_trace()
                        raise Exception("Fork server handshake failure count too high")

                    if successcnt + len(start_results['failedseeds']) == self.cores or (run_time > 300 and logfilesize > 0) or run_time > 600:
                        verified_start = True
                        success_percent = (float(successcnt) / float(totalcnt)) * 100 if totalcnt > 0 else 0
                        if success_percent < 80:
                            print(f"[*] Error less than 80% ({successcnt}/{totalcnt} = {success_percent:3.2f})of the fuzzers started up successfully please investigate")
                            start_results["totalfail"] = True

                            break
                        else:
                            start_results["totalfail"] = False
                    else:
                        start_results["totalfail"] = False

                if not crash_seen and fuzzer.found_crash():
                    chown_files()
                    # print ("\n[*] Crash found!")
                    crash_seen = True
                    reporter.set_crash_seen()
                    if self.first_crash:
                        break
                if fuzzer.timed_out():
                    reporter.set_timeout_seen()
                    start_results["timeout"] = True
                    print("\n[*] Timeout reached.")
                    break
                run_time += 1
                time.sleep(1)

        except KeyboardInterrupt:
            end_reason = "Keyboard Interrupt"
            print("\n[*] Aborting wait. Ctrl-C again for KeyboardInterrupt.")
            self.kill = True

        except Exception as e:
            import traceback
            traceback.print_exc()
            end_reason = "Exception occurred"
            print("\n[*] Unknown exception received (%s). Terminating fuzzer." % e)
            self.kill = True
            raise
        finally:
            print("[*] Terminating fuzzer.")
            chown_files()
            reporter.stop()
            fuzzer.stop()
            print("[*] Fuzzer and reporter stopped.")
            # Now stop real-time response file monitoring
            print("[*] Stopping real-time response monitoring...")
            self.stop_response_monitoring()
            
            
            os.system("rm -f /tmp/start_test.dat")
            if self.kill:
                exit(199)
        return start_results


    def results_target_dir(self, trial_index, target_path):
        encoded_path = target_path.replace(self.appdir + '/', '').replace('/', '+')
        targets_dir = f"tr{trial_index}_{encoded_path}"
        results_dir = os.path.join(self.report_dir, targets_dir)
        return results_dir

    def fix_perms_in_dir(self, tdir):
        if not os.path.exists(tdir):
            return

        # this is only a problem for qemu-user targets running in a docker container
        if self.container_info:
            perm_id = pwd.getpwuid( os.getuid() ).pw_uid

            perm_cmd = f"cd {tdir}/.. && /bin/chown {perm_id}:{perm_id} -R . && find . -type d -exec chmod +rx {{}} \; " \
                       f"&& find . -type f -exec chmod +r {{}} \;"

            volume = f"{tdir}:{tdir}"
            perm_cmd = ["docker", "run", "--rm", "-v", volume, "ubuntu:20.04", "/bin/bash", "-c", perm_cmd]

            subprocess.check_output(perm_cmd)


    # it uses this method b/c with qemu-user running as root, AFL creates unreadble file permissions
    def docker_copy(self, from_dir, to_dir):
        if not os.path.exists(from_dir):
            print(f"From dir {from_dir} does not exist, cannot copy.")
            return

        os.makedirs(to_dir, exist_ok=True)

        from_volume = f"{from_dir}:/from"
        to_volume = f"{to_dir}:/to"
        cp_cmd = ["docker", "run", "--rm", "-v", from_volume,"-v", to_volume, "ubuntu:20.04",
                  "/bin/cp", "-a", "/from/.", "/to"]

        subprocess.check_output(cp_cmd)

        # just in case a rouge file gets created between last permission set and the copy, make sure all the files in
        # in the to directory have acceptable permissions
        self.fix_perms_in_dir(to_dir)

    def filter_XSS_suspects(self, file_path):
        """
        XSS filtering from individual response files without deleting the original files
        """
        xss_patterns = [
            '<script>alert(290363',
            'javascript:alert(290363',
            'onload=alert(290363)>',
            'onerror=alert(290363)>',
            'onclick=alert(290363)>',
            '<img src=x onerror=alert(290363',
            'onclick="alert(290363)">',
            'onload="alert(290363)">',
            'onerror="alert(290363)">',
            'onmouseover="alert(290363)">',
            'onfocus="alert(290363)">',
        ]
        filtered_lines = []
        
        try:
            with open(file_path, 'r', errors='ignore') as file:
                for line in file:
                    lower_line = line.lower()
                    # Check if any XSS pattern is found in the line
                    if any(xss in lower_line for xss in xss_patterns):
                        filtered_lines.append(line)
                    if lower_line.startswith('*t*'):
                        filtered_lines.append(line)
        except FileNotFoundError:
            print(f"Warning: Response file {file_path} not found")
            return
        
        # Don't delete the original file, create XSS file alongside
        fuzzer_id = os.path.basename(os.path.dirname(file_path))
        parent_dir = os.path.dirname(os.path.dirname(file_path))
        parent_parent_dir = os.path.dirname(parent_dir)
        new_file_path = os.path.join(parent_parent_dir, f"{fuzzer_id}.xss")
        
        if filtered_lines:  # Only create XSS file if we found something
            with open(new_file_path, 'a+') as file:
                file.writelines(filtered_lines)
            print(f"XSS patterns detected in {os.path.basename(file_path)}, saved to {os.path.basename(new_file_path)}")


    def copy_fuzzer_output_to_results(self, trial_index, target_path):
        if self.container_info:
            self.fix_perms_in_dir(self.work_dir)

        dst = self.results_target_dir(trial_index, target_path)

        print(f"Copy from {self.work_dir} to dst={dst}")

        if os.path.exists(dst):
            os.system(f"sudo rm -rf {dst}")

        if self.container_info:
            self.docker_copy(self.work_dir, dst)
        else:
            try:
                shutil.copytree(self.work_dir, dst)
            except:
                time.sleep(10)
                try:
                    shutil.copytree(self.work_dir, dst)
                except:
                    print("\033[31mError couldn't copy results \033[0m\n")
        # remove work dir
        try:
            os.chmod(self.work_dir, 0o444)
            os.system(f"sudo rm -rf {self.work_dir}")
        except Exception as e:
            time.sleep(10)
            os.system(f"sudo rm -rf {self.work_dir}")

    def copy_fuzzer_results_to_output(self, trial_index, target_path):

        src = self.results_target_dir(trial_index, target_path)
        print(f"Copy from src-{src} to {Witcher.WORKING_DIR}")
        if os.path.exists(Witcher.WORKING_DIR):
            os.system(f"sudo rm -rf {Witcher.WORKING_DIR}")
        shutil.copytree(src, Witcher.WORKING_DIR)

    def build_methd_map(self, methods):
        tot = sum(methods.values())
        outlist = []

        for k, v in sorted(methods.items(), key=lambda item:item[1]):
            cnt = max(int(round(v / tot * 16)), 1)
            for _ in range(0, cnt):
                outlist.append(k)

        if len(outlist) < 16:
            outlist = outlist[:16 - len(outlist)]

        outlist = outlist[:-1] if len(outlist) > 16 else outlist

        return ",".join(outlist)

    def target_contains_skiplist_value(self, target_path):
        for skipper in self.jconfig["script_skip_list"]:
            if target_path.find(skipper) > -1:
                return True
        return False

    def change_url_to_target(self, target):
        url = urlparse(target)
        netloc = url.netloc

        if ":" in netloc:
            netloc = netloc[0: netloc.find(":")]
        netloc = f"{netloc}:@@PORT_INCREMENT@@"
        url = url._replace(netloc=netloc)
        strurl=urlunparse(url)
        out_opts = []

        for cmdopt in self.binary_options:
            out_opts.append(cmdopt.replace("@@url@@", strurl))
        return out_opts


    def create_war_filter(self):
        if self.war_path:
            filelist = subprocess.check_output(["jar","-tf",self.war_path])
            filelist = filelist.decode().split("\n")
            print(filelist)
            with open("/dev/shm/javafilters.dat", "w") as jfilters:
                for f in filelist:
                    if f.endswith(".class"):
                        classfn = f.replace("WEB-INF/", "").replace("classes/","").replace("/",".").replace(".class","")
                        jfilters.write(classfn + "\n")
                        print(classfn)
                    if f.endswith(".jsp"):
                        jspclassfn = f.replace(".jsp","_jsp").replace("/",".")
                        jspclassfn = f"org.apache.jsp.{jspclassfn}"
                        jfilters.write(jspclassfn + "\n")
                        print(jspclassfn)
        # for dirpath in glob.iglob(os.path.join(TOMCAT_PATH, "webapps")):
        #     with open("/dev/shm/javafilters.dat", "w") as jfilters:
        #         if os.path.isdir(dirpath):
        #             appdirname = os.path.basename(dirpath)
        #             classpath = os.path.join(dirpath, "WEB-INF", "classes")
        #             for webfile in glob.iglob(classpath + "/*.class", recursive=True):
        #                 if os.path.isfile(webfile):
        #                     class_fn = webfile.replace(classpath, "")
        #                     class_fn = class_fn.replace(".class","")
        #                     class_fn = class_fn.replace("/",".")
        #                     jfilters.write(class_fn + "\n")
        #                     print(class_fn)
        #             workpath = os.path.join(TOMCAT_PATH, "work","Catalina","localhost", appdirname)
        #             for webfile in glob.iglob(workpath + "/*.class", recursive=True):
        #                 if os.path.isfile(webfile):
        #                     class_fn = webfile.replace(classpath, "")
        #                     class_fn = class_fn.replace(".class", "")
        #                     class_fn = class_fn.replace("/", ".")
        #                     print(class_fn)
        #                     jfilters.write(class_fn + "\n")

    def save_crashing_seed(self, seedpath: str, url_path: str) -> None:
        """
        Saves a seed that AFL reported as crashing

        """
        if seedpath+url_path in self.saved_seeds:
            print(f"{WITCH_GO} Not saving for {url_path} {seedpath}")
            return

        encoded_url_path = url_path.replace(self.appdir + '/', '').replace('/', '+')

        crash_file_dpath = os.path.join(self.report_dir, 'seed-crashes')
        os.makedirs(crash_file_dpath, exist_ok=True)

        fid = len(glob.glob(f"{crash_file_dpath}id*"))

        crash_fname = os.path.join(crash_file_dpath, f"id:{fid:06},{encoded_url_path},src:{os.path.basename(seedpath)},crash")
        crash_fname = os.path.realpath(crash_fname)
        print(f"[Witcher] Saved potential crashing input seed at {os.path.basename(crash_fname)}")
        shutil.copyfile(seedpath, crash_fname)

        fuzz_scr_fpath = os.path.join(self.work_dir, "fuzz-0.sh")
        with open(fuzz_scr_fpath, "r") as rf:
            scr = rf.read()

        cat_str = f'cat "$SCRIPT_DIR/{os.path.basename(crash_fname)}"'

        out_scr = ""
        for line in scr.split("\n"):
            if line.find("afl-fuzz") > -1:
                out_scr += """SCRIPT_DIR="$(cd "$(dirname $0)" > /dev/null && pwd)" \n"""
                args = line.split(" ")

                out_args = [f"{os.path.dirname(args[0])}/afl-showmap", "-o", f"/tmp/map-{os.path.basename(seedpath)}"]
                argindex = 1
                while argindex < len(args):
                    arg = args[argindex]
                    if arg == "-i" or arg == "-o" or arg == "-x" or arg == "-M":
                        argindex += 2
                    else:
                        out_args.append(arg)
                        argindex += 1
                out_scr += cat_str + " | " + " ".join(out_args) + "\n"

            else:
                out_scr += line + "\n"

        exec_fpath = f"{crash_fname}.sh"
        with open(exec_fpath, "w") as wf:
            wf.write(out_scr)

        os.chmod(exec_fpath, stat.S_IRWXU | stat.S_IRWXG | stat.S_IWOTH | stat.S_IROTH)

    def start_fuzz_campaign(self):
        _environ_backup = os.environ.copy()
        try:
            os.environ.clear()
            os.environ.update(self.env)

            nbr_trials = int(self.jconfig.get("number_of_trials", "1"))
            nbr_refuzzes = int(self.jconfig.get("number_of_refuzzes", "1"))

            for trial_index in range(0, nbr_trials):
                self.init_shared_memory()

                print(f"TRIAL INDEX = {trial_index}")
                self.init_fuzz_campaign_status(trial_index)
                trial = self.fuzz_campaign_status[trial_index]
                targets = trial["targets"].copy()
                print(f"Trial start = {trial['trial_start']}")

                if self.jconfig["script_random_order"] == 1:
                    random.shuffle(targets)

                self.start_external_servers()

                for refuzz_index in range(0, nbr_refuzzes):
                    if self.jconfig["script_random_order"] == 2:
                        random.shuffle(targets)
                    target_start = self.jconfig.get("script_start_index", 0)
                    target_end = self.jconfig.get("script_end_index", len(targets))

                    for target in targets[target_start: target_end]:

                        if self.single_target and target['target_path'].find(self.single_target) == -1: # if using single target and not in target name then skip
                            continue
                        if self.target_contains_skiplist_value(target['target_path']):
                            print("SKIPPING B/C in SKIPLIST")
                            continue
                        if trial_index < target["last_completed_trial"] or (trial_index == target["last_completed_trial"] and refuzz_index <= target["last_completed_refuzz"] ):
                            print(f"Skipping {target['target_path']} Trial={trial_index}, Refuzz={refuzz_index} last_completed_refuzz={target['last_completed_refuzz']}")
                            continue

                        regex = re.compile(r"(?P<prefix>http://)([0-9\.]+)(?P<postfix>.*)")

                        target_url = target['target_path']
                        result_storage_pathname = target_url

                        do_resume = refuzz_index > 0

                        # if soapaction, then go to url of first request if exists else default

                        if target['is_soapaction']:
                            if len(target['requests']) > 0 :
                                req0 = target['requests'][0]

                                trequest = self.request_data['requestsFound'][req0]
                                target_url = trequest["_url"]
                                soap_urlstr = None
                                if "soapaction" in trequest["_headers"]:
                                    soap_urlstr = trequest["_headers"]["soapaction"]
                                elif "SOAPACTION" in trequest["_headers"]:
                                    soap_urlstr = trequest["_headers"]["SOAPACTION"]

                                if soap_urlstr:
                                    soap_urlstr = soap_urlstr.replace('"', "")
                                    result_storage_pathname = urlparse(soap_urlstr).path
                            else:
                                target_url = "http://127.0.0.1/HNAP1"

                        urlmatch = regex.match(target_url)
                        if urlmatch:
                            if self.container_info:
                                target_url = regex.sub(r'\g<prefix>127.0.0.1\g<postfix>', target_url)
                            if not target["is_soapaction"]:
                                result_storage_pathname = urlparse(target_url).path

                        print(f"FUZZING \033[33m{target['target_path']}\033[0m Trial={trial_index}, Refuzz={refuzz_index} last_completed_refuzz={target['last_completed_refuzz']} result_path={result_storage_pathname}")

                        if do_resume:
                            self.copy_fuzzer_results_to_output(trial_index, result_storage_pathname)

                        seeds = self.create_seeds(target["requests"])
                        dictionary_str = self.create_dictionary(target)

                        method_map = self.build_methd_map(target["methods"])
                        start_results = self.start_fuzzer(do_resume, target_url, method_map, dictionary_str, seeds)
                        #return {"successcnt":success, "totalcnt":totallogs, "testfailed":testfailed, "failedseeds": failedseeds}
                        # if startup fails (in other words there's more fuzzers that failed to come up than successful ones.

                        while len(seeds) > 0 and (start_results.get("totalfail", True)):
                            failed_seeds = start_results.get("failedseeds", [])
                            weak_seeds = start_results.get("weakseeds", [])
                            print(f"Startup info {start_results} {weak_seeds} {failed_seeds}")
                            if failed_seeds or weak_seeds:
                                print(f"{WITCH_FAIL} {len(failed_seeds)} seeds caused a failure and {len(weak_seeds)} resulted in known execution path ")
                                seeds_to_scan = set()
                                seeds_to_scan |= failed_seeds
                                seeds_to_scan |= weak_seeds
                                for fn in seeds_to_scan:
                                    seedpath = f"{self.work_dir}/initial_seeds/{fn}"

                                    if os.path.exists(seedpath):

                                        self.save_crashing_seed(seedpath, result_storage_pathname)
                                        self.saved_seeds.add(seedpath+result_storage_pathname)

                                        with open(seedpath,"rb") as rf:
                                            filedata = rf.read()
                                        rep_regex = rb"[\x01-\x19'\x7f-\xff]"

                                        if re.match(rep_regex, filedata):
                                            print(f"[Witcher] seed has odd characters, replacing with all with 'a'")
                                            filedata = re.sub(rep_regex, repl=b"a", string=filedata)
                                            with open(seedpath, "wb") as wf:
                                                wf.write(filedata)
                                        else:
                                            print(f"[Witcher] No odd characters, deleting seed")
                                            os.remove(seedpath)
                                seeds = []
                                for fn in glob.iglob(f"{self.work_dir}/initial_seeds/*"):
                                    with open(fn,"rb") as rf:
                                        seeds.append(rf.read())
                            else:
                                print("\033[36mCould not find any failed or weak seeds, so removing last seed")
                                seeds.remove(seeds[len(seeds)-1])

                            print(f"\033[33mAttempting to fuzz again {target['target_path']}\033[0m with {len(seeds)} seeds and {start_results}")
                            start_results = self.start_fuzzer(do_resume, target_url, method_map, dictionary_str, seeds)

                        if start_results.get("totalfail", True):
                            print(f"EXITING while but total fail still True with {start_results}")
                        
                        if start_results.get("timeout", False):
                            target["last_completed_trial"] = trial_index
                            target["last_completed_refuzz"] = refuzz_index
                        else:
                            print(f"\033[31m[Finish] FUZZ {target['target_path']}\033[0m")

                        #os.system(f"sudo chown etrickel:etrickel {self.work_dir}/. -R")

                        # Differential testing is now handled in real-time during fuzzing
                        # No need for batch processing as files are processed and deleted immediately
                        if self.differential_enabled:
                            print(f"[Predator] Differential testing enabled")
                        else:
                            print(f"[Predator] Differential testing disabled")

                        # Filter XSS from response files instead of .out files
                        print(f"Checking response files processing status...")
                        responses_dir = os.path.join(self.work_dir, 'responses')
                        if os.path.exists(responses_dir):
                            # XSS filtering and differential testing are handled in real-time during fuzzing
                            
                            # Verify any remaining files (should be 0 or very few)
                            remaining_files = []
                            for root, dirs, files in os.walk(responses_dir):
                                for file in files:
                                    if not file.endswith('.tmp') and not file.endswith('.swp'):
                                        remaining_files.append(os.path.join(root, file))
                            
                            # Get thread-safe statistics
                            with self.stats_lock:
                                total_processed = self.processing_stats['total_files_processed']
                                xss_detected = self.processing_stats['xss_detected']
                                errors = self.processing_stats['errors']
                            
                            if len(remaining_files) == 0:
                                print(f"OK All response files processed successfully (total: {total_processed} files, XSS detected: {xss_detected}, errors: {errors})")
                            else:
                                print(f"WARNING {len(remaining_files)} files remained unprocessed (total processed: {total_processed} files, XSS detected: {xss_detected}, errors: {errors})")
                        else:
                            pass

                        

                        self.copy_fuzzer_output_to_results(trial_index, result_storage_pathname)
                        self.save_campaign_status()
                        sys.stdout.flush()
                        time.sleep(3)
                        self.kill_servers()
                        print("Sleeping a few and then will start up external servers ")
                        time.sleep(30)

                        self.fix_perms_in_dir(self.work_dir) # extra precaution for perms, I'm tired of these exceptions coming at the end of the loop!

                        self.start_external_servers()
                self.kill_servers()

        except Exception as exp:
            import traceback
            traceback.print_exc()

        finally:
            self.kill_servers()
            os.environ.clear()
            os.environ.update(_environ_backup)
            # kill supervisor to shutdown container, if its parent is supervisord (pid == 1)
            if os.getppid() == 1:
                try:
                    os.kill(1, signal.SIGQUIT)
                except Exception as e:
                    print(f'Could not kill supervisor with SIGQUIT: {e}, trying SIGKILL\n')
                    try:
                        os.kill(1, signal.SIGKILL)
                    except Exception as e2:
                        print(f'Could not force kill supervisor: {e2}\n')

    def log_event(self, message):
        """Log real-time events to log file, not to screen"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # Handle Unicode characters safely
        if isinstance(message, bytes):
            # If message is bytes, decode with error handling
            message = message.decode('utf-8', errors='replace')
        elif not isinstance(message, str):
            # Convert other types to string
            message = str(message)
        
        # Create log message with safe Unicode handling
        log_message = f"[{timestamp}] {message}\n"
        
        try:
            # Ensure log directory exists
            log_dir = os.path.dirname(self.log_file_path)
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            # Open with UTF-8 encoding to handle Unicode characters
            with open(self.log_file_path, 'a', encoding='utf-8', errors='replace') as log_file:
                log_file.write(log_message)
                log_file.flush()  # Flush immediately to disk
        except Exception as e:
            # Only output to screen when error occurs, with safe error message handling
            try:
                error_msg = str(e)
            except:
                error_msg = "Unknown encoding error"
            print(f"[Witcher Realtime] Error writing to log file: {error_msg}")

    def process_response_file_realtime(self, file_path, worker_id=0):
        """Real-time processing of single response file for XSS detection and differential testing"""
        try:
            # Only process .rsp files, ignore .req files in this function
            if not file_path.endswith('.rsp'):
                # For .req files, just remove them as they are handled paired with .rsp files
                if file_path.endswith('.req'):
                    os.remove(file_path)
                return
            
            # self.log_event(f"Worker {worker_id} - Processing response file: {file_path}")
            
            # Thread-safe update of statistics
            with self.stats_lock:
                self.processing_stats['total_files_processed'] += 1
                current_processed = self.processing_stats['total_files_processed']
            
            # Perform XSS detection on response file only if XSS detection is enabled
            filtered_lines = []
            if self.xss_detection_enabled:
                xss_patterns = [
                    '<script>alert(290363',
                    'javascript:alert(290363',
                    'onload=alert(290363)>',
                    'onerror=alert(290363)>',
                    'onclick=alert(290363)>',
                    '<img src=x onerror=alert(290363',
                    'onclick="alert(290363)">',
                    'onload="alert(290363)">',
                    'onerror="alert(290363)">',
                    'onmouseover="alert(290363)">',
                    'onfocus="alert(290363)">',
                ]
                
                with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
                    for line in file:
                        lower_line = line.lower()
                        # Check if any XSS pattern is found in the line
                        if any(xss in lower_line for xss in xss_patterns):
                            filtered_lines.append(line)
                        if lower_line.startswith('*t*'):
                            filtered_lines.append(line)
                
                if filtered_lines:
                    # Create XSS file using timestamp from filename
                    fuzzer_id = os.path.basename(os.path.dirname(file_path))
                    xss_file_path = os.path.join(self.work_dir, f"{fuzzer_id}.xss")
                    
                    with open(xss_file_path, 'a+') as xss_file:
                        xss_file.writelines(filtered_lines)
                    
                    # Thread-safe update of XSS detection statistics
                    with self.stats_lock:
                        self.processing_stats['xss_detected'] += 1
                        current_xss = self.processing_stats['xss_detected']
                    
                    self.log_event(f"Worker {worker_id} - XSS patterns detected in {os.path.basename(file_path)}, saved to {os.path.basename(xss_file_path)} (Total XSS: {current_xss})")
            
            # If differential testing is enabled, perform differential testing
            if self.differential_enabled:
                # Find corresponding .req file
                req_file = file_path.replace('.rsp', '.req')
                if os.path.exists(req_file):
                    self.perform_differential_test_single_file_pair(req_file, file_path)
            
            # Remove response file and corresponding request file
            os.remove(file_path)
            req_file = file_path.replace('.rsp', '.req')
            if os.path.exists(req_file):
                os.remove(req_file)
            
            # Output statistics every 100 files processed
            if current_processed % 100 == 0:
                with self.stats_lock:
                    stats = self.processing_stats.copy()
                self.log_event(f"Processing Statistics - Processed: {stats['total_files_processed']}, XSS: {stats['xss_detected']}, Errors: {stats['errors']}")
            
            # self.log_event(f"Worker {worker_id} - Processed and removed file pair: {file_path}")
            
        except Exception as e:
            # Thread-safe update of error statistics
            with self.stats_lock:
                self.processing_stats['errors'] += 1
                current_errors = self.processing_stats['errors']
                
            self.log_event(f"Worker {worker_id} - Error processing file {file_path}: {e} (Total Errors: {current_errors})")

    def perform_differential_test_single_file_pair(self, req_file, rsp_file):
        """Perform HTTP-based differential testing on a single request/response file pair"""
        if not self.differential_enabled:
            return
        
        try:
            # Get current target path
            patched_target = os.environ.get("SCRIPT_FILENAME")
            if not patched_target:
                self.log_event("Could not get current target from SCRIPT_FILENAME for differential test")
                return
            
            # Get unpatched target path
            unpatched_target = self.get_unpatched_url_for_differential_test(patched_target)
            if not unpatched_target:
                self.log_event(f"Could not generate unpatched target for differential testing: {patched_target}")
                return
            
            # Convert file paths to HTTP URLs
            patched_url = self.convert_file_path_to_http_url(patched_target)
            unpatched_url = self.convert_file_path_to_http_url(unpatched_target)
            
            if not patched_url or not unpatched_url:
                self.log_event(f"Could not convert file paths to HTTP URLs: {patched_target} -> {patched_url}, {unpatched_target} -> {unpatched_url}")
                diff_test_dir = os.path.join(self.work_dir, 'differential')
                os.makedirs(diff_test_dir, exist_ok=True)
                output_filename = f"error.cmp"
                output_path = os.path.join(diff_test_dir, output_filename)
                
                with open(output_path, 'w', encoding='utf-8', errors='replace') as wf:
                    wf.write(f"=== ERROR ===\n")
                    wf.write(f"Could not convert file paths to HTTP URLs\n")
                    wf.write(f"patched target: {patched_target} -> {patched_url}\n")
                    wf.write(f"unpatched target: {unpatched_target} -> {unpatched_url}\n")
                return
            
            # Read request file content as test input
            with open(req_file, 'rb') as rf:
                test_input = rf.read()
            
            # Load authenticated cookies for both URLs
            patched_cookies = self.load_patched_cookies()  # For patched URL
            unpatched_cookies = self.load_unpatched_cookies()  # For unpatched URL (pattern-replaced)
            
            self.log_event(f"Loaded URL1 cookies: {patched_cookies}")
            self.log_event(f"Loaded URL2 cookies: {unpatched_cookies}")
            
            def run_http_comparison():
                """
                Make HTTP requests to both patched and unpatched URLs with their respective cookies.
                
                Returns:
                    tuple: (patched_content, patched_status, unpatched_content, unpatched_status, patched_error, unpatched_error)
                """
                # Make HTTP request to patched URL with URL1 cookies
                self.log_event(f"Making HTTP request to patched URL: {patched_url}")
                patched_content, patched_status, patched_error = self.make_http_request_with_cookies(
                    patched_url, test_input, patched_cookies
                )
                
                # Make HTTP request to unpatched URL with URL2 cookies
                self.log_event(f"Making HTTP request to unpatched URL: {unpatched_url}")
                unpatched_content, unpatched_status, unpatched_error = self.make_http_request_with_cookies(
                    unpatched_url, test_input, unpatched_cookies
                )
                
                return patched_content, patched_status, unpatched_content, unpatched_status, patched_error, unpatched_error
            
            # Perform HTTP-based comparison
            patched_content, patched_status, unpatched_content, unpatched_status, patched_error, unpatched_error = run_http_comparison()
            
            # Normalize both responses for comparison
            normalized_patched_content = patched_content
            normalized_unpatched_content = unpatched_content
            
            if "url_pattern" in self.differential_config:
                pattern = self.differential_config["url_pattern"]
                from_pattern = pattern["from"]
                to_pattern = pattern["to"]
                
                # Normalize patched response
                if isinstance(patched_content, bytes):
                    patched_str = patched_content.decode('utf-8', errors='ignore')
                    normalized_patched_str = patched_str.replace(to_pattern, from_pattern)
                    try:
                        normalized_patched_content = normalized_patched_str.encode('utf-8', errors='ignore')
                    except UnicodeEncodeError:
                        normalized_patched_content = patched_content
                        self.log_event(f"Warning: Failed to normalize patched response due to encoding issues")
                else:
                    normalized_patched_content = patched_content.replace(to_pattern, from_pattern)
                
                # Normalize unpatched response
                if isinstance(unpatched_content, bytes):
                    unpatched_str = unpatched_content.decode('utf-8', errors='ignore')
                    normalized_unpatched_str = unpatched_str.replace(to_pattern, from_pattern)
                    try:
                        normalized_unpatched_content = normalized_unpatched_str.encode('utf-8', errors='ignore')
                    except UnicodeEncodeError:
                        normalized_unpatched_content = unpatched_content
                        self.log_event(f"Warning: Failed to normalize unpatched response due to encoding issues")
                else:
                    normalized_unpatched_content = unpatched_content.replace(to_pattern, from_pattern)
            
            # Calculate response length difference using normalized responses
            normalized_patched_length = len(normalized_patched_content)
            normalized_unpatched_length = len(normalized_unpatched_content)
            length_diff = abs(normalized_patched_length - normalized_unpatched_length)
            
            # Get threshold configuration
            thresholds = self.differential_config.get("thresholds", {})
            significant_diff_threshold = thresholds.get("length_diff_ratio", 0.05)
            retry_enabled = thresholds.get("retry_enabled", True)
            
            # Calculate if there is a significant difference
            min_length = max(normalized_patched_length, normalized_unpatched_length, 1)
            length_diff_ratio = length_diff / min_length
            
            is_significant_diff = (length_diff_ratio > significant_diff_threshold)
            retry_performed = False
            
            # Initialize deep analysis variables
            deep_analysis_performed = False
            deep_similarity_score = None
            deep_cleaned_patched = None
            deep_cleaned_unpatched = None
            
            # Set lengths for result saving (use normalized lengths)
            patched_length = normalized_patched_length
            unpatched_length = normalized_unpatched_length
            
            # If significant difference detected and retry enabled, perform retry verification
            if is_significant_diff and retry_enabled:
                self.log_event(f"Significant difference detected for {os.path.basename(req_file)} on first attempt. "
                              f"Length diff = {length_diff} bytes, Ratio = {length_diff_ratio:.2%}. Performing retry verification...")
                
                # For retry verification, make fresh HTTP requests to both URLs
                retry_patched_content, retry_patched_status, retry_unpatched_content, retry_unpatched_status, retry_patched_error, retry_unpatched_error = run_http_comparison()
                
                # Check for retry errors
                if retry_patched_error or retry_unpatched_error:
                    is_significant_diff = False
                else:
                    # Normalize both retry responses for more accurate length comparison
                    normalized_retry_patched_content = retry_patched_content
                    normalized_retry_unpatched_content = retry_unpatched_content
                    if "url_pattern" in self.differential_config:
                        pattern = self.differential_config["url_pattern"]
                        from_pattern = pattern["from"]
                        to_pattern = pattern["to"]
                        
                        # Normalize retry patched response
                        if isinstance(retry_patched_content, bytes):
                            retry_patched_str = retry_patched_content.decode('utf-8', errors='ignore')
                            normalized_retry_patched_str = retry_patched_str.replace(to_pattern, from_pattern)
                            try:
                                normalized_retry_patched_content = normalized_retry_patched_str.encode('utf-8', errors='ignore')
                            except UnicodeEncodeError:
                                normalized_retry_patched_content = retry_patched_content
                                self.log_event(f"Warning: Failed to normalize retry patched response due to encoding issues")
                        else:
                            normalized_retry_patched_content = retry_patched_content.replace(to_pattern, from_pattern)
                        
                        # Normalize retry unpatched response
                        if isinstance(retry_unpatched_content, bytes):
                            retry_unpatched_str = retry_unpatched_content.decode('utf-8', errors='ignore')
                            normalized_retry_unpatched_str = retry_unpatched_str.replace(to_pattern, from_pattern)
                            try:
                                normalized_retry_unpatched_content = normalized_retry_unpatched_str.encode('utf-8', errors='ignore')
                            except UnicodeEncodeError:
                                normalized_retry_unpatched_content = retry_unpatched_content
                                self.log_event(f"Warning: Failed to normalize retry unpatched response due to encoding issues")
                        else:
                            normalized_retry_unpatched_content = retry_unpatched_content.replace(to_pattern, from_pattern)
                    
                    # Recalculate differences with retry results using normalized responses
                    retry_normalized_patched_length = len(normalized_retry_patched_content)
                    retry_normalized_unpatched_length = len(normalized_retry_unpatched_content)
                    retry_length_diff = abs(retry_normalized_patched_length - retry_normalized_unpatched_length)
                    retry_min_length = max(retry_normalized_patched_length, retry_normalized_unpatched_length, 1)
                    retry_length_diff_ratio = retry_length_diff / retry_min_length
                    
                    retry_is_significant_diff = (retry_length_diff_ratio > significant_diff_threshold)
                    retry_performed = True
                    
                    with open('/tmp/retry_debug.log', 'a') as retry_dbg_file:
                        retry_dbg_file.write(f"HTTP Retry performed for {os.path.basename(req_file)}:\n")
                        retry_dbg_file.write(f"patched URL: {patched_url}, Status: {retry_patched_status}\n")
                        retry_dbg_file.write(f"unpatched URL: {unpatched_url}, Status: {retry_unpatched_status}\n")
                        retry_dbg_file.write(f"patched content: {normalized_retry_patched_content.decode('utf-8', errors='replace')[:500]}...\n")
                        retry_dbg_file.write(f"unpatched content: {normalized_retry_unpatched_content.decode('utf-8', errors='replace')[:500]}...\n")
                        retry_dbg_file.write(f"Length diff: {retry_length_diff} bytes, Ratio: {retry_length_diff_ratio:.2%}\n\n\n")
                    
                    if retry_is_significant_diff:
                        # Difference persists after retry, perform deep similarity comparison
                        self.log_event(f"Difference confirmed after retry for {os.path.basename(req_file)}. "
                                      f"Retry length diff = {retry_length_diff} bytes, Ratio = {retry_length_diff_ratio:.2%}. Performing deep similarity analysis...")
                        
                        # Clean dynamic content from both responses for deep comparison
                        cleaned_patched = self.clean_dynamic_content(normalized_retry_patched_content)
                        cleaned_unpatched = self.clean_dynamic_content(normalized_retry_unpatched_content)
                        with open('/tmp/crash.rsp', 'r', errors='ignore') as cr:
                            crash_rsp_content = cr.read()
                        cleaned_crash_rsp_content = self.clean_dynamic_content(crash_rsp_content)
                        # Calculate similarity score
                        similarity_score = self.calculate_similarity_score(cleaned_patched, cleaned_unpatched)
                        similarity_score_crash = self.calculate_similarity_score(cleaned_unpatched, cleaned_crash_rsp_content)
                        
                        # Get similarity threshold from config
                        similarity_threshold = self.differential_config.get("thresholds", {}).get("similarity_threshold", 0.90)
                        
                        # Check crash fields difference - compare unpatched and crash request parameters
                        is_crash_fields_only = self.check_crash_fields_only_difference(req_file)
                        
                        # Check if content is actually different after cleaning
                        is_truly_different = (similarity_score < similarity_threshold)
                        is_crash_different = (similarity_score_crash < similarity_threshold)

                        if is_crash_different:
                            vul_patterns = [
                                'mysql error', 'undefined index:', 'uninitialized string offset:', 'uninitialized array offset:', 
                                'illegal string offset', 'illegal offset type', 'query error', 'you have an error i', 'syntax error', 'sqlstate[',
                                '<script>alert(290363', 'javascript:alert(290363', 'onload=alert(290363)>', 'onerror=alert(290363)>',
                                'onclick=alert(290363)>', '<img src=x onerror=alert(290363', 'onclick="alert(290363)">', 
                                'onload="alert(290363)">', 'onerror="alert(290363)">', 'onmouseover="alert(290363)">', 'onfocus="alert(290363)">'
                            ]
                            for pattern in vul_patterns:
                                if pattern in cleaned_unpatched.lower():
                                    is_crash_different = False

                        if not cleaned_patched or not cleaned_unpatched:
                            is_truly_different = False
                            self.log_event(f"Deep analysis failed for {os.path.basename(req_file)} due to empty cleaned content.")
                        if 'Error displaying the error page' == cleaned_patched or 'Error displaying the error page' == cleaned_unpatched:
                            is_truly_different = False
                            self.log_event(f"Deep analysis failed for {os.path.basename(req_file)} due to error page content.")
                        if is_truly_different and is_crash_different and not is_crash_fields_only:
                            self.log_event(f"Deep analysis confirms significant difference for {os.path.basename(req_file)}. "
                                          f"Similarity score: {similarity_score:.4f} (threshold: {similarity_threshold}). Crash similarity: {similarity_score_crash:.4f}. "
                                          f"Crash fields only: {is_crash_fields_only}. Saving to .cmp file.")
                            patched_content, patched_status = retry_patched_content, retry_patched_status
                            unpatched_content, unpatched_status = retry_unpatched_content, retry_unpatched_status
                            patched_length, unpatched_length = retry_normalized_patched_length, retry_normalized_unpatched_length
                            length_diff, length_diff_ratio = retry_length_diff, retry_length_diff_ratio
                            is_significant_diff = True
                            # Store deep analysis results for logging
                            deep_analysis_performed = True
                            deep_similarity_score = similarity_score
                            deep_cleaned_patched = cleaned_patched
                            deep_cleaned_unpatched = cleaned_unpatched
                        else:
                            self.log_event(f"Deep analysis shows content is similar for {os.path.basename(req_file)}. "
                                          f"Similarity score: {similarity_score:.4f} (threshold: {similarity_threshold}). "
                                          f"Truly different: {is_truly_different}, "
                                          f"Crash different: {is_crash_different}, crash similarity: {similarity_score_crash:.4f}. "
                                          f"Crash fields only: {is_crash_fields_only}. Not saved.")
                            is_significant_diff = False
                            deep_analysis_performed = True
                    else:
                        # Difference resolved after retry, don't save
                        self.log_event(f"Difference resolved after retry for {os.path.basename(req_file)}. "
                                      f"First: {length_diff_ratio:.2%}, Retry: {retry_length_diff_ratio:.2%}. Not saving to .cmp file.")
                        is_significant_diff = False
                        
            
            # Save comparison result only if there are significant differences
            if is_significant_diff:
                # Create differential test results directory
                diff_test_dir = os.path.join(self.work_dir, 'differential')
                os.makedirs(diff_test_dir, exist_ok=True)
                
                # Save comparison results using timestamp from filename
                timestamp = os.path.splitext(os.path.basename(req_file))[0]
                output_filename = f"{timestamp}.cmp"
                output_path = os.path.join(diff_test_dir, output_filename)
                
                with open(output_path, 'w', encoding='utf-8', errors='replace') as wf:
                    wf.write(f"=== HTTP DIFFERENTIAL TEST RESULT ===\n")
                    wf.write(f"Request file: {os.path.basename(req_file)}\n")
                    wf.write(f"Response file: {os.path.basename(rsp_file)}\n")
                    wf.write(f"patched URL: {patched_url} (Status: {patched_status})\n")
                    wf.write(f"unpatched URL: {unpatched_url} (Status: {unpatched_status})\n")
                    wf.write(f"HTTP requests made with their respective authenticated cookies\n")
                    wf.write(f"URL1 cookies: {patched_cookies}\n")
                    wf.write(f"URL2 cookies: {unpatched_cookies}\n")
                    wf.write(f"patched response length: {patched_length} bytes\n")
                    wf.write(f"unpatched response length: {unpatched_length} bytes\n")
                    wf.write(f"Length difference: {length_diff} bytes ({length_diff_ratio:.2%})\n")
                    wf.write(f"Retry performed: {'YES' if retry_performed else 'NO'}\n")
                    if retry_performed:
                        wf.write(f"Retry verification: Fresh HTTP requests to both URLs - {'CONFIRMED' if is_significant_diff else 'RESOLVED'}\n")
                    else:
                        wf.write(f"Retry verification: N/A\n")
                    
                    # Add deep analysis information
                    wf.write(f"Deep analysis performed: {'YES' if deep_analysis_performed else 'NO'}\n")
                    if deep_analysis_performed and deep_similarity_score is not None:
                        similarity_threshold = self.differential_config.get("thresholds", {}).get("similarity_threshold", 0.90)
                        wf.write(f"Content similarity score: {deep_similarity_score:.4f} (threshold: {similarity_threshold})\n")
                        wf.write(f"Deep analysis result: {'TRULY_DIFFERENT' if is_significant_diff else 'DYNAMIC_CONTENT_ONLY'}\n")
                    
                    # Add crash fields analysis information
                    wf.write(f"Crash fields only difference: {'YES' if is_crash_fields_only else 'NO'}\n")
                    crash_fields = self.get_crash_fields_from_target()
                    if crash_fields:
                        wf.write(f"Crash fields identified: {', '.join(crash_fields)}\n")
                    else:
                        wf.write(f"Crash fields identified: None\n")
                    
                    wf.write(f"Significant difference detected: YES\n\n")
                    wf.write(f"=== REQUEST INPUT ===\n")
                    wf.write(test_input.decode('utf-8', errors='replace'))
                    
                    # Add cleaned content if deep analysis was performed
                    if deep_analysis_performed:
                        wf.write(f"\n\n=== Response returned by your patched application ===\n")
                        wf.write(deep_cleaned_patched if deep_cleaned_patched else "N/A")
                        wf.write(f"\n\n=== Response returned by original unpatched application ===\n")
                        wf.write(deep_cleaned_unpatched if deep_cleaned_unpatched else "N/A")
                        wf.write(f"\n\n=== Crash response content ===\n")
                        wf.write(cleaned_crash_rsp_content if cleaned_crash_rsp_content else "N/A")
                    else:
                        # Show raw responses if no deep analysis
                        wf.write(f"\n\n=== Raw response from patched application ===\n")
                        wf.write(patched_content.decode('utf-8', errors='replace')[:1000] + ("..." if len(patched_content) > 1000 else ""))
                        wf.write(f"\n\n=== Raw response from unpatched application ===\n")
                        wf.write(unpatched_content.decode('utf-8', errors='replace')[:1000] + ("..." if len(unpatched_content) > 1000 else ""))
                    
                    wf.write(f"\n=== END ===\n")
                
                if deep_analysis_performed:
                    if deep_similarity_score is not None:
                        self.log_event(f"Significant HTTP differential detected: {timestamp} - Length diff: {length_diff} bytes ({length_diff_ratio:.2%}), "
                                      f"Similarity score: {deep_similarity_score:.4f}")
                    else:
                        self.log_event(f"Significant HTTP differential detected: {timestamp} - Length diff: {length_diff} bytes ({length_diff_ratio:.2%})")
                else:
                    self.log_event(f"Significant HTTP differential detected: {timestamp} - Length diff: {length_diff} bytes ({length_diff_ratio:.2%})")
            else:
                timestamp = os.path.splitext(os.path.basename(req_file))[0]
                self.log_event(f"No significant HTTP differential detected: {timestamp} - Length diff: {length_diff} bytes ({length_diff_ratio:.2%})")
                
        except Exception as e:
            self.log_event(f"Error in HTTP differential test for {req_file}/{rsp_file}: {e}")

    def clean_dynamic_content(self, response_content):
        return response_content
        """
        Clean dynamic content from HTTP response for deep similarity comparison.
        For XSS vulnerability types, returns original content without any cleaning.
        For other types, removes cookies, timestamps, session IDs, JavaScript, and other dynamic elements.
        
        Args:
            response_content (bytes): Raw HTTP response content
            
        Returns:
            str: Cleaned content for comparison (or original content for XSS)
        """
        try:
            # For XSS vulnerability testing, return original content without any cleaning
            if self.xss_detection_enabled:
                self.log_event("XSS detection enabled - returning original content without cleaning")
                if isinstance(response_content, bytes):
                    return response_content.decode('utf-8', errors='replace')
                else:
                    return str(response_content)
            
            # Convert to string if it's bytes, with robust encoding handling
            if isinstance(response_content, bytes):
                # Try multiple encoding strategies
                content_str = None
                for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
                    try:
                        content_str = response_content.decode(encoding, errors='ignore')
                        break
                    except (UnicodeDecodeError, LookupError):
                        continue
                
                if content_str is None:
                    # Final fallback: use utf-8 with replace errors
                    content_str = response_content.decode('utf-8', errors='replace')
            else:
                content_str = str(response_content)
            
            # Split headers and body
            if '\r\n\r\n' in content_str:
                headers, body = content_str.split('\r\n\r\n', 1)
            elif '\n\n' in content_str:
                headers, body = content_str.split('\n\n', 1)
            else:
                headers, body = '', content_str
            
            # Clean headers - remove dynamic headers
            cleaned_headers = []
            dynamic_headers = [
                'set-cookie', 'date', 'expires', 'last-modified', 'etag',
                'x-request-id', 'x-trace-id', 'x-correlation-id',
                'server', 'x-powered-by', 'x-runtime', 'x-frame-options'
            ]
            
            for line in headers.split('\n'):
                line = line.strip()
                if ':' in line:
                    header_name = line.split(':', 1)[0].strip().lower()
                    if header_name not in dynamic_headers:
                        cleaned_headers.append(line)
                else:
                    cleaned_headers.append(line)
            
            # Try to parse body as HTML for more sophisticated cleaning
            try:
                try:
                    from bs4 import BeautifulSoup, Comment
                    soup = BeautifulSoup(body, 'html.parser')
                except ImportError:
                    raise ImportError("BeautifulSoup not available")
                
                # Remove JavaScript and CSS
                for script in soup(['script', 'style']):
                    script.decompose()
                
                # Remove comments
                for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                    comment.extract()
                
                # Remove common dynamic attributes
                dynamic_attrs = ['id', 'data-timestamp', 'data-session', 'nonce']
                for tag in soup.find_all():
                    for attr in dynamic_attrs:
                        if tag.has_attr(attr):
                            del tag[attr]
                
                # Remove form tokens and CSRF tokens
                for input_tag in soup.find_all('input'):
                    if input_tag.get('name') in ['_token', 'csrf_token', 'authenticity_token']:
                        input_tag.decompose()
                
                # Get cleaned text
                cleaned_body = soup.get_text(separator=' ', strip=True)
                
            except ImportError:
                self.log_event("BeautifulSoup not available, using basic text cleaning")
                # Basic cleaning without BeautifulSoup
                import re
                
                # Remove JavaScript blocks
                cleaned_body = re.sub(r'<script[^>]*>.*?</script>', '', body, flags=re.DOTALL | re.IGNORECASE)
                
                # Remove CSS blocks
                cleaned_body = re.sub(r'<style[^>]*>.*?</style>', '', cleaned_body, flags=re.DOTALL | re.IGNORECASE)
                
                # Remove HTML comments
                cleaned_body = re.sub(r'<!--.*?-->', '', cleaned_body, flags=re.DOTALL)
                
                # Remove HTML tags and get text content
                cleaned_body = re.sub(r'<[^>]+>', ' ', cleaned_body)
                
                # Remove multiple whitespaces
                cleaned_body = re.sub(r'\s+', ' ', cleaned_body).strip()
            
            except Exception as e:
                self.log_event(f"Error parsing HTML content: {e}, using raw text")
                # Fallback to raw text
                cleaned_body = body
            
            # Combine cleaned headers and body
            cleaned_content = '\n'.join(cleaned_headers) + '\n\n' + cleaned_body
            
            # Additional text normalization
            import re
            # Remove timestamps (various formats)
            cleaned_content = re.sub(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', '[TIMESTAMP]', cleaned_content)
            cleaned_content = re.sub(r'\d{10,13}', '[TIMESTAMP]', cleaned_content)  # Unix timestamps
            
            # Remove session IDs and tokens
            cleaned_content = re.sub(r'[a-f0-9]{32,}', '[TOKEN]', cleaned_content, flags=re.IGNORECASE)
            
            # Remove UUIDs
            cleaned_content = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '[UUID]', cleaned_content, flags=re.IGNORECASE)
            
            # Normalize whitespace
            cleaned_content = re.sub(r'\s+', ' ', cleaned_content).strip()
            
            return cleaned_content
            
        except Exception as e:
            self.log_event(f"Error cleaning dynamic content: {e}")
            # Return original content if cleaning fails, with robust encoding handling
            if isinstance(response_content, bytes):
                # Try multiple encoding strategies for fallback
                for encoding in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']:
                    try:
                        return response_content.decode(encoding, errors='ignore')
                    except (UnicodeDecodeError, LookupError):
                        continue
                # Final fallback
                return response_content.decode('utf-8', errors='replace')
            return str(response_content)

    def calculate_similarity_score(self, content1, content2):
        """
        Calculate similarity score between two cleaned content strings.
        
        Args:
            content1 (str): First content string
            content2 (str): Second content string
            
        Returns:
            float: Similarity score between 0.0 and 1.0
        """
        try:
            # Use difflib for sequence matching
            from difflib import SequenceMatcher
            matcher = SequenceMatcher(None, content1, content2)
            return matcher.ratio()
            
        except ImportError:
            self.log_event("difflib not available, using basic similarity calculation")
            # Fallback to basic length-based similarity
            if len(content1) == 0 and len(content2) == 0:
                return 1.0
            if len(content1) == 0 or len(content2) == 0:
                return 0.0
            
            length_diff = abs(len(content1) - len(content2))
            max_length = max(len(content1), len(content2))
            return 1.0 - (length_diff / max_length)
        
        except Exception as e:
            self.log_event(f"Error calculating similarity: {e}")
            return 0.0
    
    def check_crash_fields_only_difference(self, req_file):
        """
        Check if the difference between unpatched and crash request parameters 
        is only in crash fields.
        
        Args:
            req_file (str): Path to the request file
            
        Returns:
            bool: True if difference is only in crash fields, False otherwise
        """
        try:
            # Get crash fields from current target's POC metadata
            crash_fields = self.get_crash_fields_from_target()
            if not crash_fields:
                self.log_event("No crash fields found, skipping crash fields analysis")
                return False
            
            # Read crash request parameters
            crash_req_path = '/tmp/crash.req'
            crash_rsp_path = '/tmp/crash.rsp'
            if not os.path.exists(crash_rsp_path):
                self.log_event(f"Crash response file not found: {crash_rsp_path}")
                return False
            if not os.path.exists(crash_req_path):
                self.log_event(f"Crash request file not found: {crash_req_path}")
                return False
            
            with open(crash_req_path, 'r', errors='ignore') as cf:
                crash_req_content = cf.read()

            with open(crash_rsp_path, 'r', errors='ignore') as cr:
                crash_rsp_content = cr.read()
            
            # Read patched request parameters  
            with open(req_file, 'r', errors='ignore') as sf:
                patched_req_content = sf.read()
            
            # Parse request parameters from both files
            crash_params = self.parse_request_parameters(crash_req_content)
            patched_params = self.parse_request_parameters(patched_req_content)

            # Check if difference is only in crash fields
            is_only_crash_fields = self.compare_params_with_crash_fields(
                patched_params, crash_params, crash_fields
            )
            
            if is_only_crash_fields:
                self.log_event(f"Difference is only in crash fields: {crash_fields}")
            else:
                self.log_event("Difference involves non-crash fields or missing expected differences")
            
            return is_only_crash_fields
            
        except Exception as e:
            self.log_event(f"Error in crash fields analysis: {e}")
            return False
    
    def get_crash_fields_from_target(self):
        """
        Get crash fields from the current target's POC metadata.
        
        Returns:
            list: List of crash field names
        """
        # Method 1: Check if POC path is configured in differential_testing config
        poc_path = self.differential_config.get("poc_path")
        if poc_path and os.path.exists(poc_path):
            return self.extract_crash_fields_from_poc_file(poc_path)
    
    def extract_crash_fields_from_poc_file(self, poc_file_path):
        """
        Extract crash fields from a specific POC file.
        
        Args:
            poc_file_path (str): Path to the POC file
            
        Returns:
            list: List of crash field names
        """
        try:
            with open(poc_file_path, 'r', errors='ignore') as pf:
                content = pf.read()
                
                # Look for CRASH_FIELDS in docstring
                lines = content.split('\n')
                for line in lines:
                    if '[CRASH_FIELDS]' in line:
                        crash_fields_str = line.split('[CRASH_FIELDS]')[-1].strip()
                        if crash_fields_str:
                            crash_fields = [field.strip() for field in crash_fields_str.split(',') if field.strip()]
                            self.log_event(f"Found crash fields in {os.path.basename(poc_file_path)}: {crash_fields}")
                            return crash_fields
            
            return []
            
        except Exception as e:
            self.log_event(f"Error extracting crash fields from {poc_file_path}: {e}")
            return []
    
    def parse_request_parameters(self, request_content):
        """
        Parse HTTP request content and extract parameters.
        
        Args:
            request_content (str): Raw HTTP request content
            
        Returns:
            dict: Dictionary of parameter name-value pairs
        """
        try:
            params = {}
            
            # Handle different request formats
            if '?' in request_content:
                # GET parameters
                query_part = request_content.split('?', 1)[1]
                # Remove HTTP protocol part if present
                if ' HTTP/' in query_part:
                    query_part = query_part.split(' HTTP/')[0]
                
                if '&' in query_part:
                    query_parts = query_part.split('&')
                    for param in query_parts:
                        if '=' in param:
                            key, value = param.split('=', 1)
                            params[key.strip()] = value.strip()
                elif '=' in query_part:
                    key, value = query_part.split('=', 1)
                    params[key.strip()] = value.strip()
            
            # Also check for POST data format (key=value&key=value)
            if '=' in request_content and '&' in request_content:
                parts = request_content.split('&')
                for part in parts:
                    if '=' in part and '?' not in part and ' HTTP/' not in part:
                        key, value = part.split('=', 1)
                        params[key.strip()] = value.strip()
            
            return params
            
        except Exception as e:
            self.log_event(f"Error parsing request parameters: {e}")
            return {}
    
    def compare_params_with_crash_fields(self, patched_params, crash_params, crash_fields):
        """
        Compare patched and crash parameters to check if difference is only in crash fields.
        
        Args:
            patched_params (dict): Parameters from patched request
            crash_params (dict): Parameters from crash request  
            crash_fields (list): List of crash field names
            
        Returns:
            bool: True if difference is only in crash fields
        """
        try:
            if '\x00' in crash_params:
                crash_params_parts = crash_params.split(b'\x00')
                if len(crash_params_parts) == 4:
                    cookie_data, urlquery, post_data, headers = crash_params_parts
                    if post_data:
                        crash_params = post_data
                    else:
                        crash_params = urlquery
            # Check if all common non-crash fields are identical
            # (Allow patched to have new parameters, but common non-crash fields must be the same)
            for key, value in patched_params.items():
                if key not in crash_fields and key in crash_params:
                    # Common non-crash field should have same value
                    if crash_params[key] != value:
                        self.log_event(f"Common non-crash field {key} differs: patched='{value}', crash='{crash_params[key]}'")
                        return False

            # Check if crash params has non-crash fields that patched doesn't have
            for key in crash_params.keys():
                if key not in crash_fields and key not in patched_params:
                    self.log_event(f"Crash params has extra non-crash field: {key}")
                    return False

            return True
            
        except Exception as e:
            self.log_event(f"Error comparing parameters: {e}")
            return False
            
    def response_processor_worker(self, worker_id, response_queue):
        """Background thread worker function to process response file queue - supports multi-core"""
        self.log_event(f"Response processor worker {worker_id} started")
        
        while self.response_monitor_active:
            try:
                # Get file path from queue, timeout after 1 second
                file_path = response_queue.get(timeout=1)
                if file_path is None:  # Stop signal
                    self.log_event(f"Worker {worker_id} received stop signal")
                    break
                
                self.process_response_file_realtime(file_path, worker_id)
                response_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.log_event(f"Error in response processor worker {worker_id}: {e}")
        
        self.log_event(f"Response processor worker {worker_id} stopped")

    def start_response_monitoring(self):
        """Start real-time response file monitoring - supports multi-core parallel processing"""
        # If already running, stop first
        if self.response_monitor_active:
            self.log_event("Response monitoring already active, stopping existing monitoring first")
            self.stop_response_monitoring()
        
        responses_dir = os.path.join(self.work_dir, 'responses')
        if not os.path.exists(responses_dir):
            os.makedirs(responses_dir, exist_ok=True)
            os.chmod(responses_dir, 0o755)
        
        self.response_monitor_active = True
        
        # Reset statistics
        with self.stats_lock:
            self.processing_stats = {
                'total_files_processed': 0,
                'xss_detected': 0,
                'errors': 0
            }
        
        # Create queue and processing thread for each core
        self.response_queues = []
        self.response_processor_threads = []
        self.response_observers = []
        
        self.log_event(f"Starting {self.cores} response monitor workers")
        
        for worker_id in range(self.cores):
            response_queue = queue.Queue(maxsize=10)
            self.response_queues.append(response_queue)
            
            # Create processing thread
            processor_thread = threading.Thread(
                target=self.response_processor_worker, 
                args=(worker_id, response_queue)
            )
            processor_thread.daemon = True
            processor_thread.start()
            self.response_processor_threads.append(processor_thread)
            
            self.log_event(f"Started response processor worker {worker_id}")
        
        # Set up file system monitoring - use polling for compatibility
        self.start_polling_monitor(responses_dir)
        
        self.log_event(f"Response monitoring started with {self.cores} workers")

    def start_polling_monitor(self, responses_dir):
        """Use polling method to monitor file changes - support multi-queue load balancing"""
        def polling_worker():
            file_counter = 0  # For load balancing
            last_stats_time = time.time()
            processed_files = set()  # Track processed files
            self.log_event("Started polling monitor with load balancing")
            
            while self.response_monitor_active:
                try:
                    # Scan all files in responses directory
                    current_files = []
                    for root, dirs, files in os.walk(responses_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            # Skip temporary files and swap files
                            if not file.endswith('.tmp') and not file.endswith('.swp') and not file.startswith('.'):
                                current_files.append(file_path)
                    
                    # Only process new .rsp files that have corresponding .req files
                    new_files = []
                    for file_path in current_files:
                        if file_path not in processed_files and os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                            # If this is a .rsp file, check if corresponding .req file exists
                            if file_path.endswith('.rsp'):
                                req_file = file_path.replace('.rsp', '.req')
                                if os.path.exists(req_file) and os.path.getsize(req_file) >= 0:
                                    new_files.append(file_path)
                                    # Also mark the .req file as processed so it doesn't get processed separately
                                    processed_files.add(req_file)
                            # If this is a .req file, only add it if there's no corresponding .rsp file yet
                            elif file_path.endswith('.req'):
                                rsp_file = file_path.replace('.req', '.rsp')
                                if not os.path.exists(rsp_file):
                                    new_files.append(file_path)
                            # For other file types (backward compatibility)
                            else:
                                new_files.append(file_path)
                    
                    # Add new files to queue for processing
                    for file_path in new_files:
                        # Use round-robin to assign files to different queues
                        queue_index = file_counter % len(self.response_queues)
                        try:
                            # Add to queue in non-blocking way, skip if queue is full
                            self.response_queues[queue_index].put_nowait(file_path)
                            processed_files.add(file_path)  # Mark as processed
                            # self.log_event(f"New response file detected: {os.path.basename(file_path)} -> Worker {queue_index}")
                            file_counter += 1
                        except queue.Full:
                            # Queue is full, log but continue processing other files
                            self.log_event(f"Queue {queue_index} full, skipping file: {os.path.basename(file_path)}")
                            os.remove(file_path)  # Remove file
                            # Also remove corresponding file if it exists
                            if file_path.endswith('.rsp'):
                                req_file = file_path.replace('.rsp', '.req')
                                if os.path.exists(req_file):
                                    os.remove(req_file)
                            elif file_path.endswith('.req'):
                                rsp_file = file_path.replace('.req', '.rsp')
                                if os.path.exists(rsp_file):
                                    os.remove(rsp_file)
                    
                    # Clean up records of deleted files (these have been processed and deleted by workers)
                    processed_files = {f for f in processed_files if os.path.exists(f)}
                    
                    # Output statistics and queue status every 30 seconds
                    current_time = time.time()
                    if current_time - last_stats_time >= 30:
                        with self.stats_lock:
                            stats = self.processing_stats.copy()
                        
                        remaining_files = len(current_files)
                        total_queue_size = sum(q.qsize() for q in self.response_queues)
                        
                        self.log_event(f"Real-time Stats - Processed: {stats['total_files_processed']}, "
                                              f"XSS: {stats['xss_detected']}, Errors: {stats['errors']}, "
                                              f"Remaining: {remaining_files}, Queued: {total_queue_size}")
                        
                        # Show status of each queue
                        queue_status = []
                        for i, q in enumerate(self.response_queues):
                            queue_status.append(f"Q{i}:{q.qsize()}")
                        self.log_event(f"Queue Status: {', '.join(queue_status)}")
                        
                        last_stats_time = current_time
                    
                    time.sleep(1.0)  # Moderate polling interval
                    
                except Exception as e:
                    self.log_event(f"Error in polling worker: {e}")
                    time.sleep(1)
            
            self.log_event("Polling monitor stopped")
        
        # Start polling thread
        self.polling_thread = threading.Thread(target=polling_worker)
        self.polling_thread.daemon = True
        self.polling_thread.start()

    def stop_response_monitoring(self):
        """Stop real-time response file monitoring - support multi-core cleanup"""
        if not self.response_monitor_active:
            return
        
        self.log_event("Stopping response monitoring...")
        
        # Stop polling thread to prevent new files from entering queue
        if hasattr(self, 'polling_thread'):
            self.polling_thread.join(timeout=2)
            self.log_event("Polling thread stopped")
        
        # Wait for all queues to finish processing (before stopping worker threads)
        self.log_event("Waiting for all queues to finish processing...")
        total_pending = 0
        for i, response_queue in enumerate(self.response_queues):
            pending = response_queue.qsize()
            total_pending += pending
            if pending > 0:
                self.log_event(f"Worker {i} has {pending} pending files")
        
        if total_pending > 0:
            self.log_event(f"Total pending files: {total_pending}. Waiting for completion...")
            
            # Wait for all queues to finish processing, but set timeout (workers still running)
            max_wait_time = 60  # 1 minutes timeout
            start_wait = time.time()
            # kill all afl-fuzz processes
            os.system("pkill -f afl-fuzz")
            while time.time() - start_wait < max_wait_time:
                total_remaining = sum(q.qsize() for q in self.response_queues)
                if total_remaining == 0:
                    self.log_event("All queues processed successfully")
                    break
                
                # Show detailed progress information
                with self.stats_lock:
                    current_stats = self.processing_stats.copy()
                
                self.log_event(f"Still processing... {total_remaining} files remaining. "
                                      f"Processed: {current_stats['total_files_processed']}, "
                                      f"XSS: {current_stats['xss_detected']}, "
                                      f"Errors: {current_stats['errors']}")
                time.sleep(10)  # Check every 10 seconds
            else:
                with self.stats_lock:
                    final_stats = self.processing_stats.copy()
                self.log_event(f"Timeout reached after {max_wait_time}s. {total_remaining} files remaining. "
                                      f"Final stats - Processed: {final_stats['total_files_processed']}, "
                                      f"XSS: {final_stats['xss_detected']}, Errors: {final_stats['errors']}")
        
        # Now stop the file monitoring flag to let worker threads exit naturally
        self.response_monitor_active = False
        
        # Send stop signal to all worker threads
        self.log_event("Sending stop signals to all workers...")
        for i, response_queue in enumerate(self.response_queues):
            try:
                response_queue.put(None, timeout=1)  # Stop signal with timeout
                self.log_event(f"Stop signal sent to worker {i}")
            except queue.Full:
                self.log_event(f"Warning: Could not send stop signal to worker {i} (queue full)")
        
        # Wait for all processing threads to finish
        self.log_event("Waiting for all worker threads to stop...")
        for i, processor_thread in enumerate(self.response_processor_threads):
            processor_thread.join(timeout=10)
            if processor_thread.is_alive():
                self.log_event(f"Warning: Worker {i} thread did not stop gracefully")
            else:
                self.log_event(f"Worker {i} thread stopped successfully")
        
        responses_dir = os.path.join(self.work_dir, 'responses')
        if os.path.exists(responses_dir):
            # Clean up any remaining .req/.rsp file pairs
            remaining_files = []
            for root, dirs, files in os.walk(responses_dir):
                for file in files:
                    if file.endswith('.req') or file.endswith('.rsp'):
                        file_path = os.path.join(root, file)
                        if os.path.exists(file_path):
                            remaining_files.append(file_path)
                            
            for file_path in remaining_files:
                try:
                    os.remove(file_path)
                except Exception as e:
                    self.log_event(f"Error removing remaining file {file_path}: {e}")
            
            try:
                import shutil
                shutil.rmtree(responses_dir)
                self.log_event(f"Responses directory removed: {responses_dir}")
            except Exception as e:
                self.log_event(f"Error removing responses directory {responses_dir}: {e}")
        
        # Clean up resources
        self.response_queues = []
        self.response_processor_threads = []
        self.response_observers = []
        
        # Thread-safe get final statistics
        with self.stats_lock:
            final_stats = self.processing_stats.copy()
        
        # Print final statistics
        self.log_event(f"Response monitoring stopped. Final Statistics:")
        self.log_event(f"  Total files processed: {final_stats['total_files_processed']}")
        self.log_event(f"  XSS detected: {final_stats['xss_detected']}")
        self.log_event(f"  Errors: {final_stats['errors']}")
        self.log_event(f"  Log file saved to: {self.log_file_path}")
        
        self.log_event("Response monitoring shutdown complete")

    def load_authenticated_cookies(self):
        """
        Load authenticated session cookies from /tmp/cookies.dat if it exists and is not empty.
        
        Returns:
            dict: Dictionary of cookies if available, empty dict otherwise
        """
        cookies_file = '/tmp/cookies.dat'
        try:
            if os.path.exists(cookies_file) and os.path.getsize(cookies_file) > 0:
                with open(cookies_file, 'r', encoding='utf-8', errors='replace') as f:
                    cookies = json.load(f)
                self.log_event(f"Loaded authenticated cookies from {cookies_file}: {cookies}")
                return cookies
            else:
                self.log_event(f"No authenticated cookies found at {cookies_file}")
                return {}
        except Exception as e:
            self.log_event(f"Error loading authenticated cookies from {cookies_file}: {e}")
            return {}
    
    def load_patched_cookies(self):
        """
        Load URL1 authenticated session cookies from /tmp/cookies_url1.dat.
        
        Returns:
            dict: Dictionary of URL1 cookies if available, empty dict otherwise
        """
        cookies_file = '/tmp/cookies_url1.dat'
        try:
            if os.path.exists(cookies_file) and os.path.getsize(cookies_file) > 0:
                with open(cookies_file, 'r', encoding='utf-8', errors='replace') as f:
                    cookies = json.load(f)
                self.log_event(f"Loaded URL1 authenticated cookies from {cookies_file}: {cookies}")
                return cookies
            else:
                self.log_event(f"No URL1 authenticated cookies found at {cookies_file}")
                return {}
        except Exception as e:
            self.log_event(f"Error loading URL1 authenticated cookies from {cookies_file}: {e}")
            return {}
    
    def load_unpatched_cookies(self):
        """
        Load URL2 authenticated session cookies from /tmp/cookies_url2.dat.
        
        Returns:
            dict: Dictionary of URL2 cookies if available, empty dict otherwise
        """
        cookies_file = '/tmp/cookies_url2.dat'
        try:
            if os.path.exists(cookies_file) and os.path.getsize(cookies_file) > 0:
                with open(cookies_file, 'r', encoding='utf-8', errors='replace') as f:
                    cookies = json.load(f)
                self.log_event(f"Loaded URL2 authenticated cookies from {cookies_file}: {cookies}")
                return cookies
            else:
                self.log_event(f"No URL2 authenticated cookies found at {cookies_file}")
                return {}
        except Exception as e:
            self.log_event(f"Error loading URL2 authenticated cookies from {cookies_file}: {e}")
            return {}
    
    def make_http_request_with_cookies(self, url, request_data, cookies=None):
        """
        Make HTTP request to a URL with request data and optional cookies.
        
        Args:
            url (str): Target URL
            request_data (bytes): Request data in format: cookie_data\x00urlquery\x00post_data\x00headers
            cookies (dict): Optional cookies to include
            
        Returns:
            tuple: (response_content: bytes, status_code: int, error: str)
        """
        try:
            # Parse request data
            parts = request_data.split(b'\x00', 3)
            if len(parts) < 4:
                return b"", 0, "Invalid request data format"
            
            cookie_data, urlquery, post_data, headers_data = parts
            
            # Build cookies
            request_cookies = {}
            
            # Add cookies from request data
            if cookie_data:
                cookie_str = cookie_data.decode('utf-8', errors='ignore')
                for cookie_pair in cookie_str.split(';'):
                    if '=' in cookie_pair:
                        key, value = cookie_pair.strip().split('=', 1)
                        request_cookies[key] = value
            
            # Add additional cookies (these take precedence)
            if cookies:
                request_cookies.update(cookies)
            
            # Build URL with query parameters
            request_url = url
            if urlquery:
                query_str = urlquery.decode('utf-8', errors='ignore')
                if query_str and '=' in query_str:
                    separator = '&' if '?' in request_url else '?'
                    request_url = f"{request_url}{separator}{query_str}"
            
            # Parse headers
            request_headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            }
            if headers_data:
                headers_str = headers_data.decode('utf-8', errors='ignore')
                for header_line in headers_str.split('\n'):
                    if ':' in header_line:
                        key, value = header_line.split(':', 1)
                        request_headers[key.strip()] = value.strip()
            
            # Make HTTP request
            session = requests.Session()
            
            # Add XDEBUG_TRIGGER if enabled
            # use_trigger = os.environ.get('USE_XDEBUG_TRIGGER', 'true').lower() == 'true'
            # if use_trigger:
            #     request_cookies['XDEBUG_TRIGGER'] = '1'
            request_cookies.pop('XDEBUG_TRIGGER', None)  # Remove if exists
            
            self.log_event(f"Making HTTP request to: {request_url}")
            self.log_event(f"Request cookies: {request_cookies}")
            
            if post_data and post_data.strip():
                # POST request
                post_str = post_data.decode('utf-8', errors='ignore')
                self.log_event(f"POST data: {post_str}")
                
                request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
                response = session.post(
                    request_url,
                    data=post_str,
                    headers=request_headers,
                    cookies=request_cookies,
                    timeout=10,
                    allow_redirects=True
                )
            else:
                # GET request
                response = session.get(
                    request_url,
                    headers=request_headers,
                    cookies=request_cookies,
                    timeout=10,
                    allow_redirects=True
                )
            
            self.log_event(f"HTTP response status: {response.status_code}")
            self.log_event(f"HTTP response length: {len(response.content)} bytes")
            
            return response.content, response.status_code, ""
            
        except Exception as e:
            error_msg = f"HTTP request failed: {str(e)}"
            self.log_event(error_msg)
            return b"", 0, error_msg
    
    def merge_cookies_with_request_data(self, test_input, additional_cookies):
        """
        Merge additional cookies with existing request data.
        
        Args:
            test_input (bytes): Original request data in format: cookie_data\x00urlquery\x00post_data\x00headers
            additional_cookies (dict): Additional cookies to merge
            
        Returns:
            bytes: Modified request data with merged cookies
        """
        if not additional_cookies:
            return test_input
        
        try:
            # Split the request data
            parts = test_input.split(b'\x00', 3)
            if len(parts) < 4:
                # If format is unexpected, return original
                return test_input
            
            cookie_data, urlquery, post_data, headers = parts
            
            # Parse existing cookies
            existing_cookies = {}
            if cookie_data:
                cookie_str = cookie_data.decode('utf-8', errors='ignore')
                for cookie_pair in cookie_str.split(';'):
                    if '=' in cookie_pair:
                        key, value = cookie_pair.strip().split('=', 1)
                        existing_cookies[key] = value
            
            # Merge with additional cookies (additional cookies take precedence)
            merged_cookies = existing_cookies.copy()
            merged_cookies.update(additional_cookies)
            
            # Reconstruct cookie string
            cookie_pairs = []
            for key, value in merged_cookies.items():
                cookie_pairs.append(f"{key}={value}")
            merged_cookie_str = '; '.join(cookie_pairs)
            
            # Reconstruct request data
            merged_test_input = b'%s\x00%s\x00%s\x00%s' % (
                merged_cookie_str.encode('utf-8'),
                urlquery,
                post_data,
                headers
            )
            
            self.log_event(f"Merged cookies: {len(additional_cookies)} additional cookies added to request")
            return merged_test_input
            
        except Exception as e:
            self.log_event(f"Error merging cookies with request data: {e}")
            return test_input
    
    def convert_file_path_to_http_url(self, file_path):
        """
        Convert a file path to an HTTP URL for making requests.
        
        Args:
            file_path (str): File path like /app/joomla/administrator/index.php
            
        Returns:
            str: HTTP URL like http://localhost/joomla/administrator/index.php
        """
        try:
            # Get base URL configuration
            base_url = self.differential_config.get("base_url", "http://localhost")
            
            # Remove /app prefix if present
            if file_path.startswith("/app/"):
                relative_path = file_path[5:]  # Remove "/app/"
            elif file_path.startswith("/app"):
                relative_path = file_path[4:]  # Remove "/app"
            else:
                relative_path = file_path
            
            # Ensure relative path starts with /
            if not relative_path.startswith("/"):
                relative_path = "/" + relative_path
            
            # Combine base URL with relative path
            http_url = base_url.rstrip("/") + relative_path
            
            self.log_event(f"Converted file path to HTTP URL: {file_path} -> {http_url}")
            return http_url
            
        except Exception as e:
            self.log_event(f"Error converting file path to HTTP URL: {file_path} - {e}")
            return None
