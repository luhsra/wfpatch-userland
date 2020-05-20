#!/usr/bin/python3
import os, sys
tmp_path = "%s/git/versuchung/src"% os.environ["HOME"]
if os.path.exists(tmp_path):
    sys.path.append(tmp_path)


import time
from pathlib import Path
from versuchung.experiment import Experiment
from versuchung.types import String, Bool,List,Integer
from versuchung.database import Database
from versuchung.files import File, Directory, Executable
from versuchung.archives import GitArchive
from versuchung.execute import shell
from versuchung.tex import DatarefDict
import subprocess
import logging

from common import WaitFreeExperiment


class OpenLDAPBenchmark(WaitFreeExperiment):
    OPENLDAP_SERVER_DIR           = "/srv/scratch/osdi/openldap"

    inputs = dict(WaitFreeExperiment.inputs)
    inputs['clients'] =  Integer(200)
    inputs['records'] =  Integer(50)
    
    outputs = dict(WaitFreeExperiment.outputs)

    def run(self):
        logging.info("Build Benchmark")
        with Directory(self.OPENLDAP_SERVER_DIR):
            shell("make -C wf-benchmark benchmark")
            self.client_copy("wf-benchmark/benchmark", "/tmp/openldap-benchmark")
        wfb = os.path.join(self.OPENLDAP_SERVER_DIR, "wf-benchmark")

        runs = self.setup_experiment()

        for run in range(0, runs):
            logging.info("Run %d", run)
            server_env = self.server_env(
                run=run,
                WF_CYCLIC="0.5",
                WF_CYCLIC_BOOT="3",
            )

            subprocess.call("pkill -9 slapd.old", shell=True)
            print(server_env)

            logging.info("Starting Client")
            client  = self.client_popen([
                "/tmp/openldap-benchmark",
                str(self.clients.value),
                str(self.records.value)
            ], run=run)


            server = subprocess.Popen([f"{wfb}/slapd.old",
                                       "-h", "ldap://0.0.0.0:1500",
                                       "-d", "0",
                                       "-f", f"{wfb}/slapd.conf" ],
                                      env=server_env)


            server.communicate()
            server_ret = server.wait()
            client_ret = client.wait()
            assert server_ret == 0, ("Server Failed", server_ret)

        self.teardown_experiment()

    def symlink_name(self):
        ret = f"OpenLDAPBenchmark-mode={self.mode.value},delay={self.delay.value}"
        if self.with_patches():
            ret += ",patches"
        return ret

if __name__ == "__main__":
    if sys.argv[1] == "all":
        for delay in [0, 5, 10, 25, 50]:
            for mode in ["local", "global"]:
                experiment = OpenLDAPBenchmark()
                experiment(sys.argv[2:] + [
                    "--count", "1000",
                    "--delay", str(delay),
                    "--mode", mode,
                    "-s", "-vv",
                ])
    else:
        experiment = OpenLDAPBenchmark()
        experiment(sys.argv[1:] + ["-s"])
