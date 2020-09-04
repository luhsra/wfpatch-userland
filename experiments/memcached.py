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


class MemcachedBenchmark(WaitFreeExperiment):
    MEMCACHED_SERVER_DIR           = "/srv/scratch/osdi/memcached"

    inputs = dict(WaitFreeExperiment.inputs)
    inputs['clients'] =  Integer(50)

    outputs = dict(WaitFreeExperiment.outputs)

    def run(self):
        logging.info("Copy Benchmark")
        with Directory(self.MEMCACHED_SERVER_DIR):
            self.client_copy("wf-benchmark/benchmark.py", "/tmp/memcached-benchmark.py")

        wfb = os.path.join(self.MEMCACHED_SERVER_DIR, "wf-benchmark")

        runs = self.setup_experiment()

        for run in range(0, runs):
            logging.info("Run %d", run)

            server_env = self.server_env(
                run=run,
                WF_CYCLIC="1.5",
                WF_CYCLIC_RANDOM="100",
                WF_CYCLIC_BOOT="3",
            )

            subprocess.call("pkill -9 memcached.old", shell=True)
            print(server_env)

            logging.info("Starting Client")
            client  = self.client_popen([
                "/tmp/memcached-benchmark.py",
                str(self.clients.value),
            ], run=run)

            server = subprocess.Popen([f"{wfb}/memcached.old", "-m", "1024"],
                                      env=server_env)


            server.communicate()
            server_ret = server.wait()
            client_ret = client.wait()
            assert server_ret == 0, ("Server Failed", server_ret)

        self.teardown_experiment()

    def symlink_name(self):
        ret = f"MemcachedBenchmark-mode={self.mode.value}"
        if self.with_patches():
            ret += ",patches"
        return ret

if __name__ == "__main__":
    if sys.argv[1] == "all":
        for mode in ["local", "global"]:
            experiment = MemcachedBenchmark()
            experiment(sys.argv[2:] + [
                "--count", "1000",
                "--mode", mode,
                "-s", "-vv",
            ])
    else:
        experiment = MemcachedBenchmark()
        experiment(sys.argv[1:] + ["-s"])
