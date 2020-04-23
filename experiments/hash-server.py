#!/usr/bin/python3
import os, sys, signal
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
from urllib.request import urlopen
from urllib.error import URLError
import subprocess
import logging
import traceback
import socket

from common import WaitFreeExperiment


class HashServerBenchmark(WaitFreeExperiment):
    HASH_SERVER_DIR           = "/srv/scratch/dietrich/patch/hash-server"

    inputs = dict(WaitFreeExperiment.inputs)
    inputs['clients'] =  Integer(10)
    
    outputs = dict(WaitFreeExperiment.outputs)

    def run(self):
        with Directory(self.HASH_SERVER_DIR):
            shell("make server-good")
            self.client_copy("client.py", "/tmp/hash-server-client.py")

        server_env = self.setup_experiment()

        server = subprocess.Popen(
            [self.HASH_SERVER_DIR + "/server-good"],
            env=server_env,
        )

        #self.wait_for_tcp("localhost", "7799")

        logging.info("Starting Client")
        client  = self.client_popen([
            "/tmp/hash-server-client.py",
            "--host", socket.gethostname(),
            "--clients", str(self.clients.value),
            "--constant",
            "--zeros", "22",
        ])

        server.communicate()
        server_ret = server.wait()
        assert server_ret == 0, "Server Failed"
        client.wait()

        self.teardown_experiment()


    def symlink_name(self):
        return f"HashServerBenchmark-mode={self.mode.value},delay={self.delay.value}"

if __name__ == "__main__":
    BENCHMARK = HashServerBenchmark
    os.setpgrp() # create new process group, become its leader
    try:
        if sys.argv[1] == "all":
            modes = ["base", "local", "global"]
            for mode in modes:
                experiment = BENCHMARK()
                experiment(sys.argv[2:] + [
                    "--count", "10000",
                    "--mode", mode,
                    "-s"
                ])
        else:
            experiment = BENCHMARK()
            experiment(sys.argv[1:] + ["-s"])
    except Exception as e:
        print(traceback.format_exc())
        print("EXCEPTION: ", e, type(e))
        raise e
    finally:
        print("CLEANUP experiment")
        os.killpg(0, signal.SIGTERM) # kill all processes in my group
