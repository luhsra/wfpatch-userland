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


class NodeBenchmark(Experiment):
    NODE_DIR           = "/srv/scratch/dietrich/patch/node"
    NODE_BENCHMARK_DIR = "/srv/scratch/dietrich/patch/node-benchmarks"
    CLIENT_HOST = '10.23.33.110'
    CLIENT_SSH_KEY = '/srv/scratch/dietrich/patch/ssh/id_rsa'

    inputs = {
        'delay': Integer(0),
        'clients': Integer(10),
        'mode': String("base"),
        'count': Integer(10),
    }
    outputs = {
        'server_log': File("server.log"),
        'client_log': File("client.log"),
    }

    def on_client(self, cmd, *args, **kwargs):
        return shell("ssh -i %s %s  " + cmd,
                     self.CLIENT_SSH_KEY,
                     self.CLIENT_HOST,
                     *args, **kwargs)


    def run(self):
        assert self.mode.value in ("base", "local", "global")

        logging.info("Use WRK in %s", self.NODE_BENCHMARK_DIR)
        logging.info("  on Client: %s", self.on_client("which wrk"))
        with Directory(self.NODE_BENCHMARK_DIR):
            shell("scp -i %s load.lua %s:/tmp/node.load.lua",
                  self.CLIENT_SSH_KEY,
                  self.CLIENT_HOST
            )

        # Sudoers
        # dietrich ALL=(ALL) NOPASSWD: /sbin/tc
        logging.info(f"Setup Network config with {self.delay.value}ms delay")
        self.on_client("sudo tc qdisc del dev eno1 root || true")
        if self.delay.value > 0:
            self.on_client(f"sudo tc qdisc add dev eno1 root netem delay {self.delay.value}ms")

        WF_CYCLIC_BOUND = self.count.value + 10

        server_env = dict(
            WF_CYCLIC="1",
            WF_CYCLIC_BOUND=str(WF_CYCLIC_BOUND),
            WF_LOGFILE=self.server_log.path,
            WF_GLOBAL="-1",
        )
        if self.mode.value == "local":
            server_env["WF_GLOBAL"] = "0"
        elif self.mode.value == "global":
            server_env["WF_GLOBAL"] = "1"

        server = subprocess.Popen(
            [self.NODE_DIR + "/node", "server.js"],
            env=server_env,
            cwd=self.NODE_BENCHMARK_DIR,
            stderr=sys.stderr,
            stdout=sys.stdout,
        )

        # Give the server some time to come up
        logging.info("Wait for server to come up")
        connected = False
        while not connected:
            try:
                fd = urlopen("http://localhost:3000/pdf/abc")
                fd.read()
                fd.close()
                connected = True
            except URLError:
                time.sleep(0.4)

        logging.info("Starting Client")
        client_out_fd = open(self.client_log.path, "w+")
        client = subprocess.Popen(["ssh", "-i", self.CLIENT_SSH_KEY, self.CLIENT_HOST,
                                   "wrk",
                                   "--latency",
                                   "-t", str(int(self.clients.value/10)), # Threads
                                   "-c", str(self.clients.value),
                                   "-d", "86400", # Long enough
                                   "-s", "/tmp/node.load.lua",
                                   "http://10.23.33.180:3000"],
                                  stdout=client_out_fd,
                                  stderr=sys.stderr)
        server_ret = server.wait()
        assert server_ret == 0, f"Server Failed {server_ret}"

        self.on_client("pkill -INT wrk") # Sorry mum
        x = client.wait()
        client_out_fd.close()

        logging.info("Undo network config")
        self.on_client("sudo tc qdisc del dev eno1 root || true")


    def symlink_name(self):
        return f"NodeBenchmark-mode={self.mode.value},delay={self.delay.value}"

if __name__ == "__main__":
    os.setpgrp() # create new process group, become its leader
    try:
        if sys.argv[1] == "all":
            modes = ["base", "local", "global"]
            for mode in modes:
                experiment = NodeBenchmark()
                experiment(sys.argv[2:] + [
                    "--count", "10000",
                    "--mode", mode,
                    "-s"
                ])
        else:
            experiment = NodeBenchmark()
            experiment(sys.argv[1:] + ["-s"])
    except Exception as e:
        print(traceback.format_exc())
        print("EXCEPTION: ", e, type(e))
        raise e
    finally:
        print("CLEANUP experiment")
        os.killpg(0, signal.SIGTERM) # kill all processes in my group
