import time
import os
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
from collections import defaultdict
import subprocess
import logging
import traceback
import sys

class WaitFreeExperiment(Experiment):
    CLIENT_HOST = '10.23.33.110'
    CLIENT_SSH_KEY = '/srv/scratch/osdi/ssh/id_rsa'

    inputs = {
        'delay': Integer(0),
        'mode': String("global"),
        'count': Integer(10),
        'patches': Directory("/dev/null"),
    }
    
    outputs = {
        'server_log': File("server.log"),
        'client_log': File("client.log"),
    }


    def client_shell(self, cmd, *args, **kwargs):
        return shell("ssh -i %s %s  " + cmd,
                     self.CLIENT_SSH_KEY,
                     self.CLIENT_HOST,
                     *args, **kwargs)

    def client_copy(self, src, dst):
        logging.info("Copy %s to %s:%s", src, self.CLIENT_HOST, dst)
        return shell("scp -i %s %s %s:%s",
                     self.CLIENT_SSH_KEY,
                     src,
                     self.CLIENT_HOST,
                     dst,
        )

    def with_patches(self):
        return self.patches.path != "/dev/null"


    def setup_experiment(self):
        # Sudoers on client Machine
        # dietrich ALL=(ALL) NOPASSWD: /sbin/tc
        # 
        logging.info(f"Setup Network config with {self.delay.value}ms delay")
        self.client_shell("sudo tc qdisc del dev eno1 root || true")
        if self.delay.value > 0:
            self.client_shell(f"sudo tc qdisc add dev eno1 root netem delay {self.delay.value}ms")

        if self.with_patches():
            return self.count.value
        else:
            return 1

    def server_env(self, run, WF_CYCLIC="1", WF_CYCLIC_BOOT="3",WF_CYCLIC_RANDOM=None):
        logfile = self.server_log.path
        if run != 0:
            logfile += f".{run}"

        server_env = dict(
            WF_CYCLIC_BOOT=WF_CYCLIC_BOOT,
            WF_CYCLIC=WF_CYCLIC,
            WF_CYCLIC_BOUND=str(self.count.value),
            WF_LOGFILE=logfile,
            WF_GLOBAL="-1",
        )
        if WF_CYCLIC_RANDOM:
            server_env['WF_CYCLIC_RANDOM'] = WF_CYCLIC_RANDOM

        if self.mode.value == "local":
            server_env["WF_GLOBAL"] = "0"
        elif self.mode.value == "global":
            server_env["WF_GLOBAL"] = "1"
        else:
            raise RuntimeError()

        if self.with_patches():
            patch_files = sorted(self.patches.value)
            patch_groups = []
            patches = defaultdict(list)
            for p in patch_files:
                pg = p.split("-")[0]
                patch_groups.append(pg)
                patches[pg].append(
                    os.path.join(
                        self.patches.path,
                        p
                    )
                )

            patch_queue = []
            for pg in patch_groups:
                patch_queue.append(",".join(patches[pg]))

            server_env["WF_PATCH_QUEUE"] = ";".join(patch_queue)
            server_env["WF_CYCLIC_BOUND"] = str(len(patch_queue))
                
        return server_env

    def teardown_experiment(self):
        logging.info("Undo network config")
        self.client_shell("sudo tc qdisc del dev eno1 root || true")

    def wait_for_url(self, url):
        # Give the server some time to come up
        logging.info("Wait for server to come up")
        connected = False
        while not connected:
            try:
                fd = urlopen(url)
                fd.read()
                fd.close()
                connected = True
            except URLError:
                time.sleep(0.4)

    def client_popen(self, args, run=0, **kwargs):
        logging.info("Start Client: %s", args)
        logfile = self.client_log.path
        if run != 0:
            logfile += f".{run}"

        client_out_fd = open(logfile, "w+")

        client = subprocess.Popen(
            ["ssh", "-i", self.CLIENT_SSH_KEY, self.CLIENT_HOST] + list(args),
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            **kwargs
        )

        gzip = subprocess.Popen(
            "gzip",
            stdin=client.stdout,
            stdout=client_out_fd,
            stderr=sys.stderr
        )

        class Waiter:
            def __init__(self, client, gzip):
                self.client = client
                self.gzip = gzip

            def wait(self):
                logging.info("Wait for clients")
                a, b = self.client.wait(), self.gzip.wait()
                logging.info("Client terminated with %d %d", a, b)
                return a == 0 and b == 0

        return Waiter(client, gzip)
