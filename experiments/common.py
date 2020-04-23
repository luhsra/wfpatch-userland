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
import sys

class WaitFreeExperiment(Experiment):
    CLIENT_HOST = '10.23.33.110'
    CLIENT_SSH_KEY = '/srv/scratch/dietrich/patch/ssh/id_rsa'

    inputs = {
        'delay': Integer(0),
        'mode': String("base"),
        'count': Integer(10),
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


    def setup_experiment(self):
        # Sudoers on client Machine
        # dietrich ALL=(ALL) NOPASSWD: /sbin/tc
        # 
        logging.info(f"Setup Network config with {self.delay.value}ms delay")
        self.client_shell("sudo tc qdisc del dev eno1 root || true")
        if self.delay.value > 0:
            self.client_shell(f"sudo tc qdisc add dev eno1 root netem delay {self.delay.value}ms")

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

    def client_popen(self, args, **kwargs):
        logging.info("Start Client: %s", args)
        client_out_fd = open(self.client_log.path, "w+")

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
