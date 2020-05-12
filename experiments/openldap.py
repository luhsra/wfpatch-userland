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

class Tee(object):
    def __init__(self, a, mode):
        self.file = open(name, mode)
        self.stdout = sys.stdout
        sys.stdout = self
    def __del__(self):
        sys.stdout = self.stdout
        self.file.close()
    def write(self, data):
        self.file.write(data)
        self.stdout.write(data)
    def flush(self):
        self.file.flush()

class OpenLDAPBenchmark(Experiment):
    inputs = {
        'openldap': Directory('/srv/scratch/osdi/openldap/'),
        'client-host': String('10.23.33.110'),
        'ssh-key': File('/srv/scratch/osdi/openldap/'),
        'delay': Integer(5),
        'clients': Integer(200),
        'records': Integer(50),
        'global_barrier': Bool(True),
        'count': Integer(10),
    }
    outputs = {
        'server_log': File("server.log"),
        'client_log': File("client.log.gz"),
    }

    def on_client(self, cmd, *args, **kwargs):
        return shell("ssh -i %s %s env " + cmd,
                     self.ssh_key.path,
                     self.client_host.value,
                     *args, **kwargs)

    def run(self):
        logging.info("Build Benchmark in %s", self.openldap.path)

        shell("gcc wf-benchmark/benchmark.c -o benchmark -lpthread -lldap", cwd=self.openldap.path)
        shell("scp -i %s %s/benchmark %s:/tmp/openldap-benchmark",
              self.ssh_key.path,
              self.openldap.path,
              self.client_host.value
        )

        # Sudoers
        # dietrich ALL=(ALL) NOPASSWD: /sbin/tc
        logging.info(f"Setup Network config with {self.delay.value}ms delay")
        self.on_client("sudo tc qdisc del dev eno1 root || true")
        if self.delay.value > 0:
            self.on_client(f"sudo tc qdisc add dev eno1 root netem delay {self.delay.value}ms")

        server_env = dict(
            WF_CYCLIC="1",
            WF_GLOBAL={True: "1", False: "0"}[self.global_barrier.value],
            WF_CYCLIC_BOUND=str(self.count.value + 10),
            WF_LOGFILE=self.server_log.path,
        )

        server = subprocess.Popen(["/usr/sbin/slapd",
                                   "-h", "ldap://0.0.0.0:1500",
                                   "-d", "0",
                                   "-f", os.path.join(self.openldap.path, "wf-benchmark/slapd.conf") ],
                                  env=server_env)
        client_out_fd = open(self.client_log.path, "w+")

        time.sleep(3)

        client = subprocess.Popen(["ssh", "-i", self.ssh_key.path, self.client_host.value,
                                   "/tmp/openldap-benchmark",
                                   str(self.clients.value),
                                   str(self.records.value)],
                                  stdout=subprocess.PIPE,
                                  stderr=sys.stderr)

        gzip = subprocess.Popen("gzip",
                                stdin=client.stdout,
                                stdout=client_out_fd,
                                stderr=sys.stderr)
        
        server.communicate()
        #client.communicate()
        server_ret = server.wait()
        client.wait()
        gzip.wait()
        assert server_ret == 0, ("Server Failed", server_ret)

        logging.info("Undo network config")
        self.on_client("sudo tc qdisc del dev eno1 root || true")


    def symlink_name(self):
        g = {True: "1", False: "0"}[self.global_barrier.value]
        return f"OpenLDAPBenchmark-global={g},delay={self.delay.value}"

if __name__ == "__main__":
    if sys.argv[1] == "all":
        for delay in [5, 10, 25, 50]:
            for g in ["true", "false"]:
                experiment = OpenLDAPBenchmark()
                experiment(sys.argv[2:] + [
                    "--count", "10000",
                    "--delay", str(delay),
                    "--global_barrier", g,
                    "-s"
                ])
                
    else:
        experiment = OpenLDAPBenchmark()
        experiment(sys.argv[1:] + ["-s"])
