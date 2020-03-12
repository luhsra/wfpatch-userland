#!/usr/bin/python3
import os, sys
tmp_path = "%s/git/versuchung/src"% os.environ["HOME"]
if os.path.exists(tmp_path):
    sys.path.append(tmp_path)


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
        'openldap': Directory('/srv/scratch/dietrich/patch/openldap/'),
        'client-host': String('lab-pc10'),
        'ssh-key': File('/srv/scratch/dietrich/patch/ssh/id_rsa'),
        'delay': Integer(5),
        'clients': Integer(200),
        'records': Integer(50),
        'global_barrier': Bool(True),
        'count': Integer(10),
    }
    outputs = {
        'server_log': File("server.log"),
        'client_log': File("client.log"),
    }

    def on_client(self, cmd, *args, **kwargs):
        return shell("ssh -i %s %s env " + cmd,
                     self.ssh_key.path,
                     self.client_host.value,
                     *args, **kwargs)

    def run(self):
        logging.info("Build OpenLDAP in %s", self.openldap.path)
        shell("make", cwd=self.openldap.path)
        logging.info("Build Benchmark in %s", self.openldap.path)
        slapd = str(Path(self.openldap.path) / "servers" / "slapd" / "slapd")

        shell("gcc benchmark.c -o benchmark -lpthread -lldap", cwd=self.openldap.path)
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

        server = subprocess.Popen([slapd, "-h", "ldap://0.0.0.0:1500"],
                       env=dict(
                           WF_CYCLIC="1",
                           WF_GLOBAL={True: "1", False: "0"}[self.global_barrier.value],
                           WF_CYCLIC_BOUND=str(self.count.value + 10),
                           WF_LOGFILE=self.server_log.path,
                       ))
        client_out_fd = open(self.client_log.path, "w+")
        client = subprocess.Popen(["ssh", "-i", self.ssh_key.path, self.client_host.value,
                        "/tmp/openldap-benchmark",
                        str(self.clients.value),
                        str(self.records.value)],
                       stdout=client_out_fd,
                       stderr=subprocess.PIPE)
        server.communicate()
        client.communicate()
        server_ret = server.wait()
        client.wait()

        print(server_ret)
        assert server_ret == 0, "Server Failed"

        logging.info("Undo network config")
        self.on_client("sudo tc qdisc del dev eno1 root || true")


    def symlink_name(self):
        g = {True: "1", False: "0"}[self.global_barrier.value]
        return f"OpenLDAPBenchmark-global={g},delay={self.delay.value}"

if __name__ == "__main__":
    experiment = OpenLDAPBenchmark()
    experiment(sys.argv[1:] + ["-s"])
