#!/usr/bin/python
# (C) Copyright 2016 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import sys
import time
import pytest
import subprocess
import json
from opsvsi.docker import *
from opsvsi.opsvsitest import *


class mstpdTests(OpsVsiTest):

    def setupNet(self):
        # if you override this function, make sure to
        # either pass getNodeOpts() into hopts/sopts of the topology that
        # you build or into addHost/addSwitch calls
        self.net = Mininet(topo=SingleSwitchTopo(
            k=1,
            hopts=self.getHostOpts(),
            sopts=self.getSwitchOpts()),
            switch=VsiOpenSwitch,
            host=Host,
            link=OpsVsiLink, controller=None,
            build=True)

    def mstpd_add_vlan_to_cist(self):
        info('\n########## Test Adding vlan to CIST ##########')
        s1 = self.net.switches[0]

        s1.cmdCLI("configure terminal")
        s1.cmdCLI("vlan 1")
        s1.cmdCLI("vlan 2")
        s1.cmdCLI("exit")
        s1.cmdCLI("spanning-tree")
        s1.cmdCLI("end")
        output = s1.cmdCLI("show spanning-tree mst")
        output += s1.cmd("echo")
        debug(output)

        success = 0
        if 'Vlans mapped:  2,1' in output or 'Vlans mapped:  1,2' in output:
            success = 1
            info('\n### Passed: mstpd_add_vlan_to_cist ###')
        else:
            assert (success == 1),\
                "Failed: mstpd_add_vlan_to_cist"

    def mstpd_remove_vlan_from_cist(self):
        info('\n########## Test Removing vlan from CIST ##########')
        s1 = self.net.switches[0]

        s1.cmdCLI("configure terminal")
        s1.cmdCLI("no vlan 2")
        s1.cmdCLI("exit")
        s1.cmdCLI("end")
        output = s1.cmdCLI("show spanning-tree mst")
        output += s1.cmd("echo")
        debug(output)

        assert ('Vlans mapped:  1' in output),\
            "Failed: mstpd_remove_vlan_from_cist"

    def mstpd_add_ports_to_cist(self):
        info('\n########## Test Adding ports to CIST ##########')
        s1 = self.net.switches[0]

        s1.cmdCLI("configure terminal")
        s1.cmdCLI("no spanning-tree")
        s1.cmdCLI("interface 1")
        s1.cmdCLI("no routing")
        s1.cmdCLI("exit")
        s1.cmdCLI("spanning-tree")
        s1.cmdCLI("end")
        output = s1.cmdCLI("show spanning-tree")
        output += s1.cmd("echo")
        debug(output)

        assert ('1            Disabled       Blocking' in output),\
                "Failed: mstpd_add_ports_to_cist"

    def mstpd_remove_ports_from_cist(self):
        info('\n########## Test Removing ports from CIST ##########')
        s1 = self.net.switches[0]

        s1.cmdCLI("configure terminal")
        s1.cmdCLI("no spanning-tree")
        s1.cmdCLI("interface 1")
        s1.cmdCLI("routing")
        s1.cmdCLI("exit")
        s1.cmdCLI("spanning-tree")
        s1.cmdCLI("end")
        output = s1.cmdCLI("show spanning-tree")
        output += s1.cmd("echo")
        debug(output)

        assert ('1            Disabled       Blocking' not in output),\
            '### Failed: mstpd_remove_ports_from_cist ###'


@pytest.mark.timeout(1000)
class Test_mstpd:
    def setup(self):
        pass

    def teardown(self):
        pass

    def setup_class(cls):
        Test_mstpd.test = mstpdTests()
        pass

    def teardown_class(cls):
        # Stop the Docker containers, and
        # mininet topology
        Test_mstpd.test.net.stop()

    def setup_method(self, method):
        pass

    def teardown_method(self, method):
        pass

    def __del__(self):
        del self.test

    # mstpd add vlan to cist.
    def test_mstpd_add_vlan_to_cist_commands(self):
        self.test.mstpd_add_vlan_to_cist()

    # mstpd remove vlan from cist.
    def test_mstpd_remove_vlan_from_cist_commands(self):
        self.test.mstpd_remove_vlan_from_cist()

    # mstpd add ports to cist.
    def test_mstpd_add_ports_to_cist_commands(self):
        self.test.mstpd_add_ports_to_cist()

    # mstpd remove ports from cist.
    def test_mstpd_remove_ports_from_cist_commands(self):
        self.test.mstpd_remove_ports_from_cist()
