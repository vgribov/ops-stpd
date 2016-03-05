#!/usr/bin/python

# (c) Copyright 2015 Hewlett Packard Enterprise Development LP
#
# GNU Zebra is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.
#
# GNU Zebra is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Zebra; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

import time
import pytest
import re
from  opstestfw import *
from opstestfw.switch.CLI import *
from opstestfw.switch import *

# Topology definition
topoDict = {"topoExecution": 1000,
            "topoTarget": "dut01",
            "topoDevices": "dut01",
            "topoFilters": "dut01:system-category:switch"}

def MSTPCliTest(**kwargs):
    device1 = kwargs.get('device1',None)

    #Case:1 Adding a dummy test case for zuul pass
    device1.VtyshShell(enter=True)
    device1.ConfigVtyShell(enter=True)

class Test_mstp_cli:
    def setup_class (cls):
        Test_mstp_cli.testObj = testEnviron(topoDict=topoDict)
        Test_mstp_cli.topoObj = Test_mstp_cli.testObj.topoObjGet()

    def teardown_class (cls):
        Test_mstp_cli.topoObj.terminate_nodes()

    def test_mstp_cli(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        retValue = MSTPCliTest(device1=dut01Obj)
