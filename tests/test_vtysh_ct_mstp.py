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
    case_no = 0

    #Case:1 Test "Spanning-tree"(Default-enable) command from CLI to OVS-VSCTL
    device1.VtyshShell(enter=True)
    device1.ConfigVtyShell(enter=True)
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="no routing")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="int 2")
    retStructure = device1.DeviceInteract(command="no routing")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="vlan 1")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="vlan 2")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="vlan 3")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="spanning-tree")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree' in cmdOut, "Case:1 Test to enable MSTP failed"

    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="ovs-vsctl list bridge")
    cmdOut = retStructure.get('buffer')
    assert 'true' in cmdOut, "Case:1 Test to enable spanning-tree by default failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:2 Test "no Spanning-tree" command from CLI to OVS-VSCTL
    retStructure = device1.DeviceInteract(command="vtysh")
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="no spanning-tree")
    retCode = retStructure.get('returnCode')
    assert retCode == 0, "Case:2 - Failed to disable spanning-tree"

    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    #assert 'spanning-tree' not in cmdOut, "Case:2 Test to enable MSTP failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    retStructure = device1.DeviceInteract(command="exit")

    retStructure = device1.DeviceInteract(command="ovs-vsctl list bridge")
    retCode = retStructure.get('returnCode')
    assert retCode == 0, "Case:2 - Failed to run ovs-vsctl"
    cmdOut = retStructure.get('buffer')
    assert 'false' in cmdOut, "Case:2 Test to disable spanning-tree by default failed"

    #Case:5 Test enable spanning-tree from OVS-VSCTL
    retStructure = device1.DeviceInteract(command="ovs-vsctl set bridge \
            bridge_normal mstp_enable=true")

    retStructure = device1.DeviceInteract(command="ovs-vsctl list bridge")
    cmdOut = retStructure.get('buffer')
    assert 'true' in cmdOut, "Case:5 Test to enable spanning-tree failed"

    retStructure = device1.DeviceInteract(command="vtysh")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree' in cmdOut,"Case:5 Failed to enable MSTP"
    retStructure = device1.DeviceInteract(command="exit")
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:6 Test disable spanning-tree from OVS-VSCTL
    retStructure = device1.DeviceInteract(command="ovs-vsctl set bridge \
            bridge_normal mstp_enable=false")

    retStructure = device1.DeviceInteract(command="ovs-vsctl list bridge")
    cmdOut = retStructure.get('buffer')
    assert 'false' in cmdOut, "Case:6 Test to disable spanning-tree failed"

    retStructure = device1.DeviceInteract(command="vtysh")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    #assert 'spanning-tree' not in cmdOut, "Case:6 Failed to disable MSTP"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:7 Test spanning-tree config-revision via CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="spanning-tree \
                                                            config-revision 5")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config \
                                                            spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree config-revision 5' in cmdOut, "Case:7 Test to set \
                                                        config-revision failed"

    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="ovs-vsctl list bridge")
    cmdOut = retStructure.get('buffer')
    assert 'mstp_config_revision="5"' in cmdOut, "Case:7 Test to set \
                                                config-revision via CLI failed"

    print "Case : %d -- Pass" % case_no
    case_no += 1
    #Case:8 Test no spanning-tree config-revision from CLI
    retStructure = device1.DeviceInteract(command="vtysh")
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="no spanning-tree \
                                                            config-revision")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config \
                                                            spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree config-revision' not in cmdOut, "Case:8 Test to reset\
                                                        config-revision failed"

    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="ovs-vsctl list bridge")
    cmdOut = retStructure.get('buffer')
    assert 'mstp_config_revision="0"' in cmdOut, "Case:8 Test to reset \
                                                config-revision via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:9 Test spanning-tree config-revision via OVS_VSCTL
    retStructure = device1.DeviceInteract(command='ovs-vsctl set bridge\
            bridge_normal other_config={mstp_config_revision="44"}')

    retStructure = device1.DeviceInteract(command="ovs-vsctl list bridge")
    cmdOut = retStructure.get('buffer')
    assert 'mstp_config_revision="44"' in cmdOut, "Case:9 Test to set\
            config-revision via OVS_VSCTL failed"

    retStructure = device1.DeviceInteract(command="vtysh")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree config-revision 44' in cmdOut, "Case:9 Test to set\
                                         config-revision via OVS_VSCTL failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:10 Test spanning-tree config-name from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="spanning-tree config-name MST1")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree config-name MST1' in cmdOut, "Case:10 Test to set config name failed"

    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="ovs-vsctl list bridge")
    cmdOut = retStructure.get('buffer')
    assert 'mstp_config_name="MST1"' in cmdOut, "Case:10 Test to set config-name via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:11 Test no spanning-tree config-name from CLI
    retStructure = device1.DeviceInteract(command="vtysh")
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="no spanning-tree config-name")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree config-name' not in cmdOut, "Case:11 Test to reset config-name  failed"

    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="ovs-vsctl list bridge")
    cmdOut = retStructure.get('buffer')
    assert 'mstp_config_name' in cmdOut, "Case:11 Test to reset config-name via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:12 Test spanning-tree config-name from OVS-VSCTL
    retStructure = device1.DeviceInteract(command='ovs-vsctl set bridge\
            bridge_normal other_config={mstp_config_name="MST2"}')
    retStructure = device1.DeviceInteract(command="ovs-vsctl list bridge")
    cmdOut = retStructure.get('buffer')
    assert 'mstp_config_name="MST2"' in cmdOut, "Case:12 Test to set config-name via OVS-VSCTL failed"

    retStructure = device1.DeviceInteract(command="vtysh")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree config-name MST2' in cmdOut, "Case:12 Test to set config-name via OVS-VSCTL failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:13 Test spanning-tree bpdu-guard enable from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="spanning-tree bpdu-guard enable")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree bpdu-guard enable' in cmdOut, "Case:13 Test to set bpdu-guard via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:14 Test spanning-tree root-guard enable from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="spanning-tree root-guard enable")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree root-guard enable' in cmdOut, "Case:14 Test to set root-guard via CLI failed"

    print "Case : %d -- Pass" % case_no
    case_no += 1
    #Case:15 Test spanning-tree loop-guard enable from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="spanning-tree loop-guard enable")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree loop-guard enable' in cmdOut, "Case:15 Test to set loop-guard via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:16 Test spanning-tree bpdu-filter enable from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="spanning-tree bpdu-filter enable")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree bpdu-filter enable' in cmdOut, "Case:16 Test to set bpdu-filter via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:17 Test no spanning-tree bpdu-guard from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="no spanning-tree bpdu-guard")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree bpdu-guard' not in cmdOut, "Case:17 Test to reset bpdu-guard via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:18 Test no spanning-tree root-guard from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="no spanning-tree root-guard")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree root-guard' not in cmdOut, "Case:18 Test to reset root-guard via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:19 Test no spanning-tree loop-guard enable from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="no spanning-tree loop-guard")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree loop-guard' not in cmdOut, "Case:19 Test to reset loop-guard via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:20 Test no spanning-tree bpdu-filter enable from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="no spanning-tree bpdu-filter")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree bpdu-filter' not in cmdOut, "Case:20 Test to reset bpdu-filter via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:21 Test spanning-tree hello-time from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="spanning-tree hello-time 5")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree hello-time 5' in cmdOut, "Case:21 Test to set hello-time via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:22 Test spanning-tree forward-delay from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="spanning-tree forward-delay 5")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree forward-delay 5' in cmdOut, "Case:22 Test to set forward-delay via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:23 Test spanning-tree max-age from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="spanning-tree max-age 10")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree max-age 10' in cmdOut, "Case:23 Test to set max-age via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:24 Test spanning-tree max-hops from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="spanning-tree max-hops 10")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree max-hops 10' in cmdOut, "Case:24 Test to set max-hops via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:25 Test no spanning-tree hello-time from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="no spanning-tree hello-time")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree hello-time' not in cmdOut, "Case:25 Test to reset hello-time via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:26 Test spanning-tree forward-delay from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="no spanning-tree forward-delay")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree forward-delay' not in cmdOut, "Case:26 Test to reset forward-delay via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:27 Test spanning-tree max-age from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="no spanning-tree max-age")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree max-age' not in cmdOut, "Case:27 Test to reset max-age via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:28 Test spanning-tree max-hops from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="no spanning-tree max-hops")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree max-hops' not in cmdOut, "Case:28 Test to reset max-hops via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:29 Test spanning-tree priority from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="spanning-tree priority 12")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree priority 12' in cmdOut, "Case:29 Test to set priority via CLI failed"

    #Case:30 Test no spanning-tree priority from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="no spanning-tree priority")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree priority' not in cmdOut, "Case:30 Test to reset priority via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:31 Test spanning-tree instance 1 vlan 1 from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="spanning-tree instance 1 vlan 1")
    retStructure = device1.DeviceInteract(command="spanning-tree instance 1 vlan 2")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree instance 1 vlan 1' in cmdOut, "Case:31 Test to map vlan to instance failed"
    assert 'spanning-tree instance 1 vlan 2' in cmdOut, "Case:31 Test to map vlan to instance failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:32 Test no spanning-tree instance 1 vlan 2 from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="no spanning-tree instance 1 vlan 2")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree instance 1 vlan 1' in cmdOut, "Case:32 Test to unmap vlan from instance failed"
    assert 'spanning-tree instance 1 vlan 2' not in cmdOut, "Case:32 Test to unmap vlan from instance failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:33 Test no spanning-tree instance 1 from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="no spanning-tree instance 1")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree instance 1' not in cmdOut, "Case:33 Test to remove instance failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:34 Test spanning-tree instance 1 cost 200000 from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="spanning-tree")
    retStructure = device1.DeviceInteract(command="spanning-tree instance 1 vlan 1")
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="spanning-tree instance 1 cost 200000")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    #assert 'spanning-tree instance 1 cost 200000' in cmdOut, "Case:34 Test to set cost failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:35 Test no spanning-tree instance 1 cost 200000 from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="no spanning-tree instance 1 cost 200000")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree instance 1 cost' not in cmdOut, "Case:35 Test to reset cost failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:36 Test spanning-tree instance 1 port-priority 2 from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="spanning-tree instance 1 port-priority 2")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree instance 1 port-priority 2' in cmdOut, "Case:36 Test to set port-priority failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:37 Test no spanning-tree instance 1 port-priority 2 from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="int 1")
    retStructure = device1.DeviceInteract(command="no spanning-tree instance 1 port-priority")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree instance 1 port-priority' not in cmdOut, "Case:37 Test to reset port-priority failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:38 Test spanning-tree tx_hold_count from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="spanning-tree transmit-hold-count 5")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree transmit-hold-count 5' in cmdOut, "Case:38 Test to set transmit-hold-count via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:39 Test no spanning-tree tx_hold_count from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="no spanning-tree transmit-hold-count")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree transmit-hold-count' not in cmdOut, "Case:38 Test to reset transmit-hold-count via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:40 Test spanning-tree port-type admin-edge from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="spanning-tree")
    retStructure = device1.DeviceInteract(command="spanning-tree instance 2 vlan 3")
    retStructure = device1.DeviceInteract(command="int 2")
    retStructure = device1.DeviceInteract(command="spanning-tree port-type admin-edge")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    #assert 'spanning-tree port-type admin-edge' in cmdOut, "Case:40 Test to set port-type via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

    #Case:41 Test no spanning-tree port-type  from CLI
    retStructure = device1.DeviceInteract(command="conf t")
    retStructure = device1.DeviceInteract(command="int 2")
    retStructure = device1.DeviceInteract(command="no spanning-tree port-type")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="exit")
    retStructure = device1.DeviceInteract(command="show running-config spanning-tree")
    cmdOut = retStructure.get('buffer')
    assert 'spanning-tree port-type admin-edge' not in cmdOut, "Case:41 Test to reset port-type via CLI failed"
    print "Case : %d -- Pass" % case_no
    case_no += 1

class Test_mstp_cli:
    def setup_class (cls):
        # Test object will parse command line and formulate the env
        Test_mstp_cli.testObj = testEnviron(topoDict=topoDict)
        # Get topology object
        Test_mstp_cli.topoObj = Test_mstp_cli.testObj.topoObjGet()

    def teardown_class (cls):
        Test_mstp_cli.topoObj.terminate_nodes()

    def test_mstp_cli(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        retValue = MSTPCliTest(device1=dut01Obj)
