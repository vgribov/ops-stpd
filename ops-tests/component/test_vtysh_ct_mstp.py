# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
OpenSwitch test for MSTP CLI commands.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

import re
import time
# from time import sleep


TOPOLOGY = """
#
# +-------+     +-------+
# |       |     |       |
# |       +-----+       |
# | Sw1   +-----+   Sw2 |
# |       |     |       |
# +-------+     +-------+
#
# Nodes
[type=openswitch name="OpenSwitch 1"] sw1
[type=openswitch name="OpenSwitch 2"] sw2

# Links
sw1:1 -- sw2:1
sw1:2 -- sw2:2
"""


def turn_on_interface(sw, interface):
    with sw.libs.vtysh.ConfigInterface(interface) as ctx:
        ctx.no_routing()
        ctx.no_shutdown()


def validate_turn_on_interfaces(sw, interfaces):
    for intf in interfaces:
        output = sw.libs.vtysh.show_interface(intf)
        assert output['interface_state'] == 'up',\
            "Interface state for " + intf + " is down"


def config_mstp_region(sw, region_name, version):
    with sw.libs.vtysh.Configure() as ctx:
        ctx.spanning_tree_config_name(region_name)
        ctx.spanning_tree_config_revision(version)


def reset_mstp_region(sw):
    with sw.libs.vtysh.Configure() as ctx:
        ctx.no_spanning_tree_config_name()
        ctx.no_spanning_tree_config_revision()


def config_mstp_bpdu(sw, intf, value):
    with sw.libs.vtysh.ConfigInterface(intf) as ctx:
        ctx.spanning_tree_bpdu_guard(value)
        ctx.spanning_tree_loop_guard(value)
        ctx.spanning_tree_root_guard(value)
        ctx.spanning_tree_bpdu_filter(value)


def reset_mstp_bpdu(sw, intf):
    with sw.libs.vtysh.ConfigInterface(intf) as ctx:
        ctx.no_spanning_tree_bpdu_guard()
        ctx.no_spanning_tree_loop_guard()
        ctx.no_spanning_tree_root_guard()
        ctx.no_spanning_tree_bpdu_filter()


def config_mstp_timers(sw, hello_time, fwd_delay, max_age, max_hops, tx_hold):
    with sw.libs.vtysh.Configure() as ctx:
        ctx.spanning_tree_hello_time(hello_time)
        ctx.spanning_tree_forward_delay(fwd_delay)
        ctx.spanning_tree_max_age(max_age)
        ctx.spanning_tree_max_hops(max_hops)
        ctx.spanning_tree_transmit_hold_count(tx_hold)


def reset_mstp_timers(sw):
    with sw.libs.vtysh.Configure() as ctx:
        ctx.no_spanning_tree_hello_time()
        ctx.no_spanning_tree_forward_delay()
        ctx.no_spanning_tree_max_age()
        ctx.no_spanning_tree_max_hops()
        ctx.no_spanning_tree_transmit_hold_count()


def config_mstp_intf(sw, intf, cost, priority, port_type):
    with sw.libs.vtysh.ConfigInterface(intf) as ctx:
        ctx.spanning_tree_port_type(port_type)
    sw('conf t', shell='vtysh')
    sw('interface '+intf, shell='vtysh')
    sw('spanning-tree cost '+cost, shell='vtysh')
    sw('spanning-tree port-priority '+priority, shell='vtysh')
    sw('end', shell='vtysh')


def reset_mstp_intf(sw, intf):
    with sw.libs.vtysh.ConfigInterface(intf) as ctx:
        ctx.no_spanning_tree_port_type()
    sw('conf t', shell='vtysh')
    sw('interface '+intf, shell='vtysh')
    sw('no spanning-tree cost', shell='vtysh')
    sw('no spanning-tree port-priority', shell='vtysh')
    sw('end', shell='vtysh')


def check_global_mstp_show_cmds(sw):
    out = sw('show spanning-tree detail', shell='vtysh')
    found = 0
    lines = out.split('\n')
    for line in lines:
        if 'Spanning tree status: Enabled' in line:
            found += 1
        if 'Root ID' in line:
            found += 1
        if 'Bridge ID' in line:
            found += 1
    assert(found is 3), \
        "show spanning-tree detail failed"
    out = sw('show spanning-tree mst detail', shell='vtysh')
    found = 0
    lines = out.split('\n')
    for line in lines:
        if '#### MST0' in line:
            found += 1
        if 'Operational    Hello time' in line:
            found += 1
        if 'Configured     Hello time' in line:
            found += 1
    assert(found is 3), \
        "show spanning-tree mst detail failed"
    out = sw('show spanning-tree mst-config', shell='vtysh')
    found = 0
    lines = out.split('\n')
    for line in lines:
        if 'MST config ID' in line:
            found += 1
        if 'MST config revision' in line:
            found += 1
        if 'MST config digest' in line:
            found += 1
    assert(found is 3), \
        "show spanning-tree mst-config failed"


def check_inst_show_cmds(sw, inst, if_name):
    sw('show spanning-tree mst '+inst+' detail', shell='vtysh')
    sw('show spanning-tree mst '+inst+' interface '+if_name+' detail',
       shell='vtysh')
    print("")


def validate_mstp_show_run(sw, cmd, required):
    out = sw('show running-config spanning-tree', shell='vtysh')
    found = False
    lines = out.split('\n')
    for line in lines:
        if cmd in line:
            found = True
            break
    if(required):
        assert(found is True), \
            cmd + " cmd not found in show running-config spanning-tree"
    else:
        assert(found is False), \
            cmd + " cmd found in show running-config spanning-tree"
    out = sw('show running-config', shell='vtysh')
    found = False
    lines = out.split('\n')
    for line in lines:
        if cmd in line:
            found = True
            break
    if(required):
        assert(found is True), \
            cmd + " cmd not found in show running-config"
    else:
        assert(found is False), \
            cmd + " cmd found in show running-config"


def wait_until_interface_up(switch, portlbl, timeout=30, polling_frequency=1):
    """
    Wait until the interface, as mapped by the given portlbl, is marked as up.

    :param switch: The switch node.
    :param str portlbl: Port label that is mapped to the interfaces.
    :param int timeout: Number of seconds to wait.
    :param int polling_frequency: Frequency of the polling.
    :return: None if interface is brought-up. If not, an assertion is raised.
    """
    for i in range(timeout):
        status = switch.libs.vtysh.show_interface(portlbl)
        if status['interface_state'] == 'up':
            break
        time.sleep(polling_frequency)
    else:
        assert False, (
            'Interface {}:{} never brought-up after '
            'waiting for {} seconds'.format(
                switch.identifier, portlbl, timeout
            )
        )


def ops_get_system_mac_address(ops):
    result = ops.send_command('ovs-vsctl list system | grep system_mac',
                              shell='bash')
    result = re.search('\s*system_mac\s*:\s*"(?P<sys_mac>.*)"', result)
    result = result.groupdict()
    ops_mac = result['sys_mac']
    return ops_mac


def test_vtysh_ct_mstp(topology):
    """
    Test that a MSTP commands are working fine.

    Build a topology of two switch and connection made as shown in topology.
    Setup a spanning tree configuration on all the switches so that all the
    switch are in same region.
    Check the commands are reflected in show running-config and corresponding
    show commands of MSTP.
    """

    sw1 = topology.get('sw1')
    sw2 = topology.get('sw2')

    assert sw1 is not None
    assert sw2 is not None

    p11 = sw1.ports['1']
    p12 = sw1.ports['2']
    p21 = sw2.ports['1']
    p22 = sw2.ports['2']

    print("Turning on all interfaces used in this test")
    ports_sw1 = [p11, p12]
    for port in ports_sw1:
        turn_on_interface(sw1, port)

    ports_sw2 = [p21, p22]
    for port in ports_sw2:
        turn_on_interface(sw2, port)

    print("Waiting some time for the interfaces to be up")
    for sw in [sw1, sw2]:
        for port in ['1', '2']:
            wait_until_interface_up(sw, port)

    """
    Case 1: Check config-rev and config-name reflects in show running-config.
    """
    print("Verify all interface are up")
    validate_turn_on_interfaces(sw1, ports_sw1)
    validate_turn_on_interfaces(sw2, ports_sw2)

    print("Setting config name & revision number in switchs")
    for sw in [sw1, sw2]:
        config_mstp_region(sw, "reg_1", 1)

    print("Enabling spanning-tree in the switches")
    for sw in [sw1, sw2]:
        with sw.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree()

    print("Checking commands in show running-config")
    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree config-name reg_1', True)
        validate_mstp_show_run(sw, 'spanning-tree config-revision 1', True)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)

    """
    Case 2: Check config-rev and config-name default value by no command.
    """
    print("Resetting config name & revision number to default")
    for sw in [sw1, sw2]:
        reset_mstp_region(sw)

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree config-name', False)
        validate_mstp_show_run(sw, 'spanning-tree config-revision', False)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)

    """
    Case 3: Check Setting to enable BPDU guard and filter commands.
    """
    print("Setting bpdu guard and filter via CLI")
    for sw in [sw1, sw2]:
        config_mstp_bpdu(sw, "1", "enable")

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree bpdu-guard enable', True)
        validate_mstp_show_run(sw, 'spanning-tree root-guard enable', True)
        validate_mstp_show_run(sw, 'spanning-tree bpdu-filter enable', True)
        validate_mstp_show_run(sw, 'spanning-tree loop-guard enable', True)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)

    """
    Case 4: Check resetting BPDU guard and filter commands by no commands.
    """
    print("Resetting bpdu guard and filter via no commands in CLI")
    for sw in [sw1, sw2]:
        reset_mstp_bpdu(sw, "1")

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree bpdu-guard', False)
        validate_mstp_show_run(sw, 'spanning-tree root-guard', False)
        validate_mstp_show_run(sw, 'spanning-tree bpdu-filter', False)
        validate_mstp_show_run(sw, 'spanning-tree loop-guard', False)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)

    """
    Case 5: Check setting of helloTime, ForwardDelay, MaxAge, MaxHops via CLI.
    """
    print("Resetting bpdu guard and filter via no commands in CLI")
    for sw in [sw1, sw2]:
        config_mstp_timers(sw, "5", "5", "10", "10", "10")

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree hello-time 5', True)
        validate_mstp_show_run(sw, 'spanning-tree forward-delay 5', True)
        validate_mstp_show_run(sw, 'spanning-tree max-age 10', True)
        validate_mstp_show_run(sw, 'spanning-tree max-hops 10', True)
        validate_mstp_show_run(sw,
                               'spanning-tree transmit-hold-count 10', True)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)

    """
    Case 6: Check resetting of helloTime,ForwardDelay, MaxAge, MaxHops via CLI.
    """
    print("Resetting timers via no commands in CLI")
    for sw in [sw1, sw2]:
        reset_mstp_timers(sw)

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree hello-time', False)
        validate_mstp_show_run(sw, 'spanning-tree forward-delay', False)
        validate_mstp_show_run(sw, 'spanning-tree max-age', False)
        validate_mstp_show_run(sw, 'spanning-tree max-hops', False)
        validate_mstp_show_run(sw, 'spanning-tree transmit-hold-count', False)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)

    """
    Case 7: Check setting of instance priorities via CLI.
    """
    print("Setting cist priorities via CLI")
    for sw in [sw1, sw2]:
        with sw.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree_priority('12')

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree priority 12', True)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)

    """
    Case 8: Check resetting of instance priorities via CLI.
    """
    print("Resetting cist priorities via CLI")
    for sw in [sw1, sw2]:
        with sw.libs.vtysh.Configure() as ctx:
            ctx.no_spanning_tree_priority('12')

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree priority', False)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)

    """
    Case 9: Check creating new MSTI with VLANs as 10,20.
    """
    print("Creating new MSTI via CLI")
    for sw in [sw1, sw2]:
        for vid in ['10', '20']:
            with sw.libs.vtysh.ConfigVlan(vid) as ctx:
                ctx.no_shutdown()
            with sw.libs.vtysh.Configure() as ctx:
                ctx.spanning_tree_instance_vlan('1', vid)

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree instance 1 vlan 10', True)
        validate_mstp_show_run(sw, 'spanning-tree instance 1 vlan 20', True)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)
        for port in ['1', '2']:
            check_inst_show_cmds(sw, "1", port)

    """
    Case 10: Check deleting VLAN from MSTI.
    """
    print("Deleting VLAN from MSTI via CLI")
    for sw in [sw1, sw2]:
        with sw.libs.vtysh.Configure() as ctx:
            ctx.no_spanning_tree_instance_vlan('1', '10')

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree instance 1 vlan 10', False)
        validate_mstp_show_run(sw, 'spanning-tree instance 1 vlan 20', True)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)
        for port in ['1', '2']:
            check_inst_show_cmds(sw, "1", port)

    """
    Case 11: Check setting of instance priorities via CLI.
    """
    print("Setting MSTI priorities via CLI")
    for sw in [sw1, sw2]:
        with sw.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree_instance_priority('1', '12')

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree instance 1 priority 12',
                               True)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)
        for port in ['1', '2']:
            check_inst_show_cmds(sw, "1", port)

    """
    Case 12: Check resetting of instance priorities via CLI.
    """
    print("Resetting MSTI priorities via CLI")
    for sw in [sw1, sw2]:
        with sw.libs.vtysh.Configure() as ctx:
            ctx.no_spanning_tree_instance_priority('1')

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree instance 1 priority', False)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)
        for port in ['1', '2']:
            check_inst_show_cmds(sw, "1", port)

    """
    Case 13: Check setting of interface cost, priority, type via CLI for CIST.
    """
    print("Setting interface cost, priority, type via CLI for CIST")
    for sw in [sw1, sw2]:
        for port in ['1', '2']:
            config_mstp_intf(sw, port, "2000", "12", "admin-edge")

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree cost 2000', True)
        validate_mstp_show_run(sw, 'spanning-tree port-priority 12', True)
        validate_mstp_show_run(sw, 'spanning-tree port-type admin-edge', True)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)
        for port in ['1', '2']:
            check_inst_show_cmds(sw, "1", port)

    """
    Case 14: Check resetting interface cost, priority, type via CLI for CIST.
    """
    print("Resetting interface cost, priority, type via CLI for CIST")
    for sw in [sw1, sw2]:
        for port in ['1', '2']:
            reset_mstp_intf(sw, port)

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree cost 2000', False)
        validate_mstp_show_run(sw, 'spanning-tree port-priority 12', False)
        validate_mstp_show_run(sw, 'spanning-tree port-type admin-edge', False)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)
        for port in ['1', '2']:
            check_inst_show_cmds(sw, "1", port)

    """
    Case 15: Check setting of interface cost, priority, type via CLI for MSTI.
    """
    print("Setting interface cost, priority, type via CLI for MSTI")
    for sw in [sw1, sw2]:
        for port in ['1', '2']:
            with sw.libs.vtysh.ConfigInterface(port) as ctx:
                ctx.spanning_tree_instance_cost('1', '2000')
                ctx.spanning_tree_instance_port_priority('1', '12')

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree instance 1 cost 2000', True)
        validate_mstp_show_run(sw, 'spanning-tree instance 1 port-priority 12',
                               True)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)
        for port in ['1', '2']:
            check_inst_show_cmds(sw, "1", port)

    """
    Case 16: Check resetting interface cost, priority, type via CLI for MSTI.
    """
    print("Resetting interface cost, priority, type via CLI for MSTI")
    for sw in [sw1, sw2]:
        for port in ['1', '2']:
            with sw.libs.vtysh.ConfigInterface(port) as ctx:
                ctx.no_spanning_tree_instance_cost('1')
                ctx.no_spanning_tree_instance_port_priority('1')

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree instance 1 cost 2000', False)
        validate_mstp_show_run(sw, 'spanning-tree instance 1 port-priority 12',
                               False)

    print("Checking global and interface related MSTP show commands")
    for sw in [sw1, sw2]:
        check_global_mstp_show_cmds(sw)
        for port in ['1', '2']:
            check_inst_show_cmds(sw, "1", port)

    """
    Case 17: Check Adding VLAN to MSTI.
    """
    print("Check Adding VLAN to MSTI")
    for sw in [sw1, sw2]:
        with sw.libs.vtysh.Configure() as ctx:
            ctx.no_spanning_tree_instance('1')
            ctx.spanning_tree_instance_vlan('1', '10')
            ctx.spanning_tree_instance_vlan('1', '20')

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree instance 1 vlan 10', True)
        validate_mstp_show_run(sw, 'spanning-tree instance 1 vlan 20', True)

    out = sw.libs.vtysh.show_spanning_tree_mst()
    assert(out['MST0']['vlan_mapped'] == '1-9,11-19,21-4095' and
           out['MST1']['vlan_mapped'] == '10,20'), "VLAN MAP Failed"

    """
    Case 18: Check Removing VLAN from MSTI.
    """
    print("Check Removing VLAN from MSTI")
    for sw in [sw1, sw2]:
        with sw.libs.vtysh.Configure() as ctx:
            ctx.no_spanning_tree_instance_vlan('1', '10')

    for sw in [sw1, sw2]:
        validate_mstp_show_run(sw, 'spanning-tree instance 1 vlan 20', True)
        validate_mstp_show_run(sw, 'spanning-tree instance 1 vlan 10', False)

    out = sw.libs.vtysh.show_spanning_tree_mst()
    assert(out['MST0']['vlan_mapped'] == '1-19,21-4095' and
           out['MST1']['vlan_mapped'] == '20'), "VLAN MAP Failed"

    """
    Case 19: Check disabling spanning-tree should not allow any show commands.
    """
    print("Check disabling spanning-tree should not allow any show commands")
    for sw in [sw1, sw2]:
        with sw.libs.vtysh.Configure() as ctx:
            ctx.no_spanning_tree()

    for sw in [sw1, sw2]:
        status = False
        out = sw.libs.vtysh.show_spanning_tree()
        if out['error'] != 'Spanning-tree is disabled':
            status = True
        out = sw.libs.vtysh.show_spanning_tree_mst()
        if out['error'] != 'Spanning-tree is disabled':
            status = True
        out = sw.libs.vtysh.show_spanning_tree_mst_config()
        if out['error'] != 'Spanning-tree is disabled':
            status = True
        out = sw('show spanning-tree detail')
        if 'Spanning-tree is disabled' not in out:
            status = True
        out = sw('show spanning-tree mst detail')
        if 'Spanning-tree is disabled' not in out:
            status = True
        out = sw('show spanning-tree mst 1')
        if 'Spanning-tree is disabled' not in out:
            status = True
        out = sw('show spanning-tree mst 1 detail')
        if 'Spanning-tree is disabled' not in out:
            status = True
        out = sw('show spanning-tree mst 1 interface 1')
        if 'Spanning-tree is disabled' not in out:
            status = True
        out = sw('show spanning-tree mst 1 interface 2')
        if 'Spanning-tree is disabled' not in out:
            status = True
        out = sw('show spanning-tree mst 1 interface 1 detail')
        if 'Spanning-tree is disabled' not in out:
            status = True
        out = sw('show spanning-tree mst 1 interface 2 detail')
        if 'Spanning-tree is disabled' not in out:
            status = True
        assert(status is False), \
            "MSTP show commands should not work while MSTP is disabled"

    print("mstp commands CT passed")
