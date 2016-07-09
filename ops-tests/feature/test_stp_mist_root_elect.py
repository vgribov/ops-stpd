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

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

import re
# import json
import time
from pytest import mark
# from random import randint

TOPOLOGY = """
#                    +-----------+
#      +------------->   ops1    <------------+
#      |             +-----------+            |
#      |                                      |
#+-----v-----+                           +----v-----+
#|   ops2    <--------------------------->   ops3   |
#+-----------+                           +----------+
#
# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
[type=openswitch name="OpenSwitch 2"] ops2
[type=openswitch name="OpenSwitch 3"] ops3

# Links
ops1:1 -- ops2:1
ops1:2 -- ops3:1
ops2:2 -- ops3:2
"""

HELLO_TIME = 2
REGION_1 = "Region-One"
VERSION_REG1 = "1"

REGION_2 = "Region-Two"
VERSION_REG2 = "2"

VLAN_RANGE = 6
LOW_PRIORITY = 7


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


def enable_l2port(ops, port):
    with ops.libs.vtysh.ConfigInterface(port) as ctx:
        ctx.no_routing()
        ctx.no_shutdown()


def tag_vlan_l2port(ops, port, vlan):
    with ops.libs.vtysh.ConfigInterface(port) as ctx:
        ctx.vlan_trunk_allowed(str(vlan))


def untag_vlan_l2port(ops, port, vlan):
    with ops.libs.vtysh.ConfigInterface(port) as ctx:
        ctx.no_vlan_trunk_allowed(str(vlan))


def config_mstp_region(ops, region_name, version, hello_time):
    with ops.libs.vtysh.Configure() as ctx:
        ctx.spanning_tree_config_name(region_name)
        ctx.spanning_tree_config_revision(version)
        ctx.spanning_tree_hello_time(hello_time)


def get_system_mac_address(ops):

    result = ops.send_command('ovs-vsctl list system | grep system_mac',
                              shell='bash')
    result = re.search('\s*system_mac\s*:\s*"(?P<sys_mac>.*)"', result)
    result = result.groupdict()
    ops_mac = result['sys_mac']
    return ops_mac


def mist_check_root_bridge_active_ports(interface, ops_show, mst):

    assert(ops_show[mst][interface]['role'] == 'Designated'), \
        "Port role has not updated correctly"
    assert(ops_show[mst][interface]['State'] == 'Forwarding'), \
        "Port state has not updated correctly"


def mist_check_root_bridge_relayed_prot_params(root_show, ops_show, instance):
    mist_id = (instance[3:])
    mist_id.strip()
    root_sh_pri = int(root_show[instance]['bridge_priority']) + int(mist_id)
    ops_sh_pri = int(ops_show[instance]['root_priority'])

    assert(root_sh_pri == ops_sh_pri), \
        "Root bridge priority is updated incorrectly"

    assert(root_show[instance]['bridge_address'] ==
           ops_show[instance]['root_address']), \
        "Root bridge mac is updated incorrectly"


# vlan param accepts integer value
def configure_vlan(ops, vlan):
    with ops.libs.vtysh.ConfigVlan(str(vlan)) as ctx:
        ctx.no_shutdown()


def configure_vlan_trunk(ops, port, vlan):
    with ops.libs.vtysh.ConfigInterface(str(port)) as ctx:
        ctx.vlan_trunk_allowed(vlan)


def configure_spanning_tree_instance(ops, instance, vlans):
    i = 0
    while i < len(vlans):
        vlan2map = vlans[i]
        with ops.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree_instance_vlan(instance, vlan2map)
        i = i + 1


# this returns the lowest mac and it's index in the list
def get_low_mac_index(mac_list):
    mac_int = []
    macs_count = len(mac_list)
    assert macs_count > 0
    for mac in mac_list:
        mac_int.append(int(mac.replace(':', ''), 16))
    list_index = mac_int.index(min(mac_int))
    return list_index


@mark.platform_incompatible(['docker'])
def test_stp_mist_root_elect(topology):
    """
    Test that a cist in single region is functional with a OpenSwitch switch.

    Build a topology of three switch and connection made as shown in topology.
    Setup a spanning tree configuration on all the three switch so that all the
    switch are in same region. Now enable spanning tree and check loop is
    resolved and cist root selected.
    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    ops3 = topology.get('ops3')

    assert ops1 is not None
    assert ops2 is not None
    assert ops3 is not None

    ops1_port1 = ops1.ports['1']
    ops1_port2 = ops1.ports['2']
    ops2_port1 = ops2.ports['1']
    ops2_port2 = ops2.ports['2']
    ops3_port1 = ops3.ports['1']
    ops3_port2 = ops3.ports['2']

    # configure VLANS
    for ops in [ops1, ops2, ops3]:
        for vlan in range(1, VLAN_RANGE + 1):
            configure_vlan(ops, vlan)

    for ops in [ops1, ops2, ops3]:
        enable_l2port(ops, '1')
        for vlan in range(1, VLAN_RANGE + 1):
            tag_vlan_l2port(ops, '1', vlan)

        enable_l2port(ops, '2')
        for vlan in range(1, VLAN_RANGE + 1):
            tag_vlan_l2port(ops, '2', vlan)

        for switch, portlbl in [(ops, '1'), (ops, '2')]:
            wait_until_interface_up(switch, portlbl)

        config_mstp_region(ops, REGION_1, VERSION_REG1, HELLO_TIME)

    for ops in [ops1, ops2, ops3]:
        with ops.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree_instance_vlan(2, 3)
            ctx.spanning_tree_instance_vlan(2, 4)
            ctx.spanning_tree_instance_vlan(3, 5)
            ctx.spanning_tree_instance_vlan(3, 6)

    # enable spanning tree on all of the switches
    for ops in [ops1, ops2, ops3]:
        with ops.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree()

    print("wait for convergence time")
    # Covergence should happen with HELLO_TIME * 2
    time.sleep(HELLO_TIME * 2)

    ops1_show_mst = ops1.libs.vtysh.show_spanning_tree_mst()

    ops2_show_mst = ops2.libs.vtysh.show_spanning_tree_mst()

    ops3_show_mst = ops3.libs.vtysh.show_spanning_tree_mst()

    ops1_mac = get_system_mac_address(ops1)
    ops2_mac = get_system_mac_address(ops2)
    ops3_mac = get_system_mac_address(ops3)

    ops1_mac_int = int(ops1_mac.replace(':', ''), 16)
    ops2_mac_int = int(ops2_mac.replace(':', ''), 16)
    ops3_mac_int = int(ops3_mac.replace(':', ''), 16)

    root = ops3_mac
    if (ops1_mac_int < ops2_mac_int) and (ops1_mac_int < ops3_mac_int):
        root = ops1_mac
    elif (ops2_mac_int < ops3_mac_int):
        root = ops2_mac

    for ops_show in [ops1_show_mst, ops2_show_mst, ops3_show_mst]:
        for mst in ['MST2', 'MST3']:
            assert(root == ops_show[mst]['root_address']), \
                "Root bridge mac is updated incorrectly"

    for mst in ['MST2', 'MST3']:
        forwarding = 0
        blocking = 0
        for ops_show in [ops1_show_mst, ops2_show_mst, ops3_show_mst]:
            if ops_show == ops1_show_mst:
                interface1 = ops1_port1
                interface2 = ops1_port2
            if ops_show == ops2_show_mst:
                interface1 = ops2_port1
                interface2 = ops2_port2
            if ops_show == ops3_show_mst:
                interface1 = ops3_port1
                interface2 = ops3_port2
            if ops_show[mst][interface1]['State'] == 'Forwarding':
                forwarding = forwarding + 1
            elif ops_show[mst][interface1]['State'] == 'Blocking':
                blocking = blocking + 1

            if ops_show[mst][interface2]['State'] == 'Forwarding':
                forwarding = forwarding + 1
            elif ops_show[mst][interface2]['State'] == 'Blocking':
                blocking = blocking + 1

        assert(forwarding == 5), \
            "Port state has not updated correctly"

        assert(blocking == 1), \
            "Port state has not updated correctly"

    for mst in ['MST2', 'MST3']:
        for ops_show in [ops1_show_mst, ops2_show_mst, ops3_show_mst]:
            if ops_show == ops1_show_mst:
                int1 = ops1_port1
                int2 = ops1_port2
            if ops_show == ops2_show_mst:
                int1 = ops2_port1
                int2 = ops2_port2
            if ops_show == ops3_show_mst:
                int1 = ops3_port1
                int2 = ops3_port2
            if ops_show[mst]['bridge_address'] == \
               ops_show[mst]['root_address']:
                mist_check_root_bridge_active_ports(int1, ops_show, mst)
                mist_check_root_bridge_active_ports(int2, ops_show, mst)
                if mst == 'MST2':
                    root_mst2 = ops_show
                if mst == 'MST3':
                    root_mst3 = ops_show
            else:
                if (ops_show[mst][int1]['role'] == 'Designated'):
                    assert(ops_show[mst][int1]['State'] == 'Forwarding'),\
                        "Port state has not updated correctly"
                elif (ops_show[mst][int1]['role'] == 'Root'):
                    assert(ops_show[mst][int1]['State'] == 'Forwarding'),\
                        "Port state has not updated correctly"
                elif (ops_show[mst][int1]['role'] == 'Alternate'):
                    assert(ops_show[mst][int1]['State'] == 'Blocking'),\
                        "Port state has not updated correctly"

                if (ops_show[mst][int2]['role'] == 'Designated'):
                    assert(ops_show[mst][int2]['State'] == 'Forwarding'),\
                        "Port state has not updated correctly"
                elif (ops_show[mst][int2]['role'] == 'Root'):
                    assert(ops_show[mst][int2]['State'] == 'Forwarding'),\
                        "Port state has not updated correctly"
                elif (ops_show[mst][int2]['role'] == 'Alternate'):
                    assert(ops_show[mst][int2]['State'] == 'Blocking'),\
                        "Port state has not updated correctly"

    for ops_show in [ops1_show_mst, ops2_show_mst, ops3_show_mst]:
        mist_check_root_bridge_relayed_prot_params(root_mst2, ops_show, 'MST2')
        mist_check_root_bridge_relayed_prot_params(root_mst3, ops_show, 'MST3')

    print("Configure Priority for all instance")

    priority = LOW_PRIORITY
    for ops in [ops1, ops2, ops3]:
        with ops.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree_instance_priority(2, priority)
            priority = priority + 1

    for ops in [ops1, ops2, ops3]:
        with ops.libs.vtysh.Configure() as ctx:
            priority = priority - 1
            ctx.spanning_tree_instance_priority(3, priority)
            priority = priority - 1

    time.sleep(HELLO_TIME * 5)

    ops1_show_mst = ops1.libs.vtysh.show_spanning_tree_mst()

    ops2_show_mst = ops2.libs.vtysh.show_spanning_tree_mst()

    ops3_show_mst = ops3.libs.vtysh.show_spanning_tree_mst()

    root = ops1_mac
    root_mst = ops1_show_mst
    for ops_show in [ops1_show_mst, ops2_show_mst, ops3_show_mst]:
        assert(root == ops_show['MST2']['root_address']), \
            "Root bridge mac is updated incorrectly"
        mist_check_root_bridge_relayed_prot_params(root_mst, ops_show, 'MST2')

    root = ops3_mac
    root_mst = ops3_show_mst
    for ops_show in [ops1_show_mst, ops2_show_mst, ops3_show_mst]:
        assert(root == ops_show['MST3']['root_address']), \
            "Root bridge mac is updated incorrectly"
        mist_check_root_bridge_relayed_prot_params(root_mst, ops_show, 'MST3')
