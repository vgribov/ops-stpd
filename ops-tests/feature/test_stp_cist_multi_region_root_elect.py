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
OpenSwitch Test for cist multiple regional root elect.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from pytest import mark

import re
import json
import time

TOPOLOGY = """
#
# +-------+     +--------+      +-------+     +-------+
# |       <----->        <------>       <----->       |
# | OPS1  |     | OPS2   |      | OPS3  |     | OPS4  |
# |       <----->        <------>       <----->       |
# +-------+     +--------+      +-------+     +-------+
#
#
# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
[type=openswitch name="OpenSwitch 2"] ops2
[type=openswitch name="OpenSwitch 3"] ops3
[type=openswitch name="OpenSwitch 4"] ops4

# Links
ops1:1 -- ops2:1
ops1:2 -- ops2:2
ops2:3 -- ops3:3
ops2:4 -- ops3:4
ops3:1 -- ops4:1
ops3:2 -- ops4:2

"""

HELLO_TIME = 2
REGION_1 = "Region-One"
REGION_2 = "Region-Two"
REGION_3 = "Region-Three"
REGION_4 = "Region-Four"
VERSION = 8
PRIORITY = 8


def enable_l2port(ops, port):
    with ops.libs.vtysh.ConfigInterface(port) as ctx:
        ctx.no_routing()
        ctx.no_shutdown()


def config_mstp_region(ops, region_name, version, hello_time):
    with ops.libs.vtysh.Configure() as ctx:
        ctx.spanning_tree_config_name(region_name)
        ctx.spanning_tree_config_revision(version)
        ctx.spanning_tree_hello_time(hello_time)


def ops_get_system_mac_address(ops):
    result = ops.send_command('ovs-vsctl list system | grep system_mac',
                              shell='bash')
    result = re.search('\s*system_mac\s*:\s*"(?P<sys_mac>.*)"', result)
    result = result.groupdict()
    ops_mac = result['sys_mac']
    return ops_mac


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


def cleanup_config(switch):
    with switch.libs.vtysh.Configure() as ctx:
        ctx.no_spanning_tree_config_name()
        ctx.no_spanning_tree_config_revision()
        ctx.no_spanning_tree_hello_time()
        ctx.no_spanning_tree_priority()
        ctx.no_spanning_tree()


@mark.platform_incompatible(['docker'])
def test_stp_cist_multi_region_root_elect(topology):
    """
    Test that a cist in multiple region is functional with a OpenSwitch switch.

    Build a topology of three switch and connection made as shown in topology.
    Setup a spanning tree configuration on all the three switch so that all the
    switch are in multiple region. Now enable spanning tree and check loop is
    resolved and cist root selected.

    """
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')
    ops3 = topology.get('ops3')
    ops4 = topology.get('ops4')

    assert ops1 is not None
    assert ops2 is not None
    assert ops3 is not None

    for ops in [ops1, ops2, ops3, ops4]:
        cleanup_config(ops)

    for ops in [ops1, ops4]:
        enable_l2port(ops, '1')
        enable_l2port(ops, '2')
        for switch, portlbl in [(ops, '1'), (ops, '2')]:
            wait_until_interface_up(switch, portlbl)

    for ops in [ops2, ops3]:
        enable_l2port(ops, '1')
        enable_l2port(ops, '2')
        enable_l2port(ops, '3')
        enable_l2port(ops, '4')
        for switch, portlbl in [(ops, '1'), (ops, '2'),
                                (ops, '3'), (ops, '4')]:
            wait_until_interface_up(switch, portlbl)

    for ops in [ops1, ops2]:
        config_mstp_region(ops, REGION_1, VERSION, HELLO_TIME)

    for ops in [ops3, ops4]:
        config_mstp_region(ops, REGION_2, VERSION, HELLO_TIME)

    for ops in [ops1, ops2, ops3, ops4]:
        with ops.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree()

    # Covergence should happen with HELLO_TIME * 2
    time.sleep(HELLO_TIME * 5)

    ops1_show = ops1.libs.vtysh.show_spanning_tree()
    ops1_mac = ops_get_system_mac_address(ops1)
    ops2_show = ops2.libs.vtysh.show_spanning_tree()
    ops2_mac = ops_get_system_mac_address(ops2)
    ops3_show = ops3.libs.vtysh.show_spanning_tree()
    ops3_mac = ops_get_system_mac_address(ops3)
    ops4_show = ops4.libs.vtysh.show_spanning_tree()
    ops4_mac = ops_get_system_mac_address(ops4)

    ops1_mac_int = int(ops1_mac.replace(':', ''), 16)
    ops2_mac_int = int(ops2_mac.replace(':', ''), 16)
    ops3_mac_int = int(ops3_mac.replace(':', ''), 16)
    ops4_mac_int = int(ops4_mac.replace(':', ''), 16)

    region_1_root = ops2_mac
    region_1_sw = ops2
    if (ops1_mac_int < ops2_mac_int):
        region_1_root = ops1_mac
        region_1_sw = ops1

    region_2_root = ops4_mac
    region_2_sw = ops4
    if (ops3_mac_int < ops4_mac_int):
        region_2_root = ops3_mac
        region_2_sw = ops3

    root = region_2_root
    if (region_1_root < region_2_root):
        root = region_1_root

    assert(root == ops1_show['root_mac_address']), \
        "Root bridge mac is updated incorrectly"

    assert(root == ops2_show['root_mac_address']), \
        "Root bridge mac is updated incorrectly"

    assert(root == ops3_show['root_mac_address']), \
        "Root bridge mac is updated incorrectly"

    assert(root == ops4_show['root_mac_address']), \
        "Root bridge mac is updated incorrectly"

    if(root == ops1_mac):
        region_1_sw = ops1
        region_2_sw = ops3
    if(root == ops4_mac):
        region_1_sw = ops2
        region_2_sw = ops4
    if(root == ops2_mac or root == ops3_mac):
        region_1_sw = ops2
        region_2_sw = ops3

    region1_show_mst = region_1_sw.libs.vtysh.show_spanning_tree_mst()
    print(json.dumps(region1_show_mst, indent=4))

    region2_show_mst = region_2_sw.libs.vtysh.show_spanning_tree_mst()
    print(json.dumps(region2_show_mst, indent=4))

    assert(region1_show_mst['MST0']["regional_root"] == "yes"), \
        "Regional root not updated correclty"

    assert(region2_show_mst['MST0']['regional_root'] == 'yes'), \
        "Regional root not updated correclty"

    priority = PRIORITY
    for ops in [ops1, ops2, ops3, ops4]:
        with ops.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree_priority(priority)
        priority = priority + 1

    # Covergence should happen with HELLO_TIME * 2
    time.sleep(HELLO_TIME * 5)

    ops1_show_mst = ops1.libs.vtysh.show_spanning_tree_mst()
    print(json.dumps(ops1_show_mst, indent=4))

    ops3_show_mst = ops3.libs.vtysh.show_spanning_tree_mst()
    print(json.dumps(ops3_show_mst, indent=4))

    assert(ops3_show_mst['MST0']['regional_root'] == 'yes'), \
        "Regional root not updated correclty"

    assert(ops1_show_mst['MST0']['regional_root'] == 'yes'), \
        "Regional root not updated correclty"

    priority = PRIORITY
    for ops in [ops1, ops2, ops3, ops4]:
        with ops.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree_priority(priority)
        priority = priority - 1

    # Covergence should happen with HELLO_TIME * 2
    time.sleep(HELLO_TIME * 5)

    ops2_show_mst = ops2.libs.vtysh.show_spanning_tree_mst()
    print(json.dumps(ops2_show_mst, indent=4))

    ops4_show_mst = ops4.libs.vtysh.show_spanning_tree_mst()
    print(json.dumps(ops4_show_mst, indent=4))

    assert(ops4_show_mst['MST0']['regional_root'] == 'yes'), \
        "Regional root not updated correclty"

    assert(ops2_show_mst['MST0']['regional_root'] == 'yes'), \
        "Regional root not updated correclty"

    priority = PRIORITY
    for ops in [ops1, ops2, ops3, ops4]:
        with ops.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree_priority(priority)

    config_mstp_region(ops1, REGION_1, VERSION, HELLO_TIME)
    config_mstp_region(ops2, REGION_2, VERSION, HELLO_TIME)
    config_mstp_region(ops3, REGION_3, VERSION, HELLO_TIME)
    config_mstp_region(ops4, REGION_4, VERSION, HELLO_TIME)

    # Covergence should happen with HELLO_TIME * 2
    time.sleep(HELLO_TIME * 5)

    ops1_show_mst = ops1.libs.vtysh.show_spanning_tree_mst()
    print(json.dumps(ops1_show_mst, indent=4))

    ops2_show_mst = ops2.libs.vtysh.show_spanning_tree_mst()
    print(json.dumps(ops2_show_mst, indent=4))

    ops3_show_mst = ops3.libs.vtysh.show_spanning_tree_mst()
    print(json.dumps(ops3_show_mst, indent=4))

    ops4_show_mst = ops4.libs.vtysh.show_spanning_tree_mst()
    print(json.dumps(ops4_show_mst, indent=4))

    '''
    assert(ops1_show_mst['MST0']['regional_root'] == 'yes'), \
        "Regional root not updated correclty"

    assert(ops2_show_mst['MST0']['regional_root'] == 'yes'), \
        "Regional root not updated correclty"

    assert(ops3_show_mst['MST0']['regional_root'] == 'yes'), \
        "Regional root not updated correclty"

    assert(ops4_show_mst['MST0']['regional_root'] == 'yes'), \
        "Regional root not updated correclty"
    '''

    for ops in [ops1, ops2, ops3, ops4]:
        cleanup_config(ops)
