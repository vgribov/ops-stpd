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
OpenSwitch Test for cist single region root elect.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from pytest import mark

import re
import time

TOPOLOGY = """
#                                        +---------+
#                         +-------------->   hs1   |
#                         |              |         |
#                         |              +---------+
#                         |
#                    +----+------+
#      +------------->   ops1    <------------+
#      |             +-----------+            |
#      |                                      |
#+-----v-----+                           +----v-----+
#|   ops2    <--------------------------->   ops3   |
#+-----+-----+                           +----------+
#      |
#      |                                 +----------+
#      |                                 |  hs2     |
#      +--------------------------------->          |
#                                        +----------+
#
# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
[type=openswitch name="OpenSwitch 2"] ops2
[type=openswitch name="OpenSwitch 3"] ops3
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2

# Links
ops1:1 -- ops2:1
ops1:2 -- ops3:1
ops2:2 -- ops3:2
hs1:1 -- ops1:4
hs2:1 -- ops2:4
"""

HELLO_TIME = 2
REGION_1 = "Region-One"
VERSION = "8"
PRIORITY = 8
MAX_PRIORITY = 15


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


def ops_check_root_bridge_active_ports(interface, ops_show):

    assert(ops_show[interface]['role'] == 'Designated'), \
           "Port role has not updated correctly"
    assert(ops_show[interface]['State'] == 'Forwarding'), \
        "Port state has not updated correctly"


def ops_check_root_bridge_relayed_prot_params(root_show, ops_show):

    assert(root_show['bridge_max_age'] == ops_show['root_max_age']), \
        "Root bridge max age is updated incorrectly"

    assert(root_show['bridge_forward_delay'] ==
           ops_show['root_forward_delay']), \
        "Root bridge forward delay is updated incorrectly"

    assert(root_show['bridge_priority'] == ops_show['root_priority']), \
        "Root bridge priority is updated incorrectly"

    assert(root_show['bridge_mac_address'] ==
           ops_show['root_mac_address']), \
        "Root bridge mac is updated incorrectly"


@mark.platform_incompatible(['docker'])
def test_stp_cist_single_region_root_elect(topology):
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
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert ops2 is not None
    assert ops3 is not None
    assert hs1 is not None
    assert hs2 is not None

    ops1_port1 = ops1.ports['1']
    ops1_port2 = ops1.ports['2']
    ops2_port1 = ops2.ports['1']
    ops2_port2 = ops2.ports['2']
    ops3_port1 = ops3.ports['1']
    ops3_port2 = ops3.ports['2']

    # Configure IP and bring UP host 1 interfaces
    hs1.libs.ip.interface('1', addr='10.0.0.1/24', up=True)

    # Configure IP and bring UP host 2 interfaces
    hs2.libs.ip.interface('1', addr='10.0.0.2/24', up=True)

    for ops in [ops1, ops2, ops3]:
        enable_l2port(ops, '1')
        enable_l2port(ops, '2')
        for switch, portlbl in [(ops, '1'), (ops, '2')]:
            wait_until_interface_up(switch, portlbl)

        config_mstp_region(ops, REGION_1, VERSION, HELLO_TIME)

    enable_l2port(ops1, '4')
    enable_l2port(ops2, '4')
    for switch, portlbl in [(ops1, '4'), (ops2, '4')]:
        wait_until_interface_up(switch, portlbl)

    for ops in [ops1, ops2, ops3]:
        with ops.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree()

    # Covergence should happen with HELLO_TIME * 2
    time.sleep(HELLO_TIME * 2)

    ops1_show = ops1.libs.vtysh.show_spanning_tree()
    ops1_mac = ops_get_system_mac_address(ops1)
    ops2_show = ops2.libs.vtysh.show_spanning_tree()
    ops2_mac = ops_get_system_mac_address(ops2)
    ops3_show = ops3.libs.vtysh.show_spanning_tree()
    ops3_mac = ops_get_system_mac_address(ops3)

    ops1_mac_int = int(ops1_mac.replace(':', ''), 16)
    ops2_mac_int = int(ops2_mac.replace(':', ''), 16)
    ops3_mac_int = int(ops3_mac.replace(':', ''), 16)

    root = ops3_mac
    if (ops1_mac_int < ops2_mac_int) and (ops1_mac_int < ops3_mac_int):
        root = ops1_mac
    elif (ops2_mac_int < ops3_mac_int):
        root = ops2_mac

    for ops_show in [ops1_show, ops2_show, ops3_show]:
        assert(root == ops_show['root_mac_address']), \
            "Root bridge mac is updated incorrectly"

    forwarding = 0
    blocking = 0

    for ops_show in [ops1_show, ops2_show, ops3_show]:
        if ops_show == ops1_show:
            interface1 = ops1_port1
            interface2 = ops1_port2
        if ops_show == ops2_show:
            interface1 = ops2_port1
            interface2 = ops2_port2
        if ops_show == ops3_show:
            interface1 = ops3_port1
            interface2 = ops3_port2
        if ops_show[interface1]['State'] == 'Forwarding':
            forwarding = forwarding + 1
        elif ops_show[interface1]['State'] == 'Blocking':
            blocking = blocking + 1

        if ops_show[interface2]['State'] == 'Forwarding':
            forwarding = forwarding + 1
        elif ops_show[interface2]['State'] == 'Blocking':
            blocking = blocking + 1

    assert(forwarding == 5), \
        "Port state has not updated correctly"

    assert(blocking == 1), \
        "Port state has not updated correctly"

    for ops_show in [ops1_show, ops2_show, ops3_show]:
        if ops_show == ops1_show:
            interface1 = ops1_port1
            interface2 = ops1_port2
        if ops_show == ops2_show:
            interface1 = ops2_port1
            interface2 = ops2_port2
        if ops_show == ops3_show:
            interface1 = ops3_port1
            interface2 = ops3_port2
        if ops_show['root'] == 'yes':
            root_show = ops_show
            ops_check_root_bridge_active_ports(interface1, ops_show)
            ops_check_root_bridge_active_ports(interface2, ops_show)
        else:
            if (ops_show[interface1]['role'] == 'Designated'):
                assert(ops_show[interface1]['State'] == 'Forwarding'), \
                    "Port state has not updated correctly"
            elif (ops_show[interface1]['role'] == 'Root'):
                assert(ops_show[interface1]['State'] == 'Forwarding'), \
                    "Port state has not updated correctly"
            elif (ops_show[interface1]['role'] == 'Alternate'):
                assert(ops_show[interface1]['State'] == 'Blocking'), \
                    "Port state has not updated correctly"

    for ops_show in [ops1_show, ops2_show, ops3_show]:
        ops_check_root_bridge_relayed_prot_params(root_show, ops_show)

    ping = hs1.libs.ping.ping(10, '10.0.0.2')
    assert(ping['transmitted'] >= 7 and ping['received'] >= 7), \
        "Ping between host failed after convergence"

    priority = PRIORITY
    root_sw = None
    for ops in [ops1, ops2, ops3]:
        ops_show = ops.libs.vtysh.show_spanning_tree()
        if root == ops_show['bridge_mac_address']:
            with ops.libs.vtysh.Configure() as ctx:
                ctx.spanning_tree_priority(MAX_PRIORITY)
        else:
            with ops.libs.vtysh.Configure() as ctx:
                ctx.spanning_tree_priority(priority)
            if not root_sw:
                root_sw = ops
            priority = priority + 1

    # Covergence should happen with HELLO_TIME * 2
    time.sleep(HELLO_TIME * 2)

    root = ops_get_system_mac_address(root_sw)

    ops1_show = ops1.libs.vtysh.show_spanning_tree()

    ops2_show = ops2.libs.vtysh.show_spanning_tree()

    ops3_show = ops3.libs.vtysh.show_spanning_tree()

    for ops_show in [ops1_show, ops2_show, ops3_show]:
        assert(root == ops_show['root_mac_address']), \
            "Root bridge mac is updated incorrectly"

    '''
    ping = hs1.libs.ping.ping(10, '10.0.0.2')
    assert(ping['transmitted'] >= 7 and ping['received'] >= 7), \
        "Ping between host failed after convergence"
    '''

    for ops in [ops1, ops2, ops3]:
        with ops.libs.vtysh.Configure() as ctx:
            ctx.no_spanning_tree_config_name()
            ctx.no_spanning_tree_config_revision()
            ctx.no_spanning_tree_hello_time()
            ctx.no_spanning_tree_priority()
            ctx.no_spanning_tree()
