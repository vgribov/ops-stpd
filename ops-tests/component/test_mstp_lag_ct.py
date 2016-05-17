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

import re
import time
import pytest
from time import sleep

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

HELLO_TIME = 2
REGION_1 = "Region-One"
VERSION = "8"
PRIORITY = 8
MAX_PRIORITY = 15
DIAG_DUMP_LOCAL_STATE = 'actor_oper_port_state'
DIAG_DUMP_REMOTE_STATE = 'partner_oper_port_state'
LOCAL_STATE = 'local_state'
REMOTE_STATE = 'remote_state'
ACTOR = 'Actor'
PARTNER = 'Partner'
LACP_PROTOCOL = '0x8809'
LACP_MAC_HEADER = '01:80:c2:00:00:02'


def create_lag_active(sw, lag_id):
    with sw.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        ctx.lacp_mode_active()


def create_lag_passive(sw, lag_id):
    with sw.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        ctx.lacp_mode_passive()


def lag_no_routing(sw, lag_id):
    with sw.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        ctx.no_routing()


def create_lag(sw, lag_id, lag_mode):
    with sw.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        if(lag_mode == 'active'):
            ctx.lacp_mode_active()
        elif(lag_mode == 'passive'):
            ctx.lacp_mode_passive()
        elif(lag_mode == 'off'):
            pass
        else:
            assert False, 'Invalid mode %s for LAG' % (lag_mode)
    lag_name = "lag" + lag_id
    output = sw.libs.vtysh.show_lacp_aggregates(lag_name)
    assert lag_mode == output[lag_name]['mode'],\
        "Unable to create and validate LAG"


def delete_lag(sw, lag_id):
    with sw.libs.vtysh.Configure() as ctx:
        ctx.no_interface_lag(lag_id)
    lag_name = "lag" + lag_id
    output = sw.libs.vtysh.show_lacp_aggregates()
    assert lag_name not in output,\
        "Unable to delete LAG"


def associate_interface_to_lag(sw, interface, lag_id):
    with sw.libs.vtysh.ConfigInterface(interface) as ctx:
        ctx.lag(lag_id)
    lag_name = "lag" + lag_id
    output = sw.libs.vtysh.show_lacp_aggregates(lag_name)
    assert interface in output[lag_name]['interfaces'],\
        "Unable to associate interface to lag"


def remove_interface_from_lag(sw, interface, lag_id):
    with sw.libs.vtysh.ConfigInterface(interface) as ctx:
        ctx.no_lag(lag_id)
    lag_name = "lag" + lag_id
    output = sw.libs.vtysh.show_lacp_aggregates(lag_name)
    assert interface not in output[lag_name]['interfaces'],\
        "Unable to remove interface from lag"


def disassociate_interface_to_lag(sw, interface, lag_id):
    with sw.libs.vtysh.ConfigInterface(interface) as ctx:
        ctx.no_lag(lag_id)


def turn_on_interface(sw, interface):
    with sw.libs.vtysh.ConfigInterface(interface) as ctx:
        ctx.no_shutdown()


def turn_off_interface(sw, interface):
    with sw.libs.vtysh.ConfigInterface(interface) as ctx:
        ctx.shutdown()


def validate_turn_on_interfaces(sw, interfaces):
    for intf in interfaces:
        output = sw.libs.vtysh.show_interface(intf)
        assert output['interface_state'] == 'up',\
            "Interface state for " + intf + " is down"


def validate_turn_off_interfaces(sw, interfaces):
    for intf in interfaces:
        output = sw.libs.vtysh.show_interface(intf)
        assert output['interface_state'] == 'down',\
            "Interface state for " + intf + "is up"


def validate_local_key(map_lacp, lag_id):
    assert map_lacp['local_key'] == lag_id,\
        "Actor Key is not the same as the LAG ID"


def validate_remote_key(map_lacp, lag_id):
    assert map_lacp['remote_key'] == lag_id,\
        "Partner Key is not the same as the LAG ID"


def validate_lag_name(map_lacp, lag_id):
    assert map_lacp['lag_id'] == lag_id,\
        "LAG ID should be " + lag_id


def validate_lag_state_sync(map_lacp, state, lacp_mode='active'):
    assert map_lacp[state][lacp_mode] is True,\
        "LAG state should be {}".format(lacp_mode)
    assert map_lacp[state]['aggregable'] is True,\
        "LAG state should have aggregable enabled"
    assert map_lacp[state]['in_sync'] is True,\
        "LAG state should be In Sync"
    assert map_lacp[state]['collecting'] is True,\
        "LAG state should be in collecting"
    assert map_lacp[state]['distributing'] is True,\
        "LAG state should be in distributing"


def lag_shutdown(sw, lag_id):
    with sw.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        ctx.shutdown()


def lag_no_shutdown(sw, lag_id):
    with sw.libs.vtysh.ConfigInterfaceLag(lag_id) as ctx:
        ctx.no_shutdown()


def config_mstp_region(ops, region_name, version):
    with ops.libs.vtysh.Configure() as ctx:
        ctx.spanning_tree_config_name(region_name)
        ctx.spanning_tree_config_revision(version)


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


def ops_check_root_bridge_active_ports(interface, ops_show):

    assert(ops_show[interface]['role'] == 'Designated'), \
           "Port role has not updated correctly"
    assert(ops_show[interface]['State'] == 'Forwarding'), \
        "Port state has not updated correctly"


@pytest.mark.skipif(True, reason="lacp bond_status column issue")
def test_cist_single_region_root_elect_with_lag(topology):
    """
    Test that a cist in single region is functional with a OpenSwitch switch.

    Build a topology of two switch and connection made as shown in topology.
    Setup a spanning tree configuration on all the switches so that all the
    switch are in same region. Now enable spanning tree and check cist root
    selected.
    """
    """
    Case 1:
        Verify 2 switches configured
        with L2 dynamic LAGs works properly.
    """
    sw1 = topology.get('sw1')
    sw2 = topology.get('sw2')
    sw1_lag_id = '10'
    sw2_lag_id = '10'

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
    sleep(60)

    print("Verify all interface are up")
    validate_turn_on_interfaces(sw1, ports_sw1)
    validate_turn_on_interfaces(sw2, ports_sw2)

    print("craete l2 lag in both switches")
    lag_no_routing(sw1, sw1_lag_id)
    lag_no_routing(sw2, sw1_lag_id)

    print("Create LAG in both switches")
    create_lag(sw1, sw1_lag_id, 'active')
    create_lag(sw2, sw2_lag_id, 'active')

    print("Associate interfaces [1, 2] to LAG in both switches")
    associate_interface_to_lag(sw1, p11, sw1_lag_id)
    associate_interface_to_lag(sw1, p12, sw1_lag_id)
    associate_interface_to_lag(sw2, p21, sw2_lag_id)
    associate_interface_to_lag(sw2, p22, sw2_lag_id)

    print("Enable lag in both siwthces")
    lag_no_shutdown(sw1, sw1_lag_id)
    lag_no_shutdown(sw2, sw2_lag_id)

    print("Waiting for LAG negotations between switches")
    sleep(100)

    print("Get information for LAG in interface 2 with both switches")
    map_lacp_sw1 = sw1.libs.vtysh.show_lacp_interface(p12)
    map_lacp_sw2 = sw2.libs.vtysh.show_lacp_interface(p22)

    print("Validate the LAG was created in both switches")
    validate_lag_name(map_lacp_sw1, sw1_lag_id)
    validate_local_key(map_lacp_sw1, sw1_lag_id)
    validate_remote_key(map_lacp_sw1, sw2_lag_id)
    validate_lag_state_sync(map_lacp_sw1, LOCAL_STATE)
    validate_lag_state_sync(map_lacp_sw1, REMOTE_STATE)

    validate_lag_name(map_lacp_sw2, sw2_lag_id)
    validate_local_key(map_lacp_sw2, sw2_lag_id)
    validate_remote_key(map_lacp_sw2, sw1_lag_id)
    validate_lag_state_sync(map_lacp_sw2, LOCAL_STATE)
    validate_lag_state_sync(map_lacp_sw2, REMOTE_STATE)

    for sw in [sw1, sw2]:
        config_mstp_region(sw, REGION_1, VERSION)

    for sw in [sw1, sw2]:
        with sw.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree()

    # Covergence should happen with HELLO_TIME * 2
    time.sleep(HELLO_TIME * 2)

    sw1_show = sw1.libs.vtysh.show_spanning_tree()
    sw1_mac = ops_get_system_mac_address(sw1)
    sw2_show = sw2.libs.vtysh.show_spanning_tree()
    sw2_mac = ops_get_system_mac_address(sw2)

    sw1_mac_int = int(sw1_mac.replace(':', ''), 16)
    sw2_mac_int = int(sw2_mac.replace(':', ''), 16)

    root = sw2_mac
    if (sw1_mac_int < sw2_mac_int):
        root = sw1_mac

    for sw_show in [sw1_show, sw2_show]:
        assert(root == sw_show['root_mac_address']), \
            "Root bridge mac is updated incorrectly"

    forwarding = 0
    blocking = 0

    for sw_show in [sw1_show, sw2_show]:
        if sw_show == sw1_show:
            interface = 'lag' + sw1_lag_id
        if sw_show == sw2_show:
            interface = 'lag' + sw2_lag_id
        if sw_show[interface]['State'] == 'Forwarding':
            forwarding = forwarding + 1
        elif sw_show[interface]['State'] == 'Blocking':
            blocking = blocking + 1

    assert(forwarding == 2), \
        "Port state has not updated correctly"

    assert(blocking == 0), \
        "Port state has not updated correctly"

    for sw_show in [sw1_show, sw2_show]:
        if sw_show == sw1_show:
            interface = 'lag' + sw1_lag_id
        if sw_show == sw2_show:
            interface = 'lag' + sw2_lag_id
        if sw_show['root'] == 'yes':
            root_show = sw_show
            ops_check_root_bridge_active_ports(interface, root_show)
        else:
            if (sw_show[interface]['role'] == 'Designated'):
                assert(sw_show[interface]['State'] == 'Forwarding'), \
                    "Port state has not updated correctly"
            elif (sw_show[interface]['role'] == 'Root'):
                assert(sw_show[interface]['State'] == 'Forwarding'), \
                    "Port state has not updated correctly"

    print("mstp lag test passed")
