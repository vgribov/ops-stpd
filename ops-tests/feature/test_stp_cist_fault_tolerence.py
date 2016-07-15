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
OpenSwitch Test for simple ping between nodes.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from time import sleep
from pytest import mark


TOPOLOGY = """
# +-------+     +-------+     +-------+     +-------+
# |       |     |       |     |       |     |       |
# |       |     |       <----->       |     |       |
# |  hs1  <----->  sw1  <----->  sw2  <----->  hs2  |
# |       |     |       <----->       |     |       |
# |       |     |       |     |       |     |       |
# +-------+     +-------+     +-------+     +-------+

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=openswitch name="Switch 2"] sw2
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2

# Links
sw1:1 -- sw2:1
sw1:2 -- sw2:2
sw1:3 -- sw2:3
hs1:1 -- sw1:4
hs2:1 -- sw2:4
"""

HELLO_TIME = 2
REGION_1 = "spanning"
REVISION = 8


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


@mark.platform_incompatible(['docker'])
def test_stp_cist_falut_tolerance(topology):
    """
    Set network addresses and static routes between nodes and ping h2 from h1.
    """
    sw1 = topology.get('sw1')
    sw2 = topology.get('sw2')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert sw1 is not None
    assert sw2 is not None
    assert hs1 is not None
    assert hs2 is not None

    sw1int1 = sw1.ports['1']
    sw1int2 = sw1.ports['2']
    sw1int3 = sw1.ports['3']
    sw1int4 = sw1.ports['4']

    sw2int1 = sw2.ports['1']
    sw2int2 = sw2.ports['2']
    sw2int3 = sw2.ports['3']
    sw2int4 = sw2.ports['4']

    # Configure IP and bring UP host 1 interfaces
    hs1.libs.ip.interface('1', addr='10.0.0.1/24', up=True)

    # Configure IP and bring UP host 2 interfaces
    hs2.libs.ip.interface('1', addr='10.0.0.2/24', up=True)

    # Bring UP switch 1 interfaces
    for sw1int in ['1', '2', '3', '4']:
        enable_l2port(sw1, sw1int)

    # Bring UP switch 2 interfaces
    for sw2int in ['1', '2', '3', '4']:
        enable_l2port(sw2, sw2int)

    # Wait until interfaces are up
    for switch, portlbl in [(sw1, sw1int1), (sw1, sw1int2),
                            (sw1, sw1int3), (sw1, sw1int4)]:
        wait_until_interface_up(switch, portlbl)

    for switch, portlbl in [(sw2, sw2int1), (sw2, sw2int2),
                            (sw2, sw2int3), (sw2, sw2int4)]:
        wait_until_interface_up(switch, portlbl)

    for sw in [sw1, sw2]:
        config_mstp_region(sw, REGION_1, REVISION, HELLO_TIME)
        with sw.libs.vtysh.Configure() as ctx:
            ctx.spanning_tree()

    sleep(HELLO_TIME * 5)

    ping = hs1.libs.ping.ping(10, '10.0.0.2')
    assert(ping['transmitted'] >= 7 and ping['received'] >= 7), \
        "Ping between host failed after convergence"

    for sw1int, sw2int in [('1', '1'),
                           ('2', '2')]:
        with sw1.libs.vtysh.ConfigInterface(sw1int) as ctx:
            ctx.shutdown()

        with sw2.libs.vtysh.ConfigInterface(sw2int) as ctx:
            ctx.shutdown()

        sleep(HELLO_TIME * 5)

        ping = hs1.libs.ping.ping(10, '10.0.0.2')
        assert(ping['transmitted'] >= 7 and ping['received'] >= 7), \
            "Ping between host failed after convergence"

    for sw in [sw1, sw2]:
        with sw.libs.vtysh.Configure() as ctx:
            ctx.no_spanning_tree_config_name()
            ctx.no_spanning_tree_config_revision()
            ctx.no_spanning_tree_hello_time()
            ctx.no_spanning_tree()
