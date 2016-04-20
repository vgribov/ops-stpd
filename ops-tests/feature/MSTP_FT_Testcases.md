# MSTP Test Cases
## Contents
- [MSTP Terminology](#mstp-terminology)
- [Sample MSTP Configuration](#sample-mstp-configuration)
- [Sample MSTP Show Commands](#sample-mstp-show-commands)
- [CIST Root Bridge Election](#cist-root-bridge-election)
- [CIST Root Bridge Election in multiple region](#cist-root-bridge-election-in-multiple-region)
- [MSTI Regional Root Bridge Election](#msti-regional-root-bridge-election)
- [Fault Tolerance in CIST](#fault-tolerance-in-cist)
- [References](#references)

##MSTP Terminology
This section aims to be a glossary of the different terms you will encounter in the following sections:
CIST   - Common Instance Spanning Tree
CLI     - Command Line Interface
IST     - Internal Spanning Tree
ICMP  - Internet Control Message Protocol
MSTI  - Multiple Spanning Tree Instance

## Sample MSTP Configuration
This section deals with the minimum set of the configurations to be done on the switch for the MSTP to be functional.

### Configuration for CIST
interface 1
no routing
no shutdown
interface 2
no routing
no shutdown
spanning-tree config-name mst
spanning-tree config-revision 1
spanning-tree

### Configuration for MSTI
vlan 10
no shutdown
vlan 20
no shutdown
interface 1
no routing
no shutdown
vlan trunk allowed 10
vlan trunk allowed 20
interface 2
no routing
no shutdown
vlan trunk allowed 10
vlan trunk allowed 20
spanning-tree config-name mst
spanning-tree config-revision 1
spanning-tree instance 1 vlan 10
spanning-tree instance 2 vlan 20
spanning-tree

## Sample MSTP Show Commands
Below is the sample output of Root Switch:
```
switch(config)# do show spanning-tree mst
#### MST0
Vlans mapped:  1-4095
Bridge         Address:48:0f:cf:af:81:dd    priority:32768
Root
Regional Root
Operational    Hello time(in seconds): 2  Forward delay(in seconds):15  Max-age(in seconds):20  txHoldCount(in pps): 6
Configured     Hello time(in seconds): 2  Forward delay(in seconds):15  Max-age(in seconds):20  txHoldCount(in pps): 6
Root           Address:48:0f:cf:af:81:dd  Priority:8
               Port:0                     Path cost:0
Regional Root  Address:48:0f:cf:af:81:dd  Priority:8
               Internal cost:0            Rem Hops:20

Port           Role           State      Cost       Priority   Type
-------------- -------------- ---------- ---------- ---------- ----------
1              Designated     Forwarding 20000      128        point_to_point
2              Designated     Forwarding 20000      128        point_to_point
```

Below is the sample output of Non root Switch:
```
switch(config)# do show spanning-tree mst
#### MST0
Vlans mapped:  1-4095
Bridge         Address:48:0f:cf:af:e1:a5    priority:32768
Operational    Hello time(in seconds): 2  Forward delay(in seconds):15  Max-age(in seconds):20  txHoldCount(in pps): 6
Configured     Hello time(in seconds): 2  Forward delay(in seconds):15  Max-age(in seconds):20  txHoldCount(in pps): 6
Root           Address:48:0f:cf:af:81:dd  Priority:8
               Port:1                     Path cost:0
Regional Root  Address:48:0f:cf:af:81:dd  Priority:8
               Internal cost:20000        Rem Hops:19

Port           Role           State      Cost       Priority   Type
-------------- -------------- ---------- ---------- ---------- ----------
1              Root           Forwarding 20000      128        point_to_point
2              Alternate      Blocking   20000      128        point_to_point

```

## CIST Root Bridge Election
#### Objective
This test case confirms that the CIST root is selected correctly in single region topology and port states and role update accordingly.
#### Requirements
- Physical Switch/Switch Test setup
- **FT File**: test_stp_cist_single_region_root_elect.py

#### Setup
##### Topology diagram
```ditaa
                         +----------------+
                         |                |
       +---------------INT1     S1       INT2--------------+
       |                 |                |                |
       |                 +----------------+                |
       |                                                  ---
       |                                                   |
+-----INT1-------+                                +------INT1-------+
|                |                                |                 |
|     S2        INT2----------------------------INT2       S3       |
|                |                                |                 |
+----------------+                                +-----------------+


---  Blocking  link
```

#### Description
1. Setup the topology as show and enable the interfaces and make it L2 interface.
2. Active spanning tree on all the switch and wait till the convergence time for loop solving. Topology should be built and become stable in about '2xHello Time' period.
3. Use CLI commands for configuration changes and for displaying spanning tree status information. Every topology should be built and become stable in about '2xHello Time' period.
4. In this case switch with lowest MAC address becomes the CIST root.
5. One of the port in switch with highest MAC address becomes blocking and remaining ports of all the switch become forwarding.

### CIST Root Bridge Election in multiple region
#### Objective
This test case confirms that the CIST root and regional root is selected correctly in multi region topology and port states and role update.
#### Requirements
- Physical Switch/Switch Test setup
- **FT File**: test_stp_cist_multi_region_root_elect.py

#### Setup
##### Topology diagram
```ditaa
+------------------------+  +-------------------------------------------------+
|                        |  | +----------------+                              |
|                        |  | |                |                              |
|           +-------------- -INT1     S1      INT2--------------+             |
|           |            |  | |                |                |             |
|           |            |  | +----------------+                |             |
|           |            |  |                                  ---            |
|           |            |  |                                   |             |
|    +----INT1--------+  |  |                          +------INT1-------+    |
|    |                |  |  |                          |                 |    |
|    |     S2       INT2------------------------------INT2      S3       |    |
|    |                |  |  |                          |                 |    |
|    +----------------+  |  |                          +-----------------+    |
|                        |  |                                                 |
|                        |  |                                                 |
|   Region One           |  |                 Region Two                      |
+------------------------+  +-------------------------------------------------+

---  Blocking  link

```

#### Description
1. Setup the topology as show and enable the interfaces and make it L2 interface.
2. Configure S1 and S3 in mstp region One and configure S2 in mstp region 2.
3. Active spanning tree on all the switch and wait till the convergence time for loop solving. Topology should be built and become stable in about '2xHello Time' period.
4. Consider S1 with lowest MAC address, and S1 becomes the CIST root of all the switchs.
5. Now S2 becomes the regional root of Region One and s1 becomes the regional root of region Two.

### MSTI Regional Root Bridge Election
#### Objective
This test case confirms that the CIST root and MSTI root and regional root are elected correctly and port state and role update correctly.
#### Requirements
- Physical Switch/Switch Test setup
- **FT File**: test_stp_mist_root_elect.py

#### Setup
##### Topology diagram
```ditaa
                         +----------------+
                         |                |
       +--------------+INT1     S1       INT2+-------------+
       |                 |  Priority:8    |                |
       |                 +----------------+                |          MST Region One: CIST
       |                                                   |
       +                                                   +
+----+INT1+------+                                +-----+INT1+------+
|                |                                |                 |
|     S2        INT2+--|------------------------+INT2       S3      |
| Priority:9     |                                |   Priority:8    |
+----------------+                                +-----------------+

                         +----------------+
                         |                |
       +--------------+INT1     S1       INT2+-------------+
       |                 |   Priority:8   |                |           MST Region One: MST1
       |                 +----------------+                |
       |                                                  ---
       +                                                   +
+----+INT1+------+                                +-----+INT1+------+
|                +                                +                 |
|     S2        INT2+--------------------------+INT2       S3       |
| Priority:7     +                                +   Priority:8    |
+----------------+                                +-----------------+

                         +----------------+
                         |                |
       +--------------+INT1     S1       INT2+-------------+
       |                 |  Priority:8    |                |           MST Region One: MST2
      ---                +----------------+                |
       |                                                   |
       +                                                   +
+----+INT1+------+                                +-----+INT1+------+
|                +                                +                 |
|     S2        INT2+--------------------------+INT2       S3       |
|  Priority:8    +                                +   Priority:7    |
+----------------+                                +-----------------+

---  Blocking  link
```

#### Description
1. Setup the topology as show and enable the interfaces and make it L2 interface.
2. Configure Bridge Priority value for each MSTI as shown in topology.
3. Verify that within MST Region One the active topology built by each spanning tree instance (the IST and MSTIs) matches to what is shown in the topology, i.e. each instance has different Regional Root switch.
4. In each instance the switch configured with lowest priority becomes the regional root.

### Fault Tolerance in CIST
#### Objective
This test case confirms if the active link goes down, the spanning tree topology recovers and continues forwarding data traffic.
#### Requirements
- Physical Switch/Switch Test setup
- **FT File**: test_stp_cist_fault_tolerence.py

#### Setup
##### Topology diagram
```ditaa
+-------------------------------------------+
|                                           |
|                     Region One            |
|                                           |
|  +-----------------------+                |     +-----------+
|  |      S1               |                |     |           |
|  |                       |                |     |           |
|  |                      6<---------------------->   host1   |
|  |                       |                |     |           |
|  |  1   2  3  4  5       |                |     +-----------+
|  +--^---^--^--^--^-------+                |
|     |   |  |  |  |                        |
|     |   |  |  |  |                        |
+-------------------------------------------+
      |   |  |  |  |
      |   |  |  |  |
      |   |  |  |  |
      |   |  |  |  |
      |  ------------
      |   |  |  |  |
      |   |  |  |  |
+---------------------------------------------+
|     |   |  |  |  |                          |
|     |   |  |  |  |      Region Two          |
|     |   |  |  |  |                          |
|   +-v---v--v--v--v--------+                 |    +------------+
|   | 1   2  3  4  5        |                 |    |            |
|   |                       |                 |    |            |
|   |                      6<---------------------->   host2    |
|   |                       |                 |    |            |
|   |      s2               |                 |    +------------+
|   +-----------------------+                 |
|                                             |
|                                             |
+---------------------------------------------+

---  Blocking  link
```

#### Description
1. Setup the topology as show and enable the interfaces and make it L2 interface.
2. Configure switches and connect the switches ports as shown in the topology . Verify that port roles and states match to that shown in topology.
3. Start 'ping' Host 1 <-> Host 2. Verify that on both hosts each ICMP Echo Request packet is echoed back via an ICMP Echo Response packet, i.e. connectivity between hosts is established
4. Disconnect links between port 1 os S1 and port 1 of S2. Verify that 'ping' still succeeds and connectivity recovery time does not exceeds the 2 * Hello Time interval. During links disconnection check that all ports states and roles matches to what is expected.

##References
* [MSTP CLI Document](/documents/user/mstp_cli)
* [MSTP User guide](/documents/user/mstp_user_guide)
* [MSTP Design](/documents/user/mstpd_design)
