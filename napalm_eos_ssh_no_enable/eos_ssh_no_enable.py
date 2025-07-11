
"""
Napalm driver for Arista EOS using SSH and a read-only account.

Read napalm.readthedocs.org for more information.
"""

# std libs
import re
import time
import ipaddress
import json
import socket
from collections import defaultdict

# third party libs
import pyeapi
from netmiko.arista.arista import AristaSSH
from typing import Dict

# NAPALM base
import napalm.base.helpers
from napalm.base.netmiko_helpers import netmiko_args
from napalm.base.base import NetworkDriver, models
from napalm.base.utils import string_parsers
from napalm.base.exceptions import (
    CommandErrorException,
)
from napalm_eos_ssh_no_enable.constants import LLDP_CAPAB_TRANFORM_TABLE


class CustomAristaSSH(AristaSSH):
    def session_preparation(self):
        self.set_base_prompt()

class EOS_SSH_NO_ENABLE_DRIVER(NetworkDriver):
    """Napalm driver for Arista EOS."""

    SUPPORTED_OC_MODELS = []

    HEREDOC_COMMANDS = [
        ("banner login", 1),
        ("banner motd", 1),
        ("comment", 1),
        ("protocol https certificate", 2),
    ]

    _RE_BGP_INFO = re.compile(
        r"BGP neighbor is (?P<neighbor>.*?), remote AS (?P<as>.*?), .*"
    )  # noqa
    _RE_BGP_RID_INFO = re.compile(
        r".*BGP version 4, remote router ID (?P<rid>.*?), VRF (?P<vrf>.*?)$"
    )  # noqa
    _RE_BGP_DESC = re.compile(r"\s+Description: (?P<description>.*?)$")
    _RE_BGP_LOCAL = re.compile(r"Local AS is (?P<as>.*?),.*")
    _RE_BGP_PREFIX = re.compile(
        r"(\s*?)(?P<af>IPv[46]) (Unicast|6PE):\s*(?P<sent>\d+)\s*(?P<received>\d+)"
    )  # noqa
    _RE_SNMP_COMM = re.compile(
        r"""^snmp-server\s+community\s+(?P<community>\S+)
                                (\s+view\s+(?P<view>\S+))?(\s+(?P<access>ro|rw)?)
                                (\s+ipv6\s+(?P<v6_acl>\S+))?(\s+(?P<v4_acl>\S+))?$""",
        re.VERBOSE,
    )

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialize EOS Driver.

        Optional args:
            * enable_password (True/False): Enable password for privilege elevation
            * eos_autoComplete (True/False): Allow for shortening of cli commands
            * transport (string): transport, eos_transport is a fallback for compatibility.
                - ssh (uses Netmiko)

        """
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.platform = "eos"
        self.profile = [self.platform]
        self.optional_args = optional_args or {}
        self.eos_autoComplete = self.optional_args.pop("eos_autoComplete", None)
        self.lock_disable = self.optional_args.pop("lock_disable", False)
        self._process_optional_args(self.optional_args)
        self.transport = "ssh"
    def _process_optional_args(self, optional_args):
        self.transport_class = None
        self.netmiko_optional_args = netmiko_args(optional_args)

    def open(self):
        host_data = {
            'device_type': 'arista_eos',
            'host': self.hostname,
            'username': self.username,
            'password': self.password,
            'timeout': self.timeout,
            'session_log': 'session_log.txt',  # Optional: Log the session for debugging
        }
        self.device = CustomAristaSSH(**host_data)
        self.device.session_preparation()

    def close(self):
        if self.device:
            self.device.disconnect()



    def close(self):
        if self.device:
            self.device.disconnect()


    def is_alive(self):
        if self.transport == "ssh":
            null = chr(0)
            if self.device is None:
                return {"is_alive": False}
            try:
                # Try sending ASCII null byte to maintain the connection alive
                self.device.write_channel(null)
                return {"is_alive": self.device.remote_conn.transport.is_active()}
            except (socket.error, EOFError):
                # If unable to send, we can tell for sure that the connection is unusable
                return {"is_alive": False}

        if hasattr(self.device.connection, "is_alive") and callable(
            self.device.connection.is_alive
        ):
            return self.device.connection.is_alive()
        return {"is_alive": True}  # always true as eAPI is HTTP-based

    def _run_commands(self, commands, **kwargs):
        ret = []
        for command in commands:
            if kwargs.get("encoding") == "text":
                cmd_output =  self.device.send_command_timing(command, read_timeout=60).replace(
                    "% Invalid input", ""
                )
                ret.append({"output": cmd_output})
                continue
            cmd_pipe = command + " | json | no-more"
            cmd_txt = self.device.send_command_timing(cmd_pipe, read_timeout=60)
            try:
                cmd_json = json.loads(cmd_txt)
            except json.decoder.JSONDecodeError:
                cmd_json = {}
            ret.append(cmd_json)
        return ret





    @staticmethod
    def _multiline_convert(config, start="banner login", end="EOF", depth=1):
        """Converts running-config HEREDOC into EAPI JSON dict"""
        ret = list(config)  # Don't modify list in-place
        try:
            s = ret.index(start)
            e = s
            while depth:
                e = ret.index(end, e + 1)
                depth = depth - 1
        except ValueError:  # Couldn't find end, abort
            return ret
        ret[s] = {"cmd": ret[s], "input": "\n".join(ret[s + 1 : e])}
        del ret[s + 1 : e + 1]

        return ret

    @staticmethod
    def _mode_comment_convert(commands):
        """
        EOS has the concept of multi-line mode comments, shown in the running-config
        as being inside a config stanza (router bgp, ACL definition, etc) and beginning
        with the normal level of spaces and '!!', followed by comments.

        Unfortunately, pyeapi does not accept mode comments in this format, and have to be
        converted to a specific type of pyeapi call that accepts multi-line input

        Copy the config list into a new return list, converting consecutive lines starting with
        "!!" into a single multiline comment command

        :param commands: List of commands to be sent to pyeapi
        :return: Converted list of commands to be sent to pyeapi
        """

        ret = []
        comment_count = 0
        for idx, element in enumerate(commands):
            # Check first for stringiness, as we may have dicts in the command list already
            if isinstance(element, str) and element.startswith("!!"):
                comment_count += 1
                continue
            else:
                if comment_count > 0:
                    # append the previous comment
                    ret.append(
                        {
                            "cmd": "comment",
                            "input": "\n".join(
                                map(
                                    lambda s: s.lstrip("! "),
                                    commands[idx - comment_count : idx],
                                )
                            ),
                        }
                    )
                    comment_count = 0
                ret.append(element)

        return ret

    def get_facts(self):
        """Implementation of NAPALM method get_facts."""
        commands = ["show version", "show hostname", "show interfaces"]

        result = self._run_commands(commands)

        version = result[0]
        hostname = result[1]
        interfaces_dict = result[2]["interfaces"]

        uptime = time.time() - version["bootupTimestamp"]

        interfaces = [i for i in interfaces_dict.keys() if "." not in i]
        interfaces = string_parsers.sorted_nicely(interfaces)

        return {
            "hostname": hostname["hostname"],
            "fqdn": hostname["fqdn"],
            "vendor": "Arista",
            "model": version["modelName"],
            "serial_number": version["serialNumber"],
            "os_version": version["internalVersion"],
            "uptime": float(uptime),
            "interface_list": interfaces,
        }

    def get_interfaces(self):
        commands = ["show interfaces"]
        output = self._run_commands(commands)[0]

        interfaces = {}

        for interface, values in output["interfaces"].items():
            interfaces[interface] = {}

            if values["lineProtocolStatus"] == "up":
                interfaces[interface]["is_up"] = True
                interfaces[interface]["is_enabled"] = True
            else:
                interfaces[interface]["is_up"] = False
                if values["interfaceStatus"] == "disabled":
                    interfaces[interface]["is_enabled"] = False
                else:
                    interfaces[interface]["is_enabled"] = True

            interfaces[interface]["description"] = values["description"]

            interfaces[interface]["last_flapped"] = values.pop(
                "lastStatusChangeTimestamp", -1.0
            )

            interfaces[interface]["mtu"] = int(values["mtu"])
            #            interfaces[interface]["speed"] = float(values["bandwidth"] * 1e-6)
            interfaces[interface]["speed"] = float(values["bandwidth"] / 1000000.0)
            interfaces[interface]["mac_address"] = napalm.base.helpers.convert(
                napalm.base.helpers.mac, values.pop("physicalAddress", "")
            )

        return interfaces

    def get_lldp_neighbors(self):
        commands = ["show lldp neighbors"]
        output = self._run_commands(commands)[0]["lldpNeighbors"]

        lldp = {}

        for n in output:
            if n["port"] not in lldp.keys():
                lldp[n["port"]] = []

            lldp[n["port"]].append(
                {"hostname": n["neighborDevice"], "port": n["neighborPort"]}
            )

        return lldp

    def get_interfaces_counters(self):
        commands = ["show interfaces"]
        output = self._run_commands(commands)
        interface_counters = defaultdict(dict)
        for interface, data in output[0]["interfaces"].items():
            if data["hardware"] == "subinterface":
                # Subinterfaces will never have counters so no point in parsing them at all
                continue
            counters = data.get("interfaceCounters", {})
            interface_counters[interface].update(
                tx_octets=counters.get("outOctets", -1),
                rx_octets=counters.get("inOctets", -1),
                tx_unicast_packets=counters.get("outUcastPkts", -1),
                rx_unicast_packets=counters.get("inUcastPkts", -1),
                tx_multicast_packets=counters.get("outMulticastPkts", -1),
                rx_multicast_packets=counters.get("inMulticastPkts", -1),
                tx_broadcast_packets=counters.get("outBroadcastPkts", -1),
                rx_broadcast_packets=counters.get("inBroadcastPkts", -1),
                tx_discards=counters.get("outDiscards", -1),
                rx_discards=counters.get("inDiscards", -1),
                tx_errors=counters.get("totalOutErrors", -1),
                rx_errors=counters.get("totalInErrors", -1),
            )
        return interface_counters

    def get_bgp_neighbors(self) -> Dict[str, models.BGPStateNeighborsPerVRFDict]:
        cmd_outputs = self._run_commands(
            [
                "show ip bgp summary vrf all",
                "show ipv6 bgp summary vrf all",
                "show ip bgp neighbors vrf all",
                "show ipv6 bgp peers vrf all",
            ],
            encoding="json",
        )

        bgp_counters = defaultdict(
            lambda: models.BGPStateNeighborsPerVRFDict(
                peers=models.BGPStateNeighborDict()  # type: ignore
            )  # type: ignore
        )  # type: ignore
        # Iterate IPv4 and IPv6 neighbor details
        for cmd in cmd_outputs[2:]:
            for vrf_name, vrf_data in cmd["vrfs"].items():
                vrf = bgp_counters[vrf_name]
                for peer in vrf_data["peerList"]:
                    peer_ip = napalm.base.helpers.ip(peer["peerAddress"])
                    v4_summary = cmd_outputs[0]["vrfs"][vrf_name]["peers"].get(
                        peer_ip, {}
                    )
                    v6_summary = cmd_outputs[1]["vrfs"][vrf_name]["peers"].get(
                        peer_ip, {}
                    )
                    local_as = napalm.base.helpers.as_number(peer["localAsn"])
                    remote_as = napalm.base.helpers.as_number(peer["asn"])
                    remote_id = napalm.base.helpers.ip(peer["routerId"])
                    if peer["state"] == "Idle":
                        is_enabled = (
                            True
                            if peer["idleReason"] != "Administratively shut down"
                            else False
                        )
                    else:
                        is_enabled = True
                    is_up = peer["state"] == "Established"
                    description = peer.get("description", "")
                    uptime = int(peer.get("establishedTime", -1))
                    v4: models.BGPStateAddressFamilyDict = {
                        "received_prefixes": peer["prefixesReceived"],
                        "accepted_prefixes": (
                            v4_summary["prefixAccepted"] if v4_summary else 0
                        ),
                        "sent_prefixes": peer["prefixesSent"],
                    }
                    v6: models.BGPStateAddressFamilyDict = {
                        "received_prefixes": peer["v6PrefixesReceived"],
                        "accepted_prefixes": (
                            v6_summary["prefixAccepted"] if v6_summary else 0
                        ),
                        "sent_prefixes": peer["v6PrefixesSent"],
                    }
                    peer_data: models.BGPStateNeighborDict = {
                        "local_as": local_as,
                        "remote_as": remote_as,
                        "remote_id": remote_id,
                        "is_up": is_up,
                        "is_enabled": is_enabled,
                        "description": description,
                        "uptime": uptime,
                        "address_family": {
                            "ipv4": v4,
                            "ipv6": v6,
                        },
                    }
                    vrf["peers"][peer_ip] = peer_data

        # Iterate IPv4 and IPv6 summary details for router-id assignment
        for cmd in cmd_outputs[:2]:
            for vrf_name, vrf_data in cmd["vrfs"].items():
                bgp_counters[vrf_name]["router_id"] = napalm.base.helpers.ip(
                    vrf_data["routerId"]
                )

        if "default" in bgp_counters:
            bgp_counters["global"] = bgp_counters.pop("default")
        return dict(bgp_counters)

    def get_environment(self):
        def extract_temperature_data(data):
            for s in data:
                temp = s["currentTemperature"] if "currentTemperature" in s else 0.0
                name = s["name"]
                values = {
                    "temperature": temp,
                    "is_alert": temp > s["overheatThreshold"],
                    "is_critical": temp > s["criticalThreshold"],
                }
                yield name, values

        sh_version_out = self._run_commands(["show version"])
        is_veos = sh_version_out[0]["modelName"].lower() in ["veos", "ceoslab"]
        commands = [
            "show system environment cooling",
            "show system environment temperature",
        ]
        if not is_veos:
            commands.append("show system environment power")
            fans_output, temp_output, power_output = self._run_commands(commands)
        else:
            fans_output, temp_output = self._run_commands(commands)
        environment_counters = {"fans": {}, "temperature": {}, "power": {}, "cpu": {}}
        cpu_output = self._run_commands(["show processes top once"], encoding="text")[0]["output"]
        
        for slot in fans_output["fanTraySlots"]:
            environment_counters["fans"][slot["label"]] = {
                "status": slot["status"] == "ok"
            }
        # First check FRU's
        for fru_type in ["cardSlots", "powerSupplySlots"]:
            for fru in temp_output[fru_type]:
                t = {
                    name: value
                    for name, value in extract_temperature_data(fru["tempSensors"])
                }
                environment_counters["temperature"].update(t)
        # On board sensors
        parsed = {n: v for n, v in extract_temperature_data(temp_output["tempSensors"])}
        environment_counters["temperature"].update(parsed)
        if not is_veos:
            for psu, data in power_output["powerSupplies"].items():
                environment_counters["power"][psu] = {
                    "status": data.get("state", "ok") == "ok",
                    "capacity": data.get("capacity", -1.0),
                    "output": data.get("outputPower", -1.0),
                }
        cpu_lines = cpu_output.splitlines()
        # Matches either of
        # Cpu(s):  5.2%us,  1.4%sy,  0.0%ni, 92.2%id,  0.6%wa,  0.3%hi,  0.4%si,  0.0%st ( 4.16 > )
        # %Cpu(s):  4.2 us,  0.9 sy,  0.0 ni, 94.6 id,  0.0 wa,  0.1 hi,  0.2 si,  0.0 st ( 4.16 < )
        m = re.match(r".*ni, (?P<idle>\d+\.\d+) id.*", cpu_lines[3])
        environment_counters["cpu"][0] = {
            "%usage": round(100 - float(m.group("idle")), 1)
        }
        return environment_counters

    def _transform_lldp_capab(self, capabilities):
        return sorted([LLDP_CAPAB_TRANFORM_TABLE[c.lower()] for c in capabilities])

    def get_lldp_neighbors_detail(self, interface=""):
        lldp_neighbors_out = {}

        filters = []
        if interface:
            filters.append(interface)

        commands = [
            "show lldp neighbors {filters} detail".format(filters=" ".join(filters))
        ]

        lldp_neighbors_in = self._run_commands(commands)[0].get("lldpNeighbors", {})

        for interface in lldp_neighbors_in:
            interface_neighbors = lldp_neighbors_in.get(interface).get(
                "lldpNeighborInfo", {}
            )
            if not interface_neighbors:
                # in case of empty infos
                continue

            # it is provided a list of neighbors per interface
            for neighbor in interface_neighbors:
                if interface not in lldp_neighbors_out.keys():
                    lldp_neighbors_out[interface] = []
                capabilities = neighbor.get("systemCapabilities", {})
                available_capabilities = self._transform_lldp_capab(capabilities.keys())
                enabled_capabilities = self._transform_lldp_capab(
                    [capab for capab, enabled in capabilities.items() if enabled]
                )
                remote_chassis_id = neighbor.get("chassisId", "")
                if neighbor.get("chassisIdType", "") == "macAddress":
                    remote_chassis_id = napalm.base.helpers.mac(remote_chassis_id)
                neighbor_interface_info = neighbor.get("neighborInterfaceInfo", {})
                lldp_neighbors_out[interface].append(
                    {
                        "parent_interface": interface,  # no parent interfaces
                        "remote_port": neighbor_interface_info.get(
                            "interfaceId", ""
                        ).replace('"', ""),
                        "remote_port_description": neighbor_interface_info.get(
                            "interfaceDescription", ""
                        ),
                        "remote_system_name": neighbor.get("systemName", ""),
                        "remote_system_description": neighbor.get(
                            "systemDescription", ""
                        ),
                        "remote_chassis_id": remote_chassis_id,
                        "remote_system_capab": available_capabilities,
                        "remote_system_enable_capab": enabled_capabilities,
                    }
                )
        return lldp_neighbors_out

    def cli(self, commands, encoding="text"):
        if encoding not in ("text", "json"):
            raise NotImplementedError("%s is not a supported encoding" % encoding)
        cli_output = {}

        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            try:
                result = self._run_commands([command], encoding=encoding)
                if encoding == "text":
                    cli_output[str(command)] = result[0]["output"]
                else:
                    cli_output[str(command)] = result[0]
                # not quite fair to not exploit rum_commands
                # but at least can have better control to point to wrong command in case of failure
            except pyeapi.eapilib.CommandError:
                # for sure this command failed
                cli_output[str(command)] = 'Invalid command: "{cmd}"'.format(
                    cmd=command
                )
                raise CommandErrorException(str(cli_output))
            except Exception as e:
                # something bad happened
                msg = 'Unable to execute command "{cmd}": {err}'.format(
                    cmd=command, err=e
                )
                cli_output[str(command)] = msg
                raise CommandErrorException(str(cli_output))

        return cli_output

    def get_bgp_config(self, group="", neighbor=""):
        """Implementation of NAPALM method get_bgp_config."""
        _GROUP_FIELD_MAP_ = {
            "type": "type",
            "multipath": "multipath",
            "apply-groups": "apply_groups",
            "remove-private-as": "remove_private_as",
            "ebgp-multihop": "multihop_ttl",
            "remote-as": "remote_as",
            "local-v4-addr": "local_address",
            "local-v6-addr": "local_address",
            "local-as": "local_as",
            "next-hop-self": "nhs",
            "description": "description",
            "import-policy": "import_policy",
            "export-policy": "export_policy",
        }

        _PEER_FIELD_MAP_ = {
            "description": "description",
            "remote-as": "remote_as",
            "local-v4-addr": "local_address",
            "local-v6-addr": "local_address",
            "local-as": "local_as",
            "next-hop-self": "nhs",
            "route-reflector-client": "route_reflector_client",
            "import-policy": "import_policy",
            "export-policy": "export_policy",
            "passwd": "authentication_key",
        }

        _PROPERTY_FIELD_MAP_ = _GROUP_FIELD_MAP_.copy()
        _PROPERTY_FIELD_MAP_.update(_PEER_FIELD_MAP_)

        _PROPERTY_TYPE_MAP_ = {
            # used to determine the default value
            # and cast the values
            "remote-as": int,
            "ebgp-multihop": int,
            "local-v4-addr": str,
            "local-v6-addr": str,
            "local-as": int,
            "remove-private-as": bool,
            "next-hop-self": bool,
            "description": str,
            "route-reflector-client": bool,
            "password": str,
            "route-map": str,
            "apply-groups": list,
            "type": str,
            "import-policy": str,
            "export-policy": str,
            "multipath": bool,
        }

        _DATATYPE_DEFAULT_ = {str: "", int: 0, bool: False, list: []}

        def default_group_dict(local_as):
            group_dict = {}
            group_dict.update(
                {
                    key: _DATATYPE_DEFAULT_.get(_PROPERTY_TYPE_MAP_.get(prop))
                    for prop, key in _GROUP_FIELD_MAP_.items()
                }
            )
            group_dict.update(
                {"prefix_limit": {}, "neighbors": {}, "local_as": local_as}
            )  # few more default values
            return group_dict

        def default_neighbor_dict(local_as, group_dict):
            neighbor_dict = {}
            neighbor_dict.update(
                {
                    key: _DATATYPE_DEFAULT_.get(_PROPERTY_TYPE_MAP_.get(prop))
                    for prop, key in _PEER_FIELD_MAP_.items()
                }
            )  # populating with default values
            neighbor_dict.update(
                {"prefix_limit": {}, "local_as": local_as, "authentication_key": ""}
            )  # few more default values
            neighbor_dict.update(
                {
                    key: group_dict.get(key)
                    for key in _GROUP_FIELD_MAP_.values()
                    if key in group_dict and key in _PEER_FIELD_MAP_.values()
                }
            )  # copy in values from group dict if present
            return neighbor_dict

        def parse_options(options, default_value=False):
            if not options:
                return {}

            config_property = options[0]
            field_name = _PROPERTY_FIELD_MAP_.get(config_property)
            field_type = _PROPERTY_TYPE_MAP_.get(config_property)
            field_value = _DATATYPE_DEFAULT_.get(field_type)  # to get the default value

            if not field_type:
                # no type specified at all => return empty dictionary
                return {}

            if not default_value:
                if len(options) > 1:
                    field_value = napalm.base.helpers.convert(
                        field_type, options[1], _DATATYPE_DEFAULT_.get(field_type)
                    )
                else:
                    if field_type is bool:
                        field_value = True
            if field_name is not None:
                return {field_name: field_value}
            elif config_property in ["route-map", "password"]:
                # do not respect the pattern neighbor [IP_ADDRESS] [PROPERTY] [VALUE]
                # or need special output (e.g.: maximum-routes)
                if config_property == "password":
                    return {"authentication_key": str(options[2])}
                    # returns the MD5 password
                if config_property == "route-map":
                    direction = None
                    if len(options) == 3:
                        direction = options[2]
                        field_value = field_type(options[1])  # the name of the policy
                    elif len(options) == 2:
                        direction = options[1]
                    if direction == "in":
                        field_name = "import_policy"
                    else:
                        field_name = "export_policy"
                    return {field_name: field_value}

            return {}

        bgp_config = {}

        commands = ["show running-config | section router bgp"]
        bgp_conf = self._run_commands(commands, encoding="text")[0].get(
            "output", "\n\n"
        )
        bgp_conf_lines = bgp_conf.splitlines()

        bgp_neighbors = {}

        if not group:
            neighbor = ""  # noqa

        local_as = 0
        bgp_neighbors = {}
        for bgp_conf_line in bgp_conf_lines:
            default_value = False
            bgp_conf_line = bgp_conf_line.strip()
            if bgp_conf_line.startswith("router bgp"):
                local_as = napalm.base.helpers.as_number(
                    (bgp_conf_line.replace("router bgp", "").strip())
                )
                continue
            if not (
                bgp_conf_line.startswith("neighbor")
                or bgp_conf_line.startswith("no neighbor")
            ):
                continue
            if bgp_conf_line.startswith("no"):
                default_value = True
            bgp_conf_line = bgp_conf_line.replace("no neighbor ", "").replace(
                "neighbor ", ""
            )
            bgp_conf_line_details = bgp_conf_line.split()
            group_or_neighbor = str(bgp_conf_line_details[0])
            options = bgp_conf_line_details[1:]
            try:
                # will try to parse the neighbor name
                # which sometimes is the IP Address of the neigbor
                # or the name of the BGP group
                ipaddress.ip_address(group_or_neighbor)
                # if passes the test => it is an IP Address, thus a Neighbor!
                peer_address = group_or_neighbor
                group_name = None
                if options[0] == "peer-group":
                    group_name = options[1]
                # EOS > 4.23.0 only supports the new syntax
                # https://www.arista.com/en/support/advisories-notices/fieldnotices/7097-field-notice-39
                elif options[0] == "peer" and options[1] == "group":
                    group_name = options[2]
                if peer_address not in bgp_neighbors:
                    bgp_neighbors[peer_address] = default_neighbor_dict(
                        local_as, bgp_config.get(group_name, {})
                    )

                if group_name:
                    bgp_neighbors[peer_address]["__group"] = group_name

                # in the config, neighbor details are lister after
                # the group is specified for the neighbor:
                #
                # neighbor 192.168.172.36 peer-group 4-public-anycast-peers
                # neighbor 192.168.172.36 remote-as 12392
                # neighbor 192.168.172.36 maximum-routes 200
                #
                # because the lines are parsed sequentially
                # can use the last group detected
                # that way we avoid one more loop to
                # match the neighbors with the group they belong to
                # directly will apend the neighbor in the neighbor list of the group at the end

                bgp_neighbors[peer_address].update(
                    parse_options(options, default_value)
                )
            except ValueError:
                # exception trying to parse group name
                # group_or_neighbor represents the name of the group
                group_name = group_or_neighbor
                if group and group_name != group:
                    continue
                if group_name not in bgp_config.keys():
                    bgp_config[group_name] = default_group_dict(local_as)
                bgp_config[group_name].update(parse_options(options, default_value))

        bgp_config["_"] = default_group_dict(local_as)

        for peer, peer_details in bgp_neighbors.items():
            peer_group = peer_details.pop("__group", None)
            if not peer_group:
                peer_group = "_"
            if peer_group not in bgp_config:
                bgp_config[peer_group] = default_group_dict(local_as)
            bgp_config[peer_group]["neighbors"][peer] = peer_details

        [
            v.pop("nhs", None) for v in bgp_config.values()
        ]  # remove NHS from group-level dictionary

        if local_as == 0:
            # BGP not running
            return {}

        return bgp_config

    def get_arp_table(self, vrf=""):
        arp_table = []

        try:
            commands = ["show arp vrf all"]
            ipv4_neighbors = [
                neighbor
                for k, v in self._run_commands(commands)[0].get("vrfs").items()
                if not vrf or k == vrf
                for neighbor in v.get("ipV4Neighbors", [])
            ]
        except pyeapi.eapilib.CommandError:
            return []

        for neighbor in ipv4_neighbors:
            interface = str(neighbor.get("interface"))
            mac_raw = neighbor.get("hwAddress")
            ip = str(neighbor.get("address"))
            age = float(neighbor.get("age", -1.0))
            arp_table.append(
                {
                    "interface": interface,
                    "mac": napalm.base.helpers.mac(mac_raw),
                    "ip": napalm.base.helpers.ip(ip),
                    "age": age,
                }
            )

        return arp_table

    def get_ntp_servers(self):
        result = {}

        commands = ["show running-config | section ntp"]

        raw_ntp_config = (
            self._run_commands(commands, encoding="text")[0]
            .get("output", "")
            .splitlines()
        )

        for server in raw_ntp_config:
            details = {
                "port": 123,
                "version": 4,
                "association_type": "SERVER",
                "iburst": False,
                "prefer": False,
                "network_instance": "default",
                "source_address": "",
                "key_id": -1,
            }
            tokens = server.split()
            if tokens[0] != "ntp":
                continue
            if tokens[2] == "vrf":
                details["network_instance"] = tokens[3]
                server_ip = details["address"] = tokens[4]
                idx = 5
            else:
                server_ip = details["address"] = tokens[2]
                idx = 3
            try:
                parsed_address = napalm.base.helpers.ipaddress.ip_address(server_ip)
                family = parsed_address.version
            except ValueError:
                # Assume family of 4, unless local-interface has no IPv4 addresses
                family = 4
            while idx < len(tokens):
                if tokens[idx] == "iburst":
                    details["iburst"] = True
                    idx += 1

                elif tokens[idx] == "key":
                    details["key_id"] = int(tokens[idx + 1])
                    idx += 2

                elif tokens[idx] == "local-interface":
                    interfaces = self.get_interfaces_ip()
                    intf = tokens[idx + 1]
                    if family == 6 and interfaces[intf]["ipv6"]:
                        details["source_address"] = list(
                            interfaces[intf]["ipv6"].keys()
                        )[0]
                    elif interfaces[intf]["ipv4"]:
                        details["source_address"] = list(
                            interfaces[intf]["ipv4"].keys()
                        )[0]
                    elif interfaces[intf]["ipv6"]:
                        details["source_address"] = list(
                            interfaces[intf]["ipv6"].keys()
                        )[0]
                    idx += 2

                elif tokens[idx] == "version":
                    details["version"] = int(tokens[idx + 1])
                    idx += 2

                elif tokens[idx] == "prefer":
                    details["prefer"] = True
                    idx += 1
                else:  # Shouldn't happen
                    idx += 1

            result[server_ip] = details

        return result

    def get_ntp_stats(self):
        ntp_stats = []

        REGEX = (
            r"^\s?(\+|\*|x|-)?([a-zA-Z0-9\.+-:]+)"
            r"\s+([a-zA-Z0-9\.]+)\s+([0-9]{1,2})"
            r"\s+(-|u)\s+([0-9h-]+)\s+([0-9]+)"
            r"\s+([0-9]+)\s+([0-9\.]+)\s+([0-9\.-]+)"
            r"\s+([0-9\.]+)\s?$"
        )

        commands = ["show ntp associations"]

        # output = self.device.run_commands(commands)
        # pyeapi.eapilib.CommandError: CLI command 2 of 2 'show ntp associations'
        # failed: unconverted command
        # JSON output not yet implemented...

        ntp_assoc = self._run_commands(commands, encoding="text")[0].get(
            "output", "\n\n"
        )
        ntp_assoc_lines = ntp_assoc.splitlines()[2:]

        for ntp_assoc in ntp_assoc_lines:
            line_search = re.search(REGEX, ntp_assoc, re.I)
            if not line_search:
                continue  # pattern not found
            line_groups = line_search.groups()
            try:
                ntp_stats.append(
                    {
                        "remote": str(line_groups[1]),
                        "synchronized": (line_groups[0] == "*"),
                        "referenceid": str(line_groups[2]),
                        "stratum": int(line_groups[3]),
                        "type": str(line_groups[4]),
                        "when": str(line_groups[5]),
                        "hostpoll": int(line_groups[6]),
                        "reachability": int(line_groups[7]),
                        "delay": float(line_groups[8]),
                        "offset": float(line_groups[9]),
                        "jitter": float(line_groups[10]),
                    }
                )
            except Exception:
                continue  # jump to next line

        return ntp_stats

    def get_interfaces_ip(self):
        interfaces_ip = {}

        interfaces_ipv4_out = self._run_commands(["show ip interface"])[0]["interfaces"]
        try:
            interfaces_ipv6_out = self._run_commands(["show ipv6 interface"])[0][
                "interfaces"
            ]
        except pyeapi.eapilib.CommandError as e:
            msg = str(e)
            if "No IPv6 configured interfaces" in msg:
                interfaces_ipv6_out = {}
            else:
                raise

        for interface_name, interface_details in interfaces_ipv4_out.items():
            ipv4_list = []
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = {}

            if "ipv4" not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name]["ipv4"] = {}
            if "ipv6" not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name]["ipv6"] = {}

            iface_details = interface_details.get("interfaceAddress", {})
            if iface_details.get("primaryIp", {}).get("address") != "0.0.0.0":
                ipv4_list.append(
                    {
                        "address": napalm.base.helpers.ip(
                            iface_details.get("primaryIp", {}).get("address")
                        ),
                        "masklen": iface_details.get("primaryIp", {}).get("maskLen"),
                    }
                )
            for secondary_ip in iface_details.get("secondaryIpsOrderedList", []):
                ipv4_list.append(
                    {
                        "address": napalm.base.helpers.ip(secondary_ip.get("address")),
                        "masklen": secondary_ip.get("maskLen"),
                    }
                )

            for ip in ipv4_list:
                if not ip.get("address"):
                    continue
                if ip.get("address") not in interfaces_ip.get(interface_name).get(
                    "ipv4"
                ):
                    interfaces_ip[interface_name]["ipv4"][ip.get("address")] = {
                        "prefix_length": ip.get("masklen")
                    }

        for interface_name, interface_details in interfaces_ipv6_out.items():
            ipv6_list = []
            if interface_name not in interfaces_ip.keys():
                interfaces_ip[interface_name] = {}

            if "ipv4" not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name]["ipv4"] = {}
            if "ipv6" not in interfaces_ip.get(interface_name):
                interfaces_ip[interface_name]["ipv6"] = {}

            ipv6_list.append(
                {
                    "address": napalm.base.helpers.convert(
                        napalm.base.helpers.ip,
                        interface_details.get("linkLocal", {}).get("address"),
                    ),
                    "masklen": int(
                        interface_details.get("linkLocal", {})
                        .get("subnet", "::/0")
                        .split("/")[-1]
                    ),
                    # when no link-local set, address will be None and maslken 0
                }
            )
            for address in interface_details.get("addresses"):
                ipv6_list.append(
                    {
                        "address": napalm.base.helpers.ip(address.get("address")),
                        "masklen": int(address.get("subnet").split("/")[-1]),
                    }
                )
            for ip in ipv6_list:
                if not ip.get("address"):
                    continue
                if ip.get("address") not in interfaces_ip.get(interface_name).get(
                    "ipv6"
                ):
                    interfaces_ip[interface_name]["ipv6"][ip.get("address")] = {
                        "prefix_length": ip.get("masklen")
                    }

        return interfaces_ip

    def get_mac_address_table(self):
        mac_table = []

        commands = ["show mac address-table"]

        mac_entries = (
            self._run_commands(commands)[0]
            .get("unicastTable", {})
            .get("tableEntries", [])
        )

        for mac_entry in mac_entries:
            vlan = mac_entry.get("vlanId")
            interface = mac_entry.get("interface")
            mac_raw = mac_entry.get("macAddress")
            static = mac_entry.get("entryType") == "static"
            last_move = mac_entry.get("lastMove", 0.0)
            moves = mac_entry.get("moves", 0)
            mac_table.append(
                {
                    "mac": napalm.base.helpers.mac(mac_raw),
                    "interface": interface,
                    "vlan": vlan,
                    "active": True,
                    "static": static,
                    "moves": moves,
                    "last_move": last_move,
                }
            )

        return mac_table


    def get_snmp_information(self):
        """get_snmp_information() for EOS.  Re-written to not use TextFSM"""

        # Default values
        snmp_dict = {"chassis_id": "", "location": "", "contact": "", "community": {}}

        commands = [
            "show snmp v2-mib chassis",
            "show snmp v2-mib location",
            "show snmp v2-mib contact",
        ]
        snmp_config = self._run_commands(commands, encoding="json")
        for line in snmp_config:
            for k, v in line.items():
                if k == "chassisId":
                    snmp_dict["chassis_id"] = v
                else:
                    # Some EOS versions add extra quotes
                    snmp_dict[k] = v.strip('"')

        commands = ["show running-config | section snmp-server community"]
        raw_snmp_config = self._run_commands(commands, encoding="text")[0].get(
            "output", ""
        )
        for line in raw_snmp_config.splitlines():
            match = self._RE_SNMP_COMM.search(line)
            if match:
                matches = match.groupdict("")
                snmp_dict["community"][match.group("community")] = {
                    "acl": str(matches["v4_acl"]),
                    "mode": str(matches["access"]),
                }

        return snmp_dict

    def get_users(self):
        def _sshkey_type(sshkey):
            if sshkey.startswith("ssh-rsa"):
                return "ssh_rsa", str(sshkey)
            elif sshkey.startswith("ssh-dss"):
                return "ssh_dsa", str(sshkey)
            return "ssh_rsa", ""

        users = {}

        commands = ["show users accounts"]
        user_items = self._run_commands(commands)[0].get("users", {})

        for user, user_details in user_items.items():
            user_details.pop("username", "")
            sshkey_value = user_details.pop("sshAuthorizedKey", "")
            sshkey_type, sshkey_value = _sshkey_type(sshkey_value)
            if sshkey_value != "":
                sshkey_list = [sshkey_value]
            else:
                sshkey_list = []
            user_details.update(
                {
                    "level": user_details.pop("privLevel", 0),
                    "password": str(user_details.pop("secret", "")),
                    "sshkeys": sshkey_list,
                }
            )
            users[user] = user_details

        return users
    

    def get_optics(self):
        command = ["show interfaces transceiver"]

        output = self._run_commands(command, encoding="json")[0]["interfaces"]

        # Formatting data into return data structure
        optics_detail = {}

        for port, port_values in output.items():
            port_detail = {"physical_channels": {"channel": []}}

            # Defaulting avg, min, max values to 0.0 since device does not
            # return these values
            optic_states = {
                "index": 0,
                "state": {
                    "input_power": {
                        "instant": (
                            port_values["rxPower"] if "rxPower" in port_values else 0.0
                        ),
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0,
                    },
                    "output_power": {
                        "instant": (
                            port_values["txPower"] if "txPower" in port_values else 0.0
                        ),
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0,
                    },
                    "laser_bias_current": {
                        "instant": (
                            port_values["txBias"] if "txBias" in port_values else 0.0
                        ),
                        "avg": 0.0,
                        "min": 0.0,
                        "max": 0.0,
                    },
                },
            }

            port_detail["physical_channels"]["channel"].append(optic_states)
            optics_detail[port] = port_detail

        return optics_detail

    def _show_vrf_json(self):
        commands = ["show vrf"]

        vrfs = self._run_commands(commands)[0]["vrfs"]
        return [
            {
                "name": k,
                "interfaces": [i for i in v["interfaces"]],
                "route_distinguisher": v["routeDistinguisher"],
            }
            for k, v in vrfs.items()
        ]

    def _show_vrf_text(self):
        commands = ["show vrf"]

        # This command has no JSON in EOS < 4.23
        raw_output = self._run_commands(commands, encoding="text")[0].get("output", "")

        width_line = raw_output.splitlines()[2]  # Line with dashes
        fields = width_line.split(" ")
        widths = [len(f) + 1 for f in fields]
        widths[-1] -= 1

        parsed_lines = string_parsers.parse_fixed_width(raw_output, *widths)

        vrfs = []
        vrf = {}
        current_vrf = None
        for line in parsed_lines[3:]:
            line = [t.strip() for t in line]
            if line[0]:
                if current_vrf:
                    vrfs.append(vrf)
                current_vrf = line[0]
                vrf = {
                    "name": current_vrf,
                    "interfaces": list(),
                }
            if line[1]:
                vrf["route_distinguisher"] = line[1]
            if line[4]:
                vrf["interfaces"].extend([t.strip() for t in line[4].split(",") if t])
        if current_vrf:
            vrfs.append(vrf)

        return vrfs

    def _show_vrf(self):
        return self._show_vrf_json()

    def _get_vrfs(self):
        output = self._show_vrf()

        vrfs = [str(vrf["name"]) for vrf in output]

        return vrfs

    def get_network_instances(self, name=""):
        """get_network_instances implementation for EOS."""

        output = self._show_vrf()
        vrfs = {}
        all_vrf_interfaces = {}
        for vrf in output:
            if (
                vrf.get("route_distinguisher", "") == "<not set>"
                or vrf.get("route_distinguisher", "") == "None"
            ):
                vrf["route_distinguisher"] = ""
            else:
                vrf["route_distinguisher"] = str(vrf["route_distinguisher"])
            interfaces = {}
            for interface_raw in vrf.get("interfaces", []):
                interface = interface_raw.split(",")
                for line in interface:
                    if line.strip() != "":
                        interfaces[str(line.strip())] = {}
                        all_vrf_interfaces[str(line.strip())] = {}

            vrfs[vrf["name"]] = {
                "name": vrf["name"],
                "type": "DEFAULT_INSTANCE" if vrf["name"] == "default" else "L3VRF",
                "state": {"route_distinguisher": vrf["route_distinguisher"]},
                "interfaces": {"interface": interfaces},
            }
        if "default" not in vrfs:
            all_interfaces = self.get_interfaces_ip().keys()
            vrfs["default"] = {
                "name": "default",
                "type": "DEFAULT_INSTANCE",
                "state": {"route_distinguisher": ""},
                "interfaces": {
                    "interface": {
                        k: {}
                        for k in all_interfaces
                        if k not in all_vrf_interfaces.keys()
                    }
                },
            }

        if name:
            if name in vrfs:
                return {str(name): vrfs[name]}
            return {}
        else:
            return vrfs

    def get_vlans(self):
        command = ["show vlan"]
        output = self._run_commands(command, encoding="json")[0]["vlans"]

        vlans = {}
        for vlan, vlan_config in output.items():
            vlans[vlan] = {
                "name": vlan_config["name"],
                "interfaces": list(vlan_config["interfaces"].keys()),
            }

        return vlans