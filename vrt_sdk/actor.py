"""Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from vrt_sdk.enumerations import *


class Actor:

  def __init__(self, actor_json):
    """Class representing an MSV Actor.

    Does not include all possible keys from the Actor json.
    """

    self._raw = actor_json

    self.available_interfaces: any = actor_json["available_interfaces"]
    self.desc: str = actor_json["desc"]
    self.disabled: bool = actor_json["disabled"]
    self.fq_hostname: str = actor_json["fq_hostname"]
    self.gateway: str = actor_json["gateway"]
    self.hostname: str = actor_json["hostname"]
    self.id: int = actor_json["id"]
    self.interface_ips: list[str] = actor_json["interface_ips"]
    self.keepalive: bool = actor_json["keepalive"]
    self.last_comms: str = actor_json["last_comms"]
    self.mgmt_ip: any = actor_json["mgmt_ip"]
    self.monitor_ip: str = actor_json["monitor_ip"]
    self.name: str = actor_json["name"]
    self.netmask: str = actor_json["netmask"]
    self.node_version: str = actor_json["node_version"]
    self.organization_id: int = actor_json["organization_id"]
    self.updating: bool = actor_json["updating"]
    self.os_base: str = actor_json["os_base"]
    self.os_full: str = actor_json["os_full"]
    self.pt_selected_os: str = actor_json["pt_selected_os"]
    # For reference, there are four node_type values
    # endpoint - Used for Host CLI Actions (i.e. non-destructive, no malware)
    # network
    # sandbox - Protected Theater, the host containing the Virtual Machine
    # protected - Protected Actor, the Virtual Machine for use in PT Actions
    self.node_type: str = actor_json[
        "node_type"
    ]  # one of endpoint (Host CLI), network, protected (pt actor)
    self.proxy_type: str = actor_json["proxy_type"]
    self.sandbox_node_id: int = actor_json["sandbox_node_id"]
    self.ssh_status: any = actor_json["ssh_status"]
    self.uptime: str = actor_json["uptime"]
    self.username: str = actor_json["username"]
    self.use_proxy: bool = actor_json["use_proxy"]

  def __repr__(self):
    return f"Actor {self.name} - OS: {self.os_full}"

  @property
  def guessed_true_os(self) -> OSTagEnum:
    """Attempt to identify the OS and coerce it to an OSTagEnum.

    Returns: An OSTagEnum
    """
    if "win10" in self.name.lower() or "win_10" in self.name.lower():
      return OSTagEnum.WINDOWS_10
    elif "win11" in self.name.lower() or "win_11" in self.name.lower():
      return OSTagEnum.WINDOWS_11
    elif "ubu" in self.name.lower() or "ubuntu" in self.os_base.lower():
      return OSTagEnum.LINUX_UBUNTU
    elif "centos" in self.os_base.lower():
      return OSTagEnum.LINUX_CENTOS
    elif "win12" in self.name.lower() or "server_2012" in self.name.lower():
      return OSTagEnum.WINDOWS_SERVER_2012
    elif "win16" in self.name.lower() or "server_2016" in self.name.lower():
      return OSTagEnum.WINDOWS_SERVER_2016
    elif "win19" in self.name.lower() or "server_2019" in self.name.lower():
      return OSTagEnum.WINDOWS_SERVER_2019
    elif "win22" in self.name.lower() or "server_2022" in self.name.lower():
      return OSTagEnum.WINDOWS_SERVER_2022
    elif "mac" in self.name.lower():
      return OSTagEnum.MACOS
