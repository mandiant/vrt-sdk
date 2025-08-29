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

from typing import TypeVar

import pandas

from .exceptions import *
from .misc import *


class Action:
  """Parent class defining an Action"""

  def __init__(self, action_json: dict):
    self._raw = action_json

    # These are not contained within 'sim_action' in a Full Action JSON
    self.control_tags: list[str] = []
    self.hex: bool = False
    self.http: bool = False
    self.nist_control_tags: list[str] = []
    self.mitre_attack_techniques: list[MitreAttackTechnique] = []
    self.mitre_mitigation_tags: list[str] = []
    self.os_tags: list[str] = []
    self.run_as_tags: list[str] = []
    self.src_destination_tags: list[str] = []
    self.tls: bool = False
    self.user_control_tags: list[str] = []
    self.user_mitre_mitigation_tags: list[str] = []
    self.user_nist_control_tags: list[str] = []
    self.user_os_tags: list[str] = []
    self.user_run_as_tags: list[str] = []
    self.user_src_destination_tags: list[str] = []
    self.user_tags: list[str] = []
    self.verodin_tags: list[str] = []

    # These are contained within 'sim_action' in a Full Action JSON
    self.action_type: str = ""
    self.approved_version: int = 0
    self.brt_version: str = ""
    self.brt_version_updated_at: str = ""
    self.cda_version: str = "str"
    self.created: str = ""
    self.created_at: str = ""
    self.desc: str = ""
    self.decommissioned: bool = False
    self.disabled: bool = False
    self.execution_plan: list[any] = []
    self.hex_http: bool = False
    self.id: int = 0
    self.metadata_version: int = 0
    self.min_version: str = ""
    self.name: str = ""
    self.notes: str = ""
    self.organization_id: int = 0
    self.require_endpoint: bool = False
    self.required_license: any = None
    self.runtime: any = None
    self.sectech_logo_id: int = 0
    self.sectech_url: str = ""
    self.status: any = None
    self.timeout_ms: int = 0
    self.trees: list[dict[str:any]] = []
    self.updated_at: str = ""
    self.uuid: str = ""
    self.ver: int = 0
    self.vid: str = ""

    # These are to be automatically computed by the director client
    self._dimension_OS_platform = ""
    self._dimension_attack_vector = ""
    self._dimension_attacker_location = ""
    self._dimension_behavior_type = ""
    self._dimension_covert = ""
    self._dimension_stage_of_attack = ""

    def _parse_possible_sim_action_attributes(target_json):

      # Always in an Action JSON,
      # but are nested under "sim_action" when using a Full Action JSON
      for attribute in [
          "id",
          "organization_id",
          "name",
          "desc",
          "action_type",
          "timeout_ms",
          "created_at",
          "updated_at",
          "vid",
          "disabled",
          "ver",
          "uuid",
          "metadata_version",
          "require_endpoint",
          "approved_version",
          "sectech_logo_id",
          "brt_version",
          "created",
          "required_license",
          "runtime",
          "notes",
          "hex_http",
          "min_version",
          "sectech_url",
          "status",
          "decommissioned",
          "brt_version_updated_at",
          "cda_version",
      ]:

        if attribute in target_json:
          self.__setattr__(attribute, target_json[attribute])
        else:
          pass

      for attribute in ["trees", "execution_plan"]:
        if attribute in target_json:
          self.__setattr__(attribute, target_json[attribute])
        else:
          pass

    if "sim_action" not in action_json:
      _parse_possible_sim_action_attributes(action_json)
    else:
      _parse_possible_sim_action_attributes(action_json["sim_action"])

    # Always in the Action JSON, are outside of "sim_action" in a Full Action. Requires special handling due to "?" character.
    for attribute in ["hex?", "http?", "tls?"]:
      if attribute in action_json:
        self.__setattr__(attribute.replace("?", ""), action_json[attribute])
      else:
        pass

    # Always in the Action JSON, outside of "sim_action" in a Full Action.
    for attribute in [
        "control_tags",
        "mitre_mitigation_tags",
        "nist_control_tags",
        "os_tags",
        "run_as_tags",
        "src_destination_tags",
        "user_control_tags",
        "user_mitre_mitigation_tags",
        "user_nist_control_tags",
        "user_os_tags",
        "user_src_destination_tags",
        "user_run_as_tags",
        "user_tags",
        "verodin_tags",
    ]:

      if attribute in action_json:
        self.__setattr__(attribute, action_json[attribute])
      else:
        pass

    if "mitre_attack_techniques" in action_json:
      if "techniques" in action_json["mitre_attack_techniques"]:
        for item in action_json["mitre_attack_techniques"]["techniques"]:
          technique = MitreAttackTechnique(item)
          self.mitre_attack_techniques.append(technique)

    self._check_required_attributes(["vid", "name", "id", "uuid", "created_at"])

  # This could be extended to other Action types
  # to enforce requirements for more specific attributes
  def _check_required_attributes(self, attrs: list[str]):
    if not all(map(lambda x: self.__getattribute__(x), attrs)):
      raise ContentParsingError

  @property
  def dimension_OS_platform(self) -> str:
    if isinstance(self, PartialAction):
      for item in self.trees:
        if item["root_name"] == "OS/Platform":
          return item["name"]
    else:
      return self._dimension_OS_platform

  @dimension_OS_platform.setter
  def dimension_OS_platform(self, value):
    self._dimension_OS_platform = value

  @property
  def dimension_attacker_location(self) -> str:
    if isinstance(self, PartialAction):
      for item in self.trees:
        if item["root_name"] == "Attacker Location":
          return item["name"]
    else:
      return self._dimension_attacker_location

  @dimension_attacker_location.setter
  def dimension_attacker_location(self, value):
    self._dimension_attacker_location = value

  @property
  def dimension_stage_of_attack(self) -> str:
    if isinstance(self, PartialAction):
      for item in self.trees:
        if item["root_name"] == "Stage of Attack":
          return item["name"]
    else:
      return self._dimension_stage_of_attack

  @dimension_stage_of_attack.setter
  def dimension_stage_of_attack(self, value):
    self._dimension_stage_of_attack = value

  @property
  def dimension_attack_vector(self) -> str:
    if isinstance(self, PartialAction):
      for item in self.trees:
        if item["root_name"] == "Attack Vector":
          return item["name"]
    else:
      return self._dimension_attack_vector

  @dimension_attack_vector.setter
  def dimension_attack_vector(self, value):
    self._dimension_attack_vector = value

  @property
  def dimension_covert(self) -> str:
    if isinstance(self, PartialAction):
      for item in self.trees:
        if item["root_name"] == "Covert":
          return item["name"]
    else:
      return self._dimension_covert

  @dimension_covert.setter
  def dimension_covert(self, value):
    self._dimension_covert = value

  @property
  def dimension_behavior_type(self) -> str:
    if isinstance(self, PartialAction):
      for item in self.trees:
        if item["root_name"] == "Behavior Type":
          return item["name"]
    else:
      return self._dimension_behavior_type

  @dimension_behavior_type.setter
  def dimension_behavior_type(self, value):
    self._dimension_behavior_type = value


class PartialAction(Action):
  """Represents a "Partial Action",

  or an abridged action returned without a sim_action key.

  Not all fields are guaranteed to be present.
  """

  def __init__(self, action_json: dict):
    super().__init__(action_json)

  def __repr__(self):
    return f"Partial Action: {self.vid} - {self.name}"


class FullAction(Action):
  """Represents a "Full Action", or one containing the sim_action key.

  This class has multiple subclasses, one for each action type. These subclasses
  define additional information about each type of action.

  Not all fields are guaranteed to be present.
  """

  def __init__(self, action_json: dict):
    super().__init__(action_json)
    self.common_detection_alerts: list[CDA] = []

    cda_jsons = action_json.get("sim_action", {}).get("common_detection_alerts")
    if not cda_jsons:
      cda_jsons = action_json.get("common_detection_alerts", {})

    for cda in cda_jsons:
      self.common_detection_alerts.append(CDA(cda))


def __repr__(self):
  return f"Full Action: {self.vid} - {self.name}"


class FileTransferAction(FullAction):
  """A FileTransferAction (i.e. "Malicious File Transfer").

  Subclass of `FullAction`
  """

  def __init__(self, action_json: dict):
    super().__init__(action_json)

    self.action_user_profile_id: int | None = None
    self.app_layer: str = ""
    self.cache_version: int = 0
    self.compare_transfer: bool = False
    self.content_encoding: str = ""
    self.dns_domain: str = ""
    self.endpoint_executable_only: bool = False
    self.file_transfer_library: VRTFile | None = None
    self.file_transfer_library_id: int = 0
    self.keep_after_compare: bool = False
    self.method: str = ""
    self.referer: any = None
    self.sim_action_id = None
    self.target_port: int = 0
    self.transfer_encoding: str = ""
    self.transport_layer: str = ""
    self.tunnel_cidr: str = ""
    self.tunnel_protocol: str = ""
    self.user_agent: any = None

    for attribute in [
        "action_user_profile_id",
        "app_layer",
        "cache_version",
        "compare_transfer",
        "content_encoding",
        "dns_domain",
        "endpoint_executable_only",
        "file_transfer_library_id",
        "keep_after_compare",
        "method",
        "referer",
        "sim_action_id",
        "target_port",
        "transfer_encoding",
        "transport_layer",
        "tunnel_cidr",
        "tunnel_protocol",
        "user_agent",
    ]:

      attr_value = (
          action_json.get("sim_action", {})
          .get("file_transfer_action", {})
          .get(attribute)
      )

      if attr_value is None:
        attr_value = action_json.get("file_transfer_action", {}).get(attribute)
      self.__setattr__(attribute, attr_value)

    ftl = (
        action_json.get("sim_action", {})
        .get("file_transfer_action", {})
        .get("file_transfer_library")
    )
    if not ftl:
      ftl = action_json.get("file_transfer_action", {}).get(
          "file_transfer_library"
      )
    self.file_transfer_library = VRTFile(ftl)

  def __repr__(self):
    return f"File Transfer Action: {self.vid} - {self.name}"


class PcapAction(FullAction):
  """A PCAP Action. Subclass of `FullAction`"""

  def __init__(self, action_json: dict):
    super().__init__(action_json)

    self.pcap_library_id: int = 0
    self.start_packet: int | None = 1
    self.end_packet: int | None = None
    self.attacker_ip: str = ""

    # Note: The Action JSON presents ports as string representations.
    #   So an Action using port 80 would have the STRING '["TCP/80"]'
    #   It is NOT a list of strings, despite being the text equivalent.
    self.attacker_ports: str = ""
    self.target_ports: str = ""

    # Note: Similarly to ports, protos are presented as string representations.
    #   So an Action using TCP and UDP would have the STRING '["TCP","UDP"]'
    #   It is NOT a list of strings, despite being the text equivalent.
    self.protos: str = ""

    self.replicate_tcp: any = None
    self.replicate_tcp_timeouts: any = None
    self.action_user_profile_id: int = 0
    self.pcap_library = {str: any}

    for attribute in [
        "pcap_library_id",
        "start_packet",
        "end_packet",
        "attacker_ip",
        "attacker_ports",
        "target_ports",
        "protos",
        "replicate_tcp",
        "replicate_tcp_timeouts",
        "action_user_profile_id",
        "pcap_library",
    ]:

      attr_value = (
          action_json.get("sim_action", {})
          .get("pcap_action", {})
          .get(attribute)
      )
      if attr_value is None:
        attr_value = action_json.get("pcap_action", {}).get(attribute)
      self.__setattr__(attribute, attr_value)

  def __repr__(self):
    return f"PCAP Action: {self.vid} - {self.name}"


class WebAction(FullAction):
  """A Web Action. Subclass of `FullAction`."""

  def __init__(self, action_json: dict):
    super().__init__(action_json)

    self.server_port: int = 0
    self.http_ver: str = ""
    self.use_https: bool = False
    self.action_user_profile_id: int = 0
    self.web_action_steps: list[WebActionStep] = []

    for attribute in [
        "server_port",
        "http_ver",
        "use_https",
        "action_user_profile_id",
    ]:

      attr_value = (
          action_json.get("sim_action", {}).get("web_action", {}).get(attribute)
      )
      if attr_value is None:
        attr_value = action_json.get("web_action", {}).get(attribute)
      self.__setattr__(attribute, attr_value)

    was = (
        action_json.get("sim_action", {})
        .get("web_action", {})
        .get("web_action_steps")
    )
    if not was:
      was = action_json.get("web_action", {}).get("web_action_steps")

    if was:
      for entry in was:
        step = WebActionStep(entry)
        self.web_action_steps.append(step)

  def __repr__(self):
    return f"Web Action: {self.vid} - {self.name}"


class WebActionStep:
  """Represents a step in a WebAction (a request and a response)."""

  def __init__(self, json: dict):
    self.request: str = json["request"]
    self.request_body: str = json["request_body"]
    self.req_headers: str = json["req_headers"]
    self.response: str = json["response"]
    self.resp_code: int = json["resp_code"]
    self.resp_headers: str = json["resp_headers"]
    self.step_order: int = json["step_order"]
    self.web_action_id: int = json["web_action_id"]

  def __repr__(self):
    return f"Web Action Step: ID:{self.web_action_id}"


class EmailAction(FullAction):
  """An Email Action. Subclass of `FullAction`.

  For information about the files used in an EmailAction,
  see the email_action_file_transfer_libraries attribute.
  This contains a list of dictionaries,
  each of which contains a key "file_transfer_library_id",
  which can be used to look up the file information in the file library.
  """

  def __init__(self, action_json: dict):
    super().__init__(action_json)

    self.subject: str = ""
    self.body: str = ""
    self.block_matching_scheme: str = ""
    self.mime_text_type: str = ""

    self.email_action_file_transfer_libraries: list[dict[str:any]] = []

    for attribute in [
        "subject",
        "body",
        "block_matching_scheme",
        "mime_text_type",
        "email_action_file_transfer_libraries",
    ]:

      attr_value = (
          action_json.get("sim_action", {})
          .get("email_action", {})
          .get(attribute)
      )
      if attr_value is None:
        attr_value = action_json.get("email_action", {}).get(attribute)
      self.__setattr__(attribute, attr_value)

  def __repr__(self):
    return f"Email Action: {self.vid} - {self.name}"


class DnsAction(FullAction):
  """A DNS Query Action. Subclass of `FullAction`."""

  def __init__(self, action_json: dict):
    super().__init__(action_json)

    self.domain: str = ""
    self.dns_server_id: any = None
    self.query_type: str = ""

    for attribute in ["domain", "dns_server_id", "query_type"]:

      attr_value = (
          action_json.get("sim_action", {})
          .get("dns_query_action", {})
          .get(attribute)
      )
      if attr_value is None:
        attr_value = action_json.get("dns_query_action", {}).get(attribute)
      self.__setattr__(attribute, attr_value)

  def __repr__(self):
    return f"DNS Action: {self.vid} - {self.name}"


class HostAction(FullAction):
  """A Host Action. Can represent either a Host CLI or Protected Theater Action.

  Subclass of `FullAction`.
  """

  def __init__(self, action_json: dict):
    super().__init__(action_json)

    self.shell: str = ""
    self.raw_text: str = ""
    self.delivery_wait_time: int = 0
    self.delivery_failed_result: str = ""
    self.destination_exists_result: str = ""
    self.action_user_profile_id: int = 0  # Probably an int?
    self.monitor_connections: str = ""
    self.user_variables: list = []
    self.separate_cleanup_shell: bool = False
    self.automatic_file_cleanup: bool = False
    self.require_run_as_interactive: bool = False
    self.host_cli_action_steps: list[HostActionStep] = []
    self.host_cli_action_file_transfer_libraries: list = []

    for attribute in [
        "shell",
        "raw_text",
        "delivery_wait_time",
        "delivery_failed_result",
        "destination_exists_result",
        "action_user_profile_id",
        "monitor_connections",
        "user_variables",
        "separate_cleanup_shell",
        "automatic_file_cleanup",
        "require_run_as_interactive",
        "host_cli_action_file_transfer_libraries",
    ]:

      attr_value = (
          action_json.get("sim_action", {})
          .get("host_cli_action", {})
          .get(attribute)
      )
      if not attr_value:
        attr_value = action_json.get("host_cli_action", {}).get(attribute)
      self.__setattr__(attribute, attr_value)

    has = (
        action_json.get("sim_action", {})
        .get("host_cli_action", {})
        .get("host_cli_action_steps")
    )
    if not has:
      has = action_json.get("host_cli_action", {}).get("host_cli_action_steps")

    for item in has:
      step = HostActionStep(item)
      self.host_cli_action_steps.append(step)

  def __repr__(self):
    return f"Host Action: {self.vid} - {self.name}"


class HostActionStep:
  """Represents a step in a HostAction (a single command)."""

  def __init__(self, step_json: dict):
    self._raw = step_json

    self.blocked_check: str | None = step_json["blocked_check"]
    self.blocked_match: str | None = step_json["blocked_match"]
    self.blocked_order: any = step_json["blocked_order"]
    self.check_events: bool = step_json["check_events"]
    self.cleanup: bool = step_json["cleanup"]
    self.command: str = step_json["command"]
    self.error_check: str | None = step_json["error_check"]
    self.error_match: str | None = step_json["error_match"]
    self.error_order: any = step_json["error_order"]
    self.event_logs: any = step_json["event_logs"]
    self.id: int = step_json["id"]
    self.incompatible_check: str | None = step_json["incompatible_check"]
    self.incompatible_match: str | None = step_json["incompatible_match"]
    self.incompatible_order: str | None = step_json["incompatible_order"]
    self.prompt: str = step_json["prompt"]
    self.sleep: int = step_json["sleep"]
    self.success_check: str | None = step_json["success_check"]
    self.success_match: str | None = step_json["success_match"]
    self.success_order: any = step_json["success_order"]
    self.timeout: int = step_json["timeout"]

  def __repr__(self):
    return f"Host Action Step: {self.id}"


class HostActionFactory:

  def __init__(
      self,
      action_name: str,
      action_description: str,
      shell: str,
      protected: bool = True,
  ):
    """Factory class for creating Host-based Actions.

    Factory class for creating Host-based Actions (Host CLI and PT Actions).

    See `add_step` and `add_file` methods for adding commands to the planned
    Host Action.

    Args:
      action_name: Name of the Action.
      action_description: Description of the Action.
      shell: Shell for the Action (i.e., "cmd.exe" or "powershell.exe").
      protected: Whether the Action should be restricted to Protected Theaters.
        Defaults to True.
    """
    self.action_name = action_name
    self.action_description = action_description
    self.shell = shell
    self.protected = protected
    self.commands: list[str] = []
    self.files: dict[int : dict[str:str]] = {}
    self.trees = {}

  def add_step(
      self,
      text: str,
      prompt_regex: str = "auto",
      sleep: int | str = "4",
      timeout: int | str = "60",
      criteria: str = "success_zero",
  ) -> None:
    """Adds a command to the planned Host Action.

    This can be either part of the test or part of the cleanup operation.
    Commands are added in order, so if you have three commands, calling this
    again will add a fourth.

    Currently does not protect against bad ordering (such as starting an Action
    with a cleanup command), so your order of commands must be valid.

    Args:
      text: The text of the command. I.e., "echo whoami". Be careful of escape
        characters (raw text may help here).
      prompt_regex: The prompt to match to signal that the director should
        execute the next command. Defaults to "auto", the normal value. This is
        normally changed for things like Mimikatz and WSL Actions, and should
        generally be left alone.
      sleep: The amount of time in seconds after completing this command to
        sleep before executing the next command. Defaults to 4 seconds.
      timeout: The amount of time in seconds to wait before raising a timeout
        error for a command. Defaults to 60 seconds.
      criteria: The success criteria for this Action. Defaults to
        "success_zero". Can also be options such as "success_match:{abc}" and
        "cleanup". See MSV documentation for valid values.
    """

    command = (
        f"{text}\r\n  {prompt_regex},{str(sleep)},true,{str(timeout)}\r\n "
        f" {criteria}\r\n\r\n"
    )
    self.commands.append(command)

  def _build_host_cli_raw_text(self):
    return "".join(self.commands)

  def add_file(
      self,
      file_id: int,
      destination_directory: str,
      destination_name: str,
      file_owner: str = "system",
  ) -> None:
    """Adds a file dependency to the planned Host Action.

    Does not protect against adding duplicates.

    Args:
      file_id: The ID of the file_transfer_library entry (file) to add to the
        action.
      destination_directory: The directory to place the file on disk.
        Ex: "C:\\Windows\\Temp".
      destination_name: The name of the file on disk.
        Ex: "example_evil_file.bin".
      file_owner: Owner of the file. Defaults to "system".
    """
    self.files[file_id] = {
        "destination_directory": destination_directory,
        "destination_name": destination_name,
        "file_owner": file_owner,
    }

  def _build_file_dependencies(self):
    return self.files

  def build_payload(self) -> dict:
    """Builds the payload to be sent to the director to create a Host Action.

    You should not need to call this.

    :return: A dict representing a payload for Host Action creation
    """

    if len(self.commands) < 1:
      raise ActionCreationError("Must have at least one CLI command")

    if not self.trees:
      raise ActionCreationError(
          "Must provide dimension information, see the"
          " set_host_factory_dimensions method on the Director class"
      )

    val = {
        "sim_action": {
            "action_type": "host_cli",
            "timeout_ms": 10000,
            "name": self.action_name,
            "desc": self.action_description,
            "require_endpoint": self.protected,
            "host_cli_action_attributes": {
                "shell": self.shell,
                "raw_text": self._build_host_cli_raw_text(),
                "action_user_profile_id": "0",
                "monitor_connections": "",
                "delivery_wait_time": 5,
                "delivery_failed_result": "blocked",
                "destination_exists_result": "",
                # 'host_cli_action_file_transfer_libraries': {
                #     fileid: {
                #         "destination_directory": 'c:/windows/temp',
                #         "destination_name": 'vserver_files_payload.zip',
                #         "file_owner": 'system'
                #     }
                # }
            },
        },
        "trees": self.trees,
        "approve_anywhere": "yes",
    }
    if self.files:
      val["sim_action"]["host_cli_action_attributes"][
          "host_cli_action_file_transfer_libraries"
      ] = self._build_file_dependencies()

    return val


class CaptiveDnsAction(FullAction):
  """A Captive DNS Action. Provides no special support or attributes.

  Subclass of `FullAction`.
  """

  def __init__(self, action_json: dict):
    super().__init__(action_json)

  def __repr__(self):
    return f"Captive DNS Action: {self.vid} - {self.name}"


class CaptivePcapAction(FullAction):
  """A Captive PCAP Action. Provides no special support or attributes.

  Subclass of `FullAction`.
  """

  def __init__(self, action_json: dict):
    super().__init__(action_json)

  def __repr__(self):
    return f"Captive PCAP Action: {self.vid} - {self.name}"


class CaptiveUrlAction(FullAction):
  """A Captive URL Action. Provides no special support or attributes.

  Subclass of `FullAction`.
  """

  def __init__(self, action_json: dict):
    super().__init__(action_json)

  def __repr__(self):
    return f"Captive URL Action: {self.vid} - {self.name}"


class SocketAction(FullAction):
  """A Socket Action. Provides no special support or attributes.

  Subclass of `FullAction`.
  """

  def __init__(self, action_json: dict):
    super().__init__(action_json)

  def __repr__(self):
    return f"Socket Action: {self.vid} - {self.name}"


class PortScanAction(FullAction):
  """A Port Scan Action. Provides no special support or attributes.

  Subclass of `FullAction`.
  """

  def __init__(self, action_json: dict):
    super().__init__(action_json)

  def __repr__(self):
    return f"Port Scan Action: {self.vid} - {self.name}"


class CloudAction(FullAction):
  """A Cloud Action. Provides no special support or attributes.

  Subclass of `FullAction`.
  """

  def __init__(self, action_json: dict):
    super().__init__(action_json)

  def __repr__(self):
    return f"Cloud Action: {self.vid} - {self.name}"


FullActionSubclass = TypeVar("FullActionSubclass", bound=FullAction)


class Simulation:
  """Parent class defining a Simulation (an Evaluation or a Sequence)."""

  def __init__(self, simulation_json: dict):
    self._raw = simulation_json

    self.action_ids: list[list[int]] = []
    self.action_vids: list[list[str]] = []
    self.created_at: str = ""
    self.desc: str = ""
    self.disabled: bool = False
    self.group_names: list[str] = []
    self.id: int = 0
    self.metadata_version: int = 0
    self.mitre_attack_techniques: dict[str:any] = (
        {}
    )  # Only held by "full" simulations".
    self.name: str = ""
    self.organization_id: int = 0
    self.protected_endpoint_rollback: str = (
        "no"  # This is returned by the director as {"yes"|"no"}, not as a bool
    )
    self.run_all_content_marker: any = None  # Why is this null?
    self.sectech_logo_id: int = 0
    self.sim_actions: list[str] = []
    self.simulation_type: str = ""
    self.step_fields: list[dict[str : str | int]] = []
    self.steps: list[dict : str : int | str | bool | None | list[dict]] = (
        []
    )  # Only held by "full" simulations". This ungodly thing has a list of Partial Actions in each item under ["sim_action"]
    self.stop_on_error: bool = False
    self.tip_aliases: list[any] = []
    self.updated_at: str = ""
    self.user_tags: list[str] = []
    self.user_tip_aliases: list[any] = []
    self.uuid: str = ""
    self.ver: int = 0
    self.verodin_tags: list[str] = []
    self.vid: str = ""

    for attribute in [
        "action_ids",
        "action_vids",
        "created_at",
        "desc",
        "disabled",
        "group_names",
        "id",
        "metadata_version",
        "mitre_attack_techniques",
        "name",
        "organization_id",
        "protected_endpoint_rollback",
        "run_all_content_marker",
        "sectech_logo_id",
        "sim_actions",
        "simulation_type",
        "step_fields",
        "steps",
        "stop_on_error",
        "tip_aliases",
        "updated_at",
        "user_tags",
        "user_tip_aliases",
        "uuid",
        "ver",
        "verodin_tags",
        "vid",
    ]:

      if attribute in simulation_json:
        self.__setattr__(attribute, simulation_json[attribute])
      else:
        pass

    """
    - Seqs and evals are identical, with the exception of the value of the "simulation_type" key
    - Full and partial are identical, except that full has "mitre_attack_techniques" and "steps" keys
    - Edit: The above is not necessarily accurate, I have observed differences recently based on the endpoints called
    - Full versions contain sim_action keys, but these contain only the PartialAction attributes minus "trees"
    """

  @property
  def parsed_vids(self) -> list[str]:
    output = []
    if self.action_vids:
      for sublist in self.action_vids:
        output.extend(sublist)
    # The format returned by the director is
    # 'A107-335Malicious File Transfer - ACTOR, MALWARE, Download, Variant #2file_transfer'
    # Just grab the first 8 characters and don't try to parse the rest
    elif "actions" in self._raw:
      for entry in self._raw["actions"]:
        output.append(entry[0:8])
    return output


class Evaluation(Simulation):
  """An Evaluation. Subclass of `Simulation`."""

  def __init__(self, simulation_json: dict):
    super().__init__(simulation_json)

  def __repr__(self):
    return f"Evaluation: {self.vid} - {self.name}"


class Sequence(Simulation):
  """A Sequence. Subclass of `Simulation`."""

  def __init__(self, simulation_json: dict):
    super().__init__(simulation_json)

  def __repr__(self):
    return f"Sequence: {self.vid} - {self.name}"


class SimulationFactory:

  def __init__(
      self,
      simulation_name: str,
      simulation_description: str,
      simulation_type: str,
  ):
    """Factory class for creating Sequences and Evaluations.

    There are two ways to create simulations.

    1. *Automatic* - Create a SimulationFactory and call
    `auto_build_from_actions()` with a list of FullAction objects. This will
    automatically group the Actions based on their type and tags to ensure a
    valid simulation. See the method documentation for more details. Then pass
    the factory object to the Director client's `create_simulation()` method.
    (Note that is may be easier to pass the list of Actions directly
    to the `create_simulation()` method, which will handle creating the factory
    for you.)

    2. *Manual* - Use the `add_step()` and `add_action()` methods to add Actions
    to groups manually, then call `create_simulation()` as described above. Be
    aware that this will NOT validate the simulation. If
    you attempt to create a group with a Host CLI Action and a File Transfer
    Action in the same group, no warning will be given, the Director will return
    an error upon attempting to create the simulation.

    Args:
      simulation_name: Name of the simulation to create
      simulation_description: Description of the simulation
      simulation_type: One of {"eval"|"sequence"}
    """

    if simulation_type not in ["eval", "sequence"]:
      raise ValueError("Simulation type must be 'evaluation' or 'sequence'")

    self.simulation_name = simulation_name
    self.simulation_description = simulation_description
    self.simulation_type = simulation_type

    self.steps: dict[str : list[str]] = {}
    self.step_names: list[str] = []

  """
  A note on Sequence/Eval creation
  Payloads expect 'steps' and 'step_names' keys
      'steps' is a dict of string integers (like '0', '1') to lists of integers
          This represents a mapping of zero-indexed groups to the list of string ids that should be in that group
      'step_names' is a list of strings
          This represents a sequential ordering of the names of the groups
  """

  def build_payload(self):
    return {
        "simulation": {
            "sim_type": self.simulation_type,
            "name": self.simulation_name,
            "desc": self.simulation_description,
            "steps": self.steps,
            "step_names": self.step_names,
        }
    }

  def add_step(self, name: str):
    """Add a new step (group) to the simulation.

    The required structure for creating simulations includes a "steps" key,
    which is a dictionary mapping zero-indexed string integers (i.e. "0", "1")
    to lists of integers that represent Action ids. It also requires a
    "step_names" key, which is a list representing a sequential ordering of
    group names.

    This method handles the above structure, adding a new group with the given
    name.

    Args:
      name: Name of the group to add.
    """
    next_step_id = str(len(self.steps.keys()))
    self.steps[next_step_id] = []
    self.step_names.append(name)

  def add_action(self, step: str | int, action: FullActionSubclass | int):
    """Add an Action to an existing step (group).

    Args:
      step: Step to add an Action to. These are zero-indexed string values.
        Provided integers will be cast to strings.
      action: An Action object or an Action ID (not a VID) representing the
        Action to add to the group.
    """
    step_key = str(step)
    if isinstance(action, Action):
      action_id = action.id
    elif isinstance(action, int):
      action_id = action
    else:
      raise ValueError("Must provide an Action object or an Action ID")

    if step_key not in self.steps:
      raise ValueError(f"Group {step_key} does not exist")

    self.steps[step_key].append(action_id)

  def auto_build_from_actions(self, actions: list[FullActionSubclass]):
    """Configures the SimulationFactory based on a provided list of Actions.

    The provided Actions will automatically be sorted into appropriate groups
    based on their type, OS tags, user tags, and run_as tags. Verodin tags will
    take priority over any "user" tags. If no verodin tags are present for a
    given category, user tags will be used. I.e. an Action w/Verodin OS tags and
    User OS tags will be grouped solely based on OS tags, ignoring the user-set
    tags. If the Action has no verodin run_as tags, but has user run_as tags,
    then it will be grouped based on the user run_as tags.


    This will overwrite any Actions and Steps added to this object using the
    `add_step` and `add_action` methods.

    Args:
      actions: A list of FullAction/ActionSubclass objects
    """

    def _obtain_action_criteria_for_grouping(input_action: FullActionSubclass):
      """Given an Action, extract attributes needed for grouping."""
      action_id = input_action.id
      action_type = input_action.action_type
      action_protected = input_action.require_endpoint

      # Could feasibly merge verodin/user tags instead, if needed
      if input_action.os_tags:
        action_os_tags = tuple(input_action.os_tags)
      else:
        action_os_tags = tuple(input_action.user_os_tags)
      if input_action.run_as_tags:
        action_run_as_tags = tuple(input_action.run_as_tags)
      else:
        action_run_as_tags = tuple(input_action.user_run_as_tags)
      if input_action.src_destination_tags:
        action_src_dst_tags = tuple(input_action.src_destination_tags)
      else:
        action_src_dst_tags = tuple(input_action.user_src_destination_tags)

      return {
          "entire_action": input_action._raw,
          "action_id": action_id,
          "action_type": action_type,
          "action_protected": action_protected,
          "action_os": action_os_tags,
          "action_run": action_run_as_tags,
          "action_src_dst": action_src_dst_tags,
      }

    # Create dataframe of actions with sortable criteria
    action_attribs = []
    for action in actions:
      action_attribs.append(
          _obtain_action_criteria_for_grouping(input_action=action)
      )
    panda_data = pandas.DataFrame(action_attribs)

    # Sort actions into groups by type, OS, RunAs, Src/Dst
    result = panda_data.groupby([
        "action_type",
        "action_protected",
        "action_os",
        "action_run",
        "action_src_dst",
    ])
    action_groupings: list[list[dict]] = []
    for group in result.groups:
      if group[1]:  # If action_protected is True for this group  # noqa
        for action_index in result.groups[group]:
          new_group: list[dict] = []
          loc = panda_data.index.get_loc(action_index)
          new_group.append(panda_data.iloc[loc]["entire_action"])
          action_groupings.append(new_group)
      else:
        new_group: list[dict] = []
        for action_index in result.groups[group]:
          loc = panda_data.index.get_loc(action_index)
          new_group.append(panda_data.iloc[loc]["entire_action"])
        action_groupings.append(new_group)

    steps_dict: dict[str : list[str]] = {}
    step_names_list: list[str] = []

    # From obtained groups, format data as expected by director
    current_group_num = 0
    for group in action_groupings:
      list_of_ids: list[str] = []
      for action in group:
        action_id = action["sim_action"]["id"]
        list_of_ids.append(action_id)
      new_key = str(current_group_num)
      steps_dict[new_key] = list_of_ids
      current_group_num += 1

    for key in steps_dict:
      step_names_list.append(f"PLACEHOLDER-{str(int(key) + 1)}")

    # Set factory object's attributes to use generated groups
    self.steps = steps_dict
    self.step_names = step_names_list


class VRTFile:

  def __init__(self, file_json: dict):
    """Represents a file in the MSV file transfer library.

    Related Actions are not returned by all endpoints.
    Requesting the ENTIRE file library will return all related Actions.
    If an individual file is requested,
    the related Actions key will NOT be present.

    Args:
      file_json: A dictionary containing file data in JSON format.
    """
    self._raw = file_json

    self.approved_user_id: int = 0
    self.created_at: str = ""
    self.disabled: bool = False
    self.file_action_type: any = None
    self.file_location: str = ""
    self.file_notes: str = ""
    self.file_restrictions: str = ""
    self.file_type: str = ""
    self.filesize: int = 0
    self.id: int = 0
    self.md5sum: str = ""
    self.metadata_version: int = 0
    self.organization_id: int = 0
    self.orig_file_name: str = ""
    self.os_tree_id: int = 0
    self.related_actions: list[dict[str : int | str]] = (
        []
    )  # Keys are id, vid, and name
    self.sha1sum: str = ""
    self.sha256sum: str = ""
    self.updated_at: str = ""
    self.user_metadata_version: int = 0
    self.user_tags: list[str] = []
    self.verodin_tags: list[str] = []

    for attribute in [
        "approved_user_id",
        "created_at",
        "disabled",
        "file_action_type",
        "file_location",
        "file_notes",
        "file_restrictions",
        "file_type",
        "filesize",
        "id",
        "md5sum",
        "metadata_version",
        "organization_id",
        "orig_file_name",
        "os_tree_id",
        "related_actions",
        "sha1sum",
        "sha256sum",
        "updated_at",
        "user_metadata_version",
        "user_tags",
        "verodin_tags",
    ]:

      if attribute in file_json:
        self.__setattr__(attribute, file_json[attribute])
      else:
        pass

  def __repr__(self):
    return f"VRT File: {self.md5sum} - {self.orig_file_name}"


def interpret_full_action(full_action_json: dict) -> FullActionSubclass:
  """Creates the appropriate subtype of FullAction

  based on the provided action JSON.

  Args:
    full_action_json: The JSON to interpret.

  Returns:
    An instance of a subtype of FullAction.
  """

  if "sim_action" in full_action_json:
    action_type_value = full_action_json["sim_action"]["action_type"]
  elif "action_type" in full_action_json:
    action_type_value = full_action_json["action_type"]
  else:
    raise ContentParsingError("Invalid JSON, no action type found")

  if action_type_value == "file_transfer":
    return FileTransferAction(full_action_json)
  elif action_type_value == "pcap":
    return PcapAction(full_action_json)
  elif action_type_value == "website":
    return WebAction(full_action_json)
  elif action_type_value == "email":
    return EmailAction(full_action_json)
  elif action_type_value == "dns":
    return DnsAction(full_action_json)
  elif action_type_value == "host_cli":
    return HostAction(full_action_json)
  elif action_type_value == "captive_dns":
    return CaptiveDnsAction(full_action_json)
  elif action_type_value == "captive_ioc_pcap":
    return CaptivePcapAction(full_action_json)
  elif action_type_value == "captive_ioc_url":
    return CaptiveUrlAction(full_action_json)
  elif action_type_value == "socket":
    return SocketAction(full_action_json)
  elif action_type_value == "port_scan":
    return PortScanAction(full_action_json)
  elif action_type_value == "cloud":
    return CloudAction(full_action_json)
  else:
    raise ContentParsingError("Unable to identify Action Type")
