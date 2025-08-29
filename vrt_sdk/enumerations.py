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

import difflib
import enum
from enum import Enum


class ControlTagEnum(Enum):
  """An Enum containing the accepted values for Control tags.

  Call `list_of_control_tags` to get the accepted Control tags
  as accepted by the director (i.e. `Control:Email`)
  """

  ATP = "ATP"
  AV = "AV"
  DLP = "DLP"
  DNS_FW = "DNS-FW"
  EMAIL = "Email"
  ENDPOINT = "Endpoint"
  IDS_IPS = "IDS/IPS"
  NGFW = "NGFW"
  PROXY = "Proxy"
  WAF = "WAF"

  @classmethod
  def list_of_control_tags(cls):
    """Returns the tags structured like `Control:Endpoint` and `Control:NGFW`.

    These are what the values look like in the Action JSON
    """
    return [f"Control:{entry.value}" for entry in cls]


class SrcDstTagEnum(Enum):
  """An Enum containing the accepted values for SrcDst tags.

  Call `list_of_src_dst_tags` to get the accepted SrcDst tags
  as accepted by the director (i.e. `Src:Internal:Trusted+Dst:DMZ`)
  """

  SRC_DMZ_DST_DMZ = "Src:DMZ+Dst:DMZ"
  SRC_DMZ_DST_EXTERNAL_UNTRUSTED = "Src:DMZ+Dst:External:Untrusted"
  SRC_DMZ_DST_INTERNAL_TRUSTED = "Src:DMZ+Dst:Internal:Trusted"
  SRC_EXTERNAL_UNTRUSTED_DST_DMZ = "Src:External:Untrusted+Dst:DMZ"
  SRC_EXTERNAL_UNTRUSTED_DST_INTERNAL_TRUSTED = (
      "Src:External:Untrusted+Dst:Internal:Trusted"
  )
  SRC_INTERNAL_TRUSTED = "Src:Internal:Trusted"
  SRC_INTERNAL_TRUSTED_DST_DMZ = "Src:Internal:Trusted+Dst:DMZ"
  SRC_INTERNAL_TRUSTED_DST_EXTERNAL_TRUSTED = (
      "Src:Internal:Trusted+Dst:External:Trusted"
  )
  SRC_INTERNAL_TRUSTED_DST_EXTERNAL_UNTRUSTED = (
      "Src:Internal:Trusted+Dst:External:Untrusted"
  )
  SRC_INTERNAL_TRUSTED_DST_INTERNAL_TRUSTED = (
      "Src:Internal:Trusted+Dst:Internal:Trusted"
  )

  @classmethod
  def list_of_src_dst_tags(cls):
    """Returns the tags structured like `Src:Internal:Trusted

     and `Src:Internal:Trusted+Dst:DMZ`.

    These are what the values look like in the Action JSON
    """
    return [f"{entry.value}" for entry in cls]


class OSTagEnum(Enum):
  """An Enum containing the accepted values for OS tags.

  Call `list_of_os_tags` to get the accepted OS tags as accepted by the director
  (i.e. `OS:Windows:10`)
  """

  ANY = "ANY"
  LINUX = "Linux"
  LINUX_CENTOS = "Linux:CentOS"
  LINUX_UBUNTU = "Linux:Ubuntu"
  MACOS = "macOS"
  WINDOWS = "Windows"
  WINDOWS_SERVER_2012 = "Windows Server:2012"
  WINDOWS_SERVER_2016 = "Windows Server:2016"
  WINDOWS_SERVER_2019 = "Windows Server:2019"
  WINDOWS_SERVER_2022 = "Windows Server:2022"
  WINDOWS_10 = "Windows:10"
  WINDOWS_11 = "Windows:11"
  WINDOWS_7 = "Windows:7"

  @classmethod
  def list_of_os_tags(cls):
    """Returns the tags structured like `OS:Windows:10` and `OS:ANY` .

    These are what the values look like in the Action JSON.
    """
    return [f"OS:{entry.value}" for entry in cls]


class RunAsTagEnum(Enum):
  """An Enum containing the accepted values for RunAs tags.

  Call `list_of_run_as_tags` to get the accepted RunAs tags as accepted
  by the director (i.e. `RunAs:Admin`).
  """

  ADMIN = "Admin"
  ROOT = "Root"
  SYSTEM = "SYSTEM"
  USER = "User"

  @classmethod
  def list_of_run_as_tags(cls):
    """Returns the tags structured like `RunAs:Admin` and `RunAs:SYSTEM`.

    These are what the values look like in the Action JSON
    """
    return [f"RunAs:{entry.value}" for entry in cls]


class MalwareToolTypeEnum(Enum):
  """An Enum containing the accepted values for Malware_Type/Tool_Type tags.

  Call `list_of_malware_type_tags` and `list_of_tool_type_tags` to get tags
  as accepted by the director (i.e. `Malware_Type:BACKDOOR`).
  """

  ARCHIVER = "ARCHIVER"
  ATM_MALWARE = "ATM_MALWARE"
  BACKDOOR = "BACKDOOR"
  BACKDOOR_BOTNET = "BACKDOOR_BOTNET"
  BOOTKIT = "BOOTKIT"
  BUILDER = "BUILDER"
  CONTROLLER = "CONTROLLER"
  CREDENTIAL_STEALER = "CREDENTIAL_STEALER"
  CRYPTOCURRENCY_MINER = "CRYPTOCURRENCY_MINER"
  DATA_MINER = "DATA_MINER"
  DISRUPTION_TOOL = "DISRUPTION_TOOL"
  DOWNLOADER = "DOWNLOADER"
  DRIVER = "DRIVER"
  DROPPER = "DROPPER"
  DROPPER_MEMORY_ONLY = "DROPPER_MEMORY_ONLY"
  EXPLOIT = "EXPLOIT"
  EXPLOIT_BUILDER = "EXPLOIT_BUILDER"
  FILE_INFECTOR = "FILE_INFECTOR"
  FRAMEWORK = "FRAMEWORK"
  KEYLOGGER = "KEYLOGGER"
  INSTALLER = "INSTALLER"
  LATERAL_MOVEMENT_TOOL = "LATERAL_MOVEMENT_TOOL"
  LAUNCHER = "LAUNCHER"
  LIGHTWEIGHT_BACKDOOR = "LIGHTWEIGHT_BACKDOOR"
  MACRO = "MACRO"
  MODULE = "MODULE"
  POINT_OF_SALE_MALWARE = "POINT_OF_SALE"  # "Point-Of-Sale Malware"
  PRIVILEGE_ESCALATION_TOOL = "PRIVILEGE_ESCALATION_TOOL"
  RANSOMWARE = "RANSOMWARE"
  RECONNAISSANCE_TOOL = "RECONNAISSANCE_TOOL"
  REMOTE_EXPLOITATION_TOOL = "REMOTE_EXPLOITATION_TOOL"
  ROOTKIT = "ROOTKIT"
  SCREEN_CAPTURE_TOOL = "SCREEN_CAPTURE_TOOL"
  SHELLCODE = "SHELLCODE"
  SNIFFER = "SNIFFER"
  SPAMBOT = "SPAMBOT"
  TUNNELER = "TUNNELER"
  UPLOADER = "UPLOADER"
  UTILITY = "UTILITY"
  WEBSHELL = "WEBSHELL"  # "Backdoor - Webshell"

  @classmethod
  def list_of_tool_type_tags(cls):
    """Returns the tags structured like `Tool_Type:UPLOADER`

    and `Tool_Type:FRAMEWORK`.

    These are what the values look like in the Action JSON.
    """
    return [f"Tool_Type:{entry.value}" for entry in cls]

  @classmethod
  def list_of_malware_type_tags(cls):
    """Returns the tags structured like `Malware_Type:DROPPER`

    and `Malware_Type:RANSOMWARE`.

    These are what the values look like in the Action JSON.
    """
    return [f"Malware_Type:{entry.value}" for entry in cls]

  @classmethod
  def coerce_to_type_tag(cls, value: str, tag_type: str = "malware"):
    """Uses string processing to convert a string

    to a malware_type/tool_type tag.

    Uses string processing and difflib to attempt to convert a string to the
    closest appropriate malware_type/tool_type tag.

    Args:
      value: The string to coerce to a malware_type/tool_type tag.
      tag_type: "malware" or "tool". Will be overridden if value contains some
        variant of "malware" or "tool".

    Returns:
      The closest tag from the list of valid tags
      (i.e., "Malware_Type:BACKDOOR").
    """
    if value.lower().startswith("malware"):
      tag_type = "malware"
    if value.lower().startswith("tool"):
      tag_type = "tool"
    value = value.upper()
    value = value.replace(" ", "_")
    value = value.replace("-", "_")

    value = value.replace("MALWARE:", "")
    value = value.replace("TOOL:", "")
    value = value.replace("MALWARE_TYPE:", "")
    value = value.replace("TOOL_TYPE:", "")
    value = value.replace("MALWARETYPE:", "")
    value = value.replace("TOOLTYPE:", "")

    closest_match = difflib.get_close_matches(
        value, [entry.value for entry in cls], 1, 0.6
    )

    if not closest_match:
      return None

    if tag_type == "tool":
      return f"Tool_Type:{closest_match[0]}"
    elif tag_type == "malware":
      return f"Malware_Type:{closest_match[0]}"
    else:
      raise Exception(
          f"Failure - Processed string {value} could not be coerced"
      )


class AttackVectorDimensionEnum(Enum):
  """An Enum containing the accepted values for the Attack Vector Dimension."""

  GENERAL_VECTOR = "General-Vector"
  GENERAL_APPLICATION = "General-Application"
  DESKTOP = "Desktop"
  WEB = "Web"
  GENERAL_BROWSER = "General-Browser"
  CHROME = "Chrome"
  FIREFOX = "Firefox"
  IE = "IE"
  SAFARI = "Safari"
  GENERAL_DB = "General-DB"
  DB2 = "DB2"
  MS_SQL = "MS-SQL"
  MYSQL = "MySQL"
  ORACLE = "Oracle"
  POSTGRESQL = "PostgreSQL"
  GENERAL_DS = "General-DS"
  ACTIVE_DIRECTORY = "Active Directory"
  KERBEROS = "Kerberos"
  LDAP = "LDAP"
  EMAIL = "Email"
  OS = "OS"
  GENERAL_PROTOCOLS = "General-Protocols"
  DNS = "DNS"
  HTTP_HTTPS = "HTTP(S)"
  ICMP = "ICMP"
  SMB = "SMB"
  SNMP = "SNMP"
  RDP = "RDP"
  SSH = "SSH"
  VPN = "VPN"
  WEB_FRAMEWORK = "Web Framework"
  GENERAL_WEB_SERVER = "General-Web Server"
  APACHE = "Apache"
  IIS = "IIS"
  NGINX = "Nginx"


class AttackerLocationDimensionEnum(Enum):
  """An Enum containing the accepted values

  for the Attacker Location Dimension.
  """

  GENERAL_LOCATION = "General-Location"
  EXTERNAL = "External"
  INTERNAL = "Internal"


class BehaviorTypeDimensionEnum(Enum):
  """An Enum containing the accepted values for the Behavior Type Dimension."""

  GENERAL_BEHAVIOR = "General-Behavior"
  GENERAL_AUTHENTICATION_AND_AUTHORIZATION = "General-A&A"
  BRUTE_FORCE = "Brute Force"
  IMPERSONATION = "Impersonation"
  PRIVILEGE_ESCALATION = "Privilege Escalation"
  GENERAL_COMMAND_AND_CONTROL = "General-C&C Comm"
  BEACONING = "Beaconing"
  CONTROL = "Control"
  GENERAL_EXFIL = "General-Exfil"
  DOWNLOAD_EXFIL = "Download-Exfil"
  UPLOAD_EXFIL = "Upload-Exfil"
  DOS = "DoS"
  MALICIOUS_DNS_QUERY = "Malicious DNS Query"
  GENERAL_MFT = "General-MFT"
  DOWNLOAD_MFT = "Download-MFT"
  UPLOAD_MFT = "Upload-MFT"
  MALWARE_EXECUTION = "Malware Execution"
  MAN_IN_THE_MIDDLE = "Man-in-the-Middle"
  PHISHING = "Phishing"
  GENERAL_POLICY_EVASION = "General-Policy Evasion"
  PEER_TO_PEER = "Peer-to-peer"
  PROTOCOL_ABUSE = "Protocol Abuse"
  RESTRICTED_SITES_MEDIA_STREAMING = "Restricted sites/media streaming"
  GENERAL_REMOTE_ACCESS = "General-Remote Access"
  REVERSE_SHELL = "Reverse Shell"
  WEB_SHELL = "Web Shell"
  GENERAL_SCANNING_AND_ENUMERATION = "General-Scanning & Enumeration"
  FINGERPRINTING = "Fingerprinting"
  PING_SWEEPS = "Ping Sweeps"
  POLICY_DISCOVERY = "Policy Discovery"
  PORT_SCANS = "Port Scans"
  VULNERABILITY_SCANNERS = "Vulnerability Scanners"
  WEB_CRAWLERS = "Web Crawlers"
  GENERAL_WEB_ATTACK = "General-Web Attack"
  COMMAND_INJECTION = "Command Injection"
  CSRF = "CSRF"
  SQL_INJECTION = "SQL Injection"
  XSS = "XSS"


class CovertDimensionEnum(Enum):
  """An Enum containing the accepted values for the Covert Dimension."""

  NO = "No"
  YES = "Yes"


class OSPlatformDimensionEnum(Enum):
  """An Enum containing the accepted values for the OS/Platform Dimension."""

  GENERAL_OS_PLATFORM = "General-OS/Platform"
  LINUX = "Linux"
  MAC = "Mac"
  WINDOWS = "Windows"


class StageOfAttackDimensionEnum(Enum):
  """An Enum containing the accepted values

  for the Stage of Attack Dimension.
  """

  RECONNAISSANCE = "Reconnaissance"
  DELIVERY = "Delivery"
  EXPLOITATION = "Exploitation"
  EXECUTION = "Execution"
  COMMAND_AND_CONTROL = "Command & Control"
  ACTION_ON_TARGET = "Action on Target"


class AUPUserTypeEnum(enum.Enum):
  """An Enum containing the possible values for Action User Profile types."""

  USER = "User"
  ADMIN = "Admin"
  SYSTEM = (  # Note: This is not an actual value you will see in the JSON
      "SYSTEM"
  )
  ROOT = "Root"
  UNKNOWN = ""


class JobStatusEnum(enum.Enum):
  """Enum for possible job statuses."""

  ERROR = "error"
  ERRORED = "errored"
  COMPLETED = "completed"
  CANCELLED = "cancelled"
  RUNNING = "running"
  PENDING = "pending"
  WAITING = "waiting"
  PREPARING = "preparing"

  UNKNOWN = "unknown"

  @classmethod
  def __missing__(cls, key):
    return cls.UNKNOWN


class JobActionResultEnum(enum.Enum):
  """Enum for possible JobAction results."""

  # ALERTED = 'Alerted'
  # BLOCKED = 'Blocked'
  # ERRORED = 'Errored'
  # INCOMPATIBLE = 'Incompatible'
  # NOT_BLOCKED = 'Not Blocked'
  # NOT_RUN = 'Not Run'
  # RUNNING = 'Running'
  # WAITING = 'Waiting'
  # Active
  PENDING = "pending"
  RUNNING = "running"
  SLEEPING = "sleeping"
  WAITING = "waiting"
  CHECKING = "checking"

  # Incomplete
  NOT_RUN = "not run"
  ERRORED = "errored"

  # Finished
  RAN = "ran"
  CANCELLED = "cancelled"

  # Unknown - It isn't clear if these are legitimate statuses or not
  # They are in the same source file, but not in the enumeration, could be an oversight
  INCOMPATIBLE = "incompatible"
  REVERTING = "reverting"

  UNKNOWN = "unknown"

  @classmethod
  def __missing__(cls, key):
    return cls.UNKNOWN

  # Completed
  # RAN is also considered Completed, for some reason
  # ERRORED is also considered Incomplete, for some reason


class FileRestrictionsEnum(enum.Enum):
  """Enum for possible file_transfer_library entry restrictions."""

  PENDING_APPROVAL = "pending_approval"
  RESTRICTED_MALICIOUS = "restricted_malicious"
  NONE = "none"
