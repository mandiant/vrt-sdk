This file contains incomplete documentation on some of the available classes
and methods in this package. This should not be considered exhaustive. It is
preferable to use documentation as rendered via your IDE and the examples
provided in this repository for guidance instead.

# Content

## Actions

Actions are either:

- A `PartialAction`
- A subclass of a `FullAction`
    - CaptiveDnsAction
    - CaptivePcapAction
    - CaptiveUrlAction
    - CloudAction
    - DnsAction
    - EmailAction
    - FileTransferAction
    - HostAction
    - PcapAction
    - SocketAction
    - WebAction

All Actions will share attributes like `vid`, `desc`, or `verodin_tags`.
Each `FullAction` subclass will have unique values, such as `domain` for
a `DnsAction`. Some Actions, such as Captive IOC Actions, have no unique values.

The JSON response used to construct an Action object can be accessed through
the `_raw` attribute if necessary.

## Files

Files are defined by the `VRTFile` class.

The JSON response used to construct a File object can be accessed through
the `_raw` attribute if necessary.

## Simulations

Simulations are represented as one of two subclasses of `Simulation`:

- A `Sequence`
- An `Evaluation`

Both types share the same attributes, all inherited from `Simulation`

The JSON response used to construct a Simulation object can be accessed through
the `_raw` attribute if necessary.

# Director Class

## add_tag_to_action

Adds a tag to an action.

Args:
target_action: Action to add a tag to
tag: Tag to add to the action
tag_type: For external users, one of
`{user_os|user_control|user_run_as|user_src_destination|user_mitre_mitigation|
user_nist_control|user}`. For VRT users and other Mandiant personnel,
the following types are also available
`{os|control|run_as|src_destination|mitre_mitigation|
nist_control|verodin}`. For VRT users, this does not need to be
specified if an enum is used.

Returns:
The JSON data from a response, if successful

Types:

target_action: str | int | vrt_sdk.content.Action

tag: enum.Enum | str

tag_type: <class 'str'>

return: <class 'dict'>

## add_tag_to_file

Adds a tag to a file_transfer_library entry.

Be aware that the file library can be slow to update. If you add a tag to a
file and then immediately attempt to pull the file library again, it is
possible that the update will not yet have occurred.

Args:
target_file: File to add a tag to.
tag: Tag to apply to the file.

Returns:
The JSON data from the response, if successful

Types:

target_file: int | vrt_sdk.content.VRTFile

tag: enum.Enum | str

return: <class 'dict'>

## add_tag_to_simulation

Adds a verodin/user tag to a Sequence or Evaluation.

Args:
target_simulation: Sequence or Evaluation to add a tag to.
tag: Tag to apply to the simulation.

Returns:
The JSON data from the response, if successful

Types:

target_simulation: str | int | vrt_sdk.content.Sequence |
vrt_sdk.content.Evaluation

tag: enum.Enum | str

return: <class 'dict'>

## create_dns_action

Creates a DNS Query Action.

Args:
action_name: The name of the Action.
action_description: The description of the Action.
domain: The domain to be used in this Action.

Returns:
A PartialAction object representing the created Action. Be aware that not
all fields are guaranteed to be populated.

Types:

action_name: <class 'str'>

action_description: <class 'str'>

domain: <class 'str'>

return: <class 'vrt_sdk.content.PartialAction'>

## create_email_action

Creates an Email Action.

Args:
action_name: The name of the Action.
action_description: The description of the Action.
body: The body of the email.
subject: The subject line of the email. Defaults to "Email".
mime_type: The mime_type of the email. Must be "html" or "plain". Defaults
to "html".
file_attachment: Either a VRTFile object or the id of the
file_transfer_library entry (file) to use for this Action. May be None
if no file is used (such as if the Action contains only a malicious
link).

Returns:
A PartialAction object representing the created Action. Be aware that not
all fields are guaranteed to be populated.

Types:

action_name: <class 'str'>

action_description: <class 'str'>

body: <class 'str'>

subject: <class 'str'>

mime_type: <class 'str'>

file_attachment: vrt_sdk.content.VRTFile | int | None

return: <class 'vrt_sdk.content.PartialAction'>

## create_file_transfer_action

Creates a file transfer action (MFT).

Creates an MFT using a GET request over HTTP/80 by default.

Must provide one of:

- A VRTFile object
- The file id and the OS value of the file for use

Args:
action_name: The name of the Action.
action_description: The description of the Action.
target_file: File to use in this Action. If provided, the OS Dimension for
the Action will be the same as the OS of the file.
file_id: The id of the file_transfer_library entry (file) to use for this
Action.
os_value: Operating system dimension as a string or
OSPlatformDimensionEnum.
method: Optional. Defaults to "get". Use at your own risk.
app_layer: Optional. Defaults to "http". Use at your own risk.
target_port: Optional. Must be string.

Returns:
A PartialAction object representing the created Action. Be aware that not
all fields are guaranteed to be populated.

Types:

action_name: <class 'str'>

action_description: <class 'str'>

target_file: vrt_sdk.content.VRTFile | None

file_id: int | None

os_value: str | vrt_sdk.enumerations.OSPlatformDimensionEnum | None

method: <class 'str'>

app_layer: <class 'str'>

target_port: str | int

return: <class 'vrt_sdk.content.PartialAction'>

## create_host_action

Creates a Host Action (Host CLI or PT) from a `HostActionFactory` object.

Args:
host_factory: A configured HostActionFactory. See documentation for
HostActionFactory for details on how to configure.

Returns:
A PartialAction object representing the created Action. Be aware that not
all fields are guaranteed to be populated.

Types:

host_factory: <class 'vrt_sdk.content.HostActionFactory'>

return: <class 'vrt_sdk.content.PartialAction'>

## create_simulation

Create a simulation (Sequence or Evaluation).

You can configure the simulation manually using a SimulationFactory, and
then provide that factory to this method to create the desired simulation.

If you just want to create a simulation out of a large collection of
Actions, and do not care about the ordering or grouping, you can instead
provide a list of Actions directly, and this method will handle configuring
the simulation automatically. This option will require you to provide
additional information (name, description, type).

Args:
factory: A configured SimulationFactory
actions: A list of Actions to create a simulation out of
simulation_name: Name of the simulation to create, required if actions
argument is used
simulation_description: Description of the simulation, required if actions
argument is used
simulation_type: One of {"eval"|"sequence"}, required if actions argument
is used

Returns:
JSON data from the request, if successful.

Types:

factory: vrt_sdk.content.SimulationFactory | None

actions: list[~FullActionSubclass] | None

simulation_name: <class 'str'>

simulation_description: <class 'str'>

simulation_type: <class 'str'>

return: <class 'dict'>

## export_all_content

Export all content from `/settings/content_export.json`.

Returns:
Bytes representing a vas file

Types:

return: <class 'bytes'>

## generate_trees

Generate a dimensions dictionary as expected by the director.

Requires exact strings for each dimension or an enum option (preferred).

Args:
attack_vector: Attack vector dimension as a string or enum option from
AttackVectorDimensionEnum
attacker_location: Attacker location dimension as a string or enum option
from AttackerLocationDimensionEnum
behavior_type: Behavior type dimension as a string or enum option from
BehaviorTypeDimensionEnum
covert: Covert dimension as a string or enum option from
CovertDimensionEnum
os_platform: Operating system dimension as a string or enum option from
OSPlatformDimensionEnum
stage_of_attack: Stage of attack dimension as a string or enum option from
StageOfAttackDimensionEnum

Returns:
A specially formatted dictionary that can be accepted by the director
during Action creation

Types:

attack_vector: str | vrt_sdk.enumerations.AttackVectorDimensionEnum

attacker_location: str | vrt_sdk.enumerations.AttackerLocationDimensionEnum

behavior_type: str | vrt_sdk.enumerations.BehaviorTypeDimensionEnum

covert: str | vrt_sdk.enumerations.CovertDimensionEnum

os_platform: str | vrt_sdk.enumerations.OSPlatformDimensionEnum

stage_of_attack: str | vrt_sdk.enumerations.StageOfAttackDimensionEnum

return: dict[slice(<class 'str'>,
dict[slice(<class 'str'>, <class 'int'>, None)], None)]

## get_action_compatible_environment

Return information about action compatibility from

"/manage_sims/actions/{target_id}/actors.json"

This endpoint returns information about appropriate action user profiles,
email profiles, actors, and "step options" for a given action.
Not all the information returned by the endpoint is accurate as of time
of writing, as described below

- The action user profiles are simply a list of all such profiles
  as the director has no way of knowing what user profiles will actually
  work
- The email profiles are also a list of all such profiles,
  even for actions that clearly don't need email profiles
- The returned actors do appear to be accurate
- Step options are not implemented.
  They are assumed to be `None` by this function

Args:
target_action: An Action to obtain compatibility information for

Returns:
A namedtuple (CompatibleEnvironment) containing the above information

Types:

target_action: str | int | vrt_sdk.content.Action

return: <class 'vrt_sdk.director.CompatibleEnvironment'>

## get_action_user_profiles

Obtain a list of ActionUserProfiles from "/action_user_profiles.json".

This is called by the Director class on object initialization.

To get a specific ActionUserProfile, it is better to call "lookup_aup_by_id"
to check the cached values on the Director object.

Returns:
A list of ActionUserProfiles

Types:

return: list[vrt_sdk.action_user_profile.ActionUserProfile]

### get_actors

Obtain a list of actors associated with this director from "/nodes.json"

This will ignore Protected *Theaters*, which are NOT the same as Protected
*Actors*.

Returns:
A list of Actors. Will be empty if an error is encountered.

Types:

return: list[vrt_sdk.actor.Actor]

## get_all_files

Obtains all files from the director from "/manage_sims/file_library.json".

Returns:
A list of VRTFile objects representing the file library.

Types:

return: list[vrt_sdk.content.VRTFile]

## get_all_full_actions

Obtains a list of full action jsons and instantiate them as objects.

First pulls all partial actions by querying
"/manage_sims/library_actions_list.json". Then uses the VIDs from each
partial action to obtain the full action.

Args:
multi_threaded: Whether to pull full action JSONs in parallel. Defaults to
True.

Returns:
A list of instances that are subclasses of FullAction,
dependent upon what type of Action is returned

Types:

multi_threaded: <class 'bool'>

return: list[~FullActionSubclass]

## get_all_jobs

Obtain a list of dictionaries containing abridged job data.

This will provide less information for a single job than the `get_job`
method.

Contains the following attributes:

- id
- plan_id
- status
- progress
- created_at
- updated_at
- organization_id
- status_desc
- user_id
- simulation_id
- node_action_queue_id

Returns:
A list of dictionaries representing abridged job data.

Types:

return: list[dict[slice(<class 'str'>, <built-in function any>, None)]]

## get_all_partial_actions

Obtains all partial actions from "/manage_sims/actions.json".

Returns:
A list of PartialAction objects

Types:

return: list[vrt_sdk.content.PartialAction]

## get_director_version

Get the version of this director.

Returns:
The version as a string (i.e. "4.11.0.0-95")

Types:

return: <class 'str'>

## get_email_profiles

Obtain a list of email profiles associated with this director

from "/settings/email_profiles.json".

This is called by the Director class on object initialization.

Returns:
A list of EmailProfiles

Types:

return: list[vrt_sdk.email_profile.EmailProfile]

## get_evaluations

Obtain a list of all evaluations from /simulations.json.

Returns:
A list of Evaluation objects

Types:

return: list[vrt_sdk.content.Evaluation]

## get_full_action_by_id

Obtains the full action JSON from "/manage_sims/actions/{action_id}.json".

Args:
action_id: Action ID, as int or string.

Returns:
A subclass of FullAction, dependent upon what type of Action is returned.

Types:

action_id: int | str

return: ~FullActionSubclass

## get_full_action_by_vid

Obtains the full action JSON from "
/manage_sims/actions/{vid}.json?lookup_type=vid".

Args:
vid: String like "A101-140".

Returns:
A subclass of FullAction, dependent upon what type of Action is returned.

Types:

vid: <class 'str'>

return: ~FullActionSubclass

## get_job

Retrieve information about a given job by ID.

This will provide more detail than the `get_all_jobs` method.

Args:
job_id: ID of the job to obtain, as an integer or string

Returns:
A Job object containing detailed data about a job.

Types:

job_id: int | str

return: <class 'vrt_sdk.job.Job'>

## get_sequences

Obtain a list of all evaluations from /simulations.json.

Returns:
A list of Sequence objects

Types:

return: list[vrt_sdk.content.Sequence]

## get_simulation_by_id

Given a VID, obtain the full simulation json.

Calls "/simulations/{vid}.json?lookup_type=vid".

Args:
simulation_id: ID of the simulation to obtain, as an integer or string

Returns:
Either a Sequence or Evaluation,
dependent upon what type of simulation is returned

Raises:
ContentParsingError: If the response does not appear to be a valid
Sequence or Evaluation

Types:

simulation_id: int | str

return: vrt_sdk.content.Sequence | vrt_sdk.content.Evaluation

## get_simulation_by_vid

Given a VID, obtain the full simulation json.

Calls "/simulations/{vid}.json?lookup_type=vid".

Args:
vid: String like "S101-140"

Returns:
Either a Sequence or Evaluation, dependent upon what type of simulation is
returned

Raises:
VidNotFoundError: If the Director returns a 404 "Not Found"
ContentParsingError: If the response does not appear to be a valid
Sequence or Evaluation

Types:

vid: <class 'str'>

return: vrt_sdk.content.Sequence | vrt_sdk.content.Evaluation

## lookup_actor_by_name

Looks up an Actor by name.

Use this instead of "get_actors", as this does not require a network call.

Args:
actor_name: The name of the actor (i.e., "brt-rnd-vna-01") to look up.

Returns:
The Actor with the given name. If no such Actor exists, returns None.

Types:

actor_name: <class 'str'>

return: vrt_sdk.actor.Actor | None

## lookup_actor_by_os

Return the first actor that matches the specified OS.

Args:
actor_os: Operating System to find an Actor for

Returns:
The first Actor with the given Operating System. If no such Actor exists,
return None.

Types:

actor_os: <enum 'OSTagEnum'>

return: vrt_sdk.actor.Actor | None

## lookup_aup_by_desc_substring

Obtains any ActionUserProfile w/a description containing the string.

Args:
substring: String to search for. Case insensitive

Returns:
A list of ActionUserProfiles that contain the provided string in their
description

Types:

substring: <class 'str'>

return: list[vrt_sdk.action_user_profile.ActionUserProfile]

## lookup_aup_by_friendly_name

Looks up an ActionUserProfile.

Use this instead of "get_action_user_profiles", as this does not require a
network call.

Args:
aup_name: The friendly name of the ActionUserProfile to find (case-
insensitive).

Returns:
The ActionUserProfile with the given ID.

Types:

aup_name: <class 'str'>

return: <class 'vrt_sdk.action_user_profile.ActionUserProfile'>

## lookup_dimension_id_by_name

Obtains the numerical ID of a dimension, given the name.

Args:
dimension_name: A string representing a dimension name, like
"Download-MFT".

Returns:
The integer representation of the dimension's ID, like 50.

Types:

dimension_name: <class 'str'>

return: <class 'int'>

## lookup_dimension_name_by_id

Obtains the string name of a dimension, given the numerical ID.

Args:
dimension_id: The integer representation of a dimension's ID, like 50.

Returns:
A string representing the dimension name, like "Download-MFT".

Types:

dimension_id: <class 'int'>

return: <class 'str'>

## remove_tag_from_action

Removes a tag from an Action.

Args:
target_action: Action to remove a tag from
tag: Tag to remove from the action
tag_type: For external users, one of
`{user_os|user_control|user_run_as|user_src_destination|user_mitre_mitigation|
user_nist_control|user}`. For VRT users and other Mandiant personnel,
the following types are also available
`{os|control|run_as|src_destination|mitre_mitigation|
nist_control|verodin}`. For VRT users, this does not need to be
specified if an enum is used.

Returns:
The JSON data from a response, if successful

Types:

target_action: str | int | vrt_sdk.content.Action

tag: enum.Enum | str

tag_type: <class 'str'>

return: <class 'dict'>

## remove_tag_from_file

Removes a tag from a file_transfer_library entry.

Args:
target_file: File to remove a tag from.
tag: Tag to remove from the file.

Returns:
The JSON data from the response, if successful

Types:

target_file: int | vrt_sdk.content.VRTFile

tag: enum.Enum | str

return: <class 'dict'>

## remove_tag_from_simulation

Removes a tag from a Sequence or Evaluation.

Args:
target_simulation: Sequence or Evaluation to remove a tag from.
tag: Tag to remove from the simulation.

Returns:
The JSON data from the response, if successful

Types:

target_simulation: str | int | vrt_sdk.content.Sequence |
vrt_sdk.content.Evaluation

tag: enum.Enum | str

return: <class 'dict'>

## run_action

Runs a single Action with the given settings.

Will attempt to automatically select valid settings if not provided.

Args:
action: The Action to execute. Can be an Action object, id (int), or VID
(str).
source_actor: The source actor. Can be an Actor object or id (int). All
actions require this to run. If not provided, a random Actor will be
provided out of all valid options for the given Action.
destination_actor: The destination actor. Can be an Actor object or id
(int). Only Actions requiring two Actors require this parameter. If not
provided, a random Actor will be provided out of all valid options for
the given Action.
action_user_profile: The user profile (user/admin/etc). Can be an
ActionUserProfile object or id (int). Only needed for host actions. If
not provided for a host action, an error will be raised.
source_email_profile: The source email profile. Can be an EmailProfile or
an id (int). Only needed for email actions. If not provided, a random
EmailProfile will be selected.
destination_email_profile: The destination email profile. Can be an
EmailProfile or an id (int). Only needed for email actions. If not
provided, a random EmailProfile will be selected.
proxy: Whether or not to use a proxy. I **think** this will default to
picking the first available proxy.
job_name: The name of the job. If not provided, will default to the format
"{username} || {VID}:{Action name}".

Returns:
The id of the created job as an integer.

Types:

action: vrt_sdk.content.Action | str | int

source_actor: vrt_sdk.actor.Actor | int

destination_actor: vrt_sdk.actor.Actor | int

action_user_profile: vrt_sdk.action_user_profile.ActionUserProfile | int

source_email_profile: vrt_sdk.email_profile.EmailProfile | int

destination_email_profile: vrt_sdk.email_profile.EmailProfile | int

proxy: <class 'bool'>

job_name: <class 'str'>

return: <class 'int'>

## set_host_factory_dimensions

Sets the dimensions of the HostActionFactory.

It is not possible to identify dimensions without use of a director,
therefore this method is required to set the dimensions of a planned
Host Action.

Args:
factory: The HostActionFactory instance to set dimensions on.
attack_vector: Attack vector dimension as a string or
AttackVectorDimensionEnum.
attacker_location: Attacker location dimension as a string or
AttackerLocationDimensionEnum.
behavior_type: Behavior type dimension as a string or
BehaviorTypeDimensionEnum.
covert: Covert dimension as a string or CovertDimensionEnum.
os_platform: Operating system dimension as a string or
OSPlatformDimensionEnum.
stage_of_attack: Stage of attack dimension as a string or
StageOfAttackDimensionEnum.

Types:

factory: <class 'vrt_sdk.content.HostActionFactory'>

attack_vector: str | vrt_sdk.enumerations.AttackVectorDimensionEnum

attacker_location: str | vrt_sdk.enumerations.AttackerLocationDimensionEnum

behavior_type: str | vrt_sdk.enumerations.BehaviorTypeDimensionEnum

covert: str | vrt_sdk.enumerations.CovertDimensionEnum

os_platform: str | vrt_sdk.enumerations.OSPlatformDimensionEnum

stage_of_attack: str | vrt_sdk.enumerations.StageOfAttackDimensionEnum

return: <class 'NoneType'>

## upload_file

Uploads a file to the file_transfer_library.

Uploads a file to the file_transfer_library (the default file library).
Raises a `FileUploadError` if the file already exists and
error_if_exists is True.

Args:
file_bytes: The bytes to upload to the file library.
file_name: Name of the file in the file library.
file_restrictions: File restrictions, one of
{'pending_approval'|'restricted_malicious'|'none'} or a
FileRestrictionsEnum.
file_notes: File description for file library entry.
os_value: Operating system dimension as a string or as an
OSPlatformDimensionEnum.

Returns:
The ID of the uploaded file on the director.

Types:

file_bytes: <class 'bytes'>

file_name: <class 'str'>

file_restrictions: str | vrt_sdk.enumerations.FileRestrictionsEnum

file_notes: <class 'str'>

os_value: str | vrt_sdk.enumerations.OSPlatformDimensionEnum

return: <class 'int'>

# Actor Class

## Actor

Contains information about an Actor attached to a Director. Is returned from
methods on the Director class. Should not be created manually.

### guessed_true_os

Attempt to identify the OS and coerce it to an OSTagEnum.

Returns: An OSTagEnum

# Enumerations

Enumerations are defined to make it easier to provide valid information to the
MSV API. Use of enumerations over string values is _strongly_ encouraged.

## Dimension Enumerations

### AttackerLocationDimensionEnum

- EXTERNAL
- GENERAL_LOCATION
- INTERNAL

### AttackVectorDimensionEnum

- ACTIVE_DIRECTORY
- APACHE
- CHROME
- DB2
- DESKTOP
- DNS
- EMAIL
- FIREFOX
- GENERAL_APPLICATION
- GENERAL_BROWSER
- GENERAL_DB
- GENERAL_DS
- GENERAL_PROTOCOLS
- GENERAL_VECTOR
- GENERAL_WEB_SERVER
- HTTP_HTTPS
- ICMP
- IE
- IIS
- KERBEROS
- LDAP
- MS_SQL
- MYSQL
- NGINX
- ORACLE
- OS
- POSTGRESQL
- RDP
- SAFARI
- SMB
- SNMP
- SSH
- VPN
- WEB
- WEB_FRAMEWORK

### BehaviorTypeDimensionEnum

- BEACONING
- BRUTE_FORCE
- COMMAND_INJECTION
- CONTROL
- CSRF
- DOS
- DOWNLOAD_EXFIL
- DOWNLOAD_MFT
- FINGERPRINTING
- GENERAL_AUTHENTICATION_AND_AUTHORIZATION
- GENERAL_BEHAVIOR
- GENERAL_COMMAND_AND_CONTROL
- GENERAL_EXFIL
- GENERAL_MFT
- GENERAL_POLICY_EVASION
- GENERAL_REMOTE_ACCESS
- GENERAL_SCANNING_AND_ENUMERATION
- GENERAL_WEB_ATTACK
- IMPERSONATION
- MALICIOUS_DNS_QUERY
- MALWARE_EXECUTION
- MAN_IN_THE_MIDDLE
- PEER_TO_PEER
- PHISHING
- PING_SWEEPS
- POLICY_DISCOVERY
- PORT_SCANS
- PRIVILEGE_ESCALATION
- PROTOCOL_ABUSE
- RESTRICTED_SITES_MEDIA_STREAMING
- REVERSE_SHELL
- SQL_INJECTION
- UPLOAD_EXFIL
- UPLOAD_MFT
- VULNERABILITY_SCANNERS
- WEB_CRAWLERS
- WEB_SHELL
- XSS

### CovertDimensionEnum

- NO
- YES

### OSPlatformDimensionEnum

- GENERAL_OS_PLATFORM
- LINUX
- MAC
- WINDOWS

### StageOfAttackDimensionEnum

- ACTION_ON_TARGET
- COMMAND_AND_CONTROL
- DELIVERY
- EXECUTION
- EXPLOITATION
- RECONNAISSANCE

## Tag Enumerations

### ControlTagEnum

- ATP
- AV
- DLP
- DNS_FW
- EMAIL
- ENDPOINT
- IDS_IPS
- NGFW
- PROXY
- WAF

### OSTagEnum

- ANY
- LINUX
- LINUX_CENTOS
- LINUX_UBUNTU
- MACOS
- WINDOWS
- WINDOWS_10
- WINDOWS_11
- WINDOWS_7
- WINDOWS_SERVER_2012
- WINDOWS_SERVER_2016
- WINDOWS_SERVER_2019
- WINDOWS_SERVER_2022

### RunAsTagEnum

- USER
- ADMIN
- SYSTEM
- ROOT

### SrcDstTagEnum

- SRC_DMZ_DST_DMZ
- SRC_DMZ_DST_EXTERNAL_UNTRUSTED
- SRC_DMZ_DST_INTERNAL_TRUSTED
- SRC_EXTERNAL_UNTRUSTED_DST_DMZ
- SRC_EXTERNAL_UNTRUSTED_DST_INTERNAL_TRUSTED
- SRC_INTERNAL_TRUSTED
- SRC_INTERNAL_TRUSTED_DST_DMZ
- SRC_INTERNAL_TRUSTED_DST_EXTERNAL_TRUSTED
- SRC_INTERNAL_TRUSTED_DST_EXTERNAL_UNTRUSTED
- SRC_INTERNAL_TRUSTED_DST_INTERNAL_TRUSTED

## Other Enumerations

### AUPUserTypeEnum

- USER
- ADMIN
- SYSTEM
- ROOT
- UNKNOWN

### FileRestrictionsEnum

- NONE
- PENDING_APPROVAL
- RESTRICTED_MALICIOUS

### JobActionResultEnum

- CANCELLED
- CHECKING
- ERRORED
- INCOMPATIBLE
- NOT_RUN
- PENDING
- RAN
- REVERTING
- RUNNING
- SLEEPING
- UNKNOWN
- WAITING

### MalwareToolTypeEnum

- ARCHIVER
- ATM_MALWARE
- BACKDOOR
- BACKDOOR_BOTNET
- BOOTKIT
- BUILDER
- CONTROLLER
- CREDENTIAL_STEALER
- CRYPTOCURRENCY_MINER
- DATA_MINER
- DISRUPTION_TOOL
- DOWNLOADER
- DRIVER
- DROPPER
- DROPPER_MEMORY_ONLY
- EXPLOIT
- EXPLOIT_BUILDER
- FILE_INFECTOR
- FRAMEWORK
- INSTALLER
- KEYLOGGER
- LATERAL_MOVEMENT_TOOL
- LAUNCHER
- LIGHTWEIGHT_BACKDOOR
- MACRO
- MODULE
- POINT_OF_SALE_MALWARE
- PRIVILEGE_ESCALATION_TOOL
- RANSOMWARE
- RECONNAISSANCE_TOOL
- REMOTE_EXPLOITATION_TOOL
- ROOTKIT
- SCREEN_CAPTURE_TOOL
- SHELLCODE
- SNIFFER
- SPAMBOT
- TUNNELER
- UPLOADER
- UTILITY
- WEBSHELL

### JobStatusEnum

- CANCELLED
- COMPLETED
- ERROR
- ERRORED
- PENDING
- PREPARING
- RUNNING
- UNKNOWN
- WAITING

==========

# Factory Classes

Host Actions (Host CLI and Protected Theater) and Simulations (Sequences and
Evaluations) are complicated to create via the API. These classes provide
simplified ways to create such content without having to grapple with the
required JSON structure.

## HostActionFactory

Factory class for creating Host-based Actions (Host CLI and PT Actions).

### add_file

Adds a file dependency to the planned Host Action.

Does not protect against adding duplicates.

Args:
file_id: The ID of the file_transfer_library entry (file) to add to the
action.
destination_directory: The directory to place the file on disk.
Ex: "C:\Windows\Temp".
destination_name: The name of the file on disk.
Ex: "example_evil_file.bin".
file_owner: Owner of the file. Defaults to "system".

Types:

file_id: <class 'int'>

destination_directory: <class 'str'>

destination_name: <class 'str'>

file_owner: <class 'str'>

return: <class 'NoneType'>

### add_step

Adds a command to the planned Host Action.

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

Types:

text: <class 'str'>

prompt_regex: <class 'str'>

sleep: int | str

timeout: int | str

criteria: <class 'str'>

return: <class 'NoneType'>

### build_payload

Builds the payload to be sent to the director to create a Host Action.

You should not need to call this.

:return: A dict representing a payload for Host Action creation

Types:

return: <class 'dict'>

## SimulationFactory

Factory class for creating Sequences and Evaluations.

### add_action

Add an Action to an existing step (group).

Args:
step: Step to add an Action to. These are zero-indexed string values.
Provided integers will be cast to strings.
action: An Action object or an Action ID (not a VID) representing the
Action to add to the group.

Types:

step: str | int

action: typing.Union[~FullActionSubclass, int]

### add_step

Add a new step (group) to the simulation.

The required structure for creating simulations includes a "steps" key,
which is a dictionary mapping zero-indexed string integers (i.e. "0", "1")
to lists of integers that represent Action ids. It also requires a
"step_names" key, which is a list representing a sequential ordering of
group names.

This method handles the above structure, adding a new group with the given
name.

Args:
name: Name of the group to add.

Types:

name: <class 'str'>

### auto_build_from_actions

Configures the SimulationFactory based on a provided list of Actions.

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

Types:

actions: list[~FullActionSubclass]
