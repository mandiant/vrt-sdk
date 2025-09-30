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

# pylint: disable=undefined-variable
# ^^^ pylint is returning false positives w/this warning

from collections import namedtuple
import concurrent.futures
import configparser
import os
import random

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
import vrt_sdk.enumerations

from .action_user_profile import *
from .actor import *
from .content import *
from .email_profile import *
from .job import *

CompatibleEnvironment = namedtuple(
    "CompatibleEnvironment", "au_profiles email_profiles actor_ids step_options"
)
"""A namedtuple containing information from 
"/manage_sims/actions/{target_id}/actors.json"""


class Director:

  def __init__(
      self,
      director_name: str = None,
      director_address: str = None,
      director_username: str = None,
      director_apikey: str = None,
      director_org_id: int = None,
      vrt_config_path: str = None,
      vrt_authority: bool = False,
  ):
    """Class representing an MSV Director.

    Provides a variety of methods for interacting with the MSV Platform.
    There are three ways to construct a Director client.

    1. If an appropriate config file is set up, simply provide the director name
    as specified in the config, i.e. `Director("local")` or `Director("rnd1")`.

    2. Specify the director name and the config file,
    i.e. `Director("rnd1", vrt_config_path="/home/user/config.ini")`

    3. Provide the director address, username, api key, and organization id
    (if using SaaS). For example,
    `Director("director_address="hxxps://mandiant[.]com",
    director_username="john", director_apikey="1234abcd")`. If using SaaS,
    then the org id parameter needs to be provided as well.

    Args:
      director_name: Name of the director in a config file
      director_address: URL the director is located at
      director_username: Username to use with the director
      director_apikey: The API Key to use with the director
      director_org_id: The organization ID if the director is SaaS
      vrt_config_path: Path for an ini config file to use
      vrt_authority: Used to govern whether tags should be set as verodin tags
        or user tags. External parties should not use this, as they do not have
        authority to set verodin tags, and this will only result in errors.
    """

    self.address: str = ""
    self.username: str = ""
    self.apikey: str | None = None
    self.org_id: int | None = None
    self._vrt_authority: bool = vrt_authority

    self._session_object = requests.Session()

    self._dimension_cache = {}

    vrt_config: None | configparser.ConfigParser = None

    # If provided a config path as an argument, attempt to use that first
    if vrt_config_path:
      vrt_config = configparser.ConfigParser()
      result = vrt_config.read(vrt_config_path)
      if not result:
        vrt_config = None

    # If not provided a config path or could not read at that path,
    # check environment variables
    if not vrt_config:
      try:
        vrt_config = configparser.ConfigParser()
        result = vrt_config.read(os.environ["VRTCONFIG"])
        if not result:
          vrt_config = None
      except KeyError:
        vrt_config = None

    # If provided a director name, but we could not parse the config, we can't
    # create a client
    if director_name and not vrt_config:
      print(f"Could not read config, could not find {director_name}")
      raise configparser.ParsingError("Unable to read config")

    # If given a director name, instantiate (whether on prem or saas)
    if director_name:
      try:
        identifier = vrt_config.get("msv_directors", director_name)
      except configparser.NoSectionError:
        print("Could not find [msv_directors]")
        raise
      except configparser.NoOptionError:
        print(f"Could not find director entry for {director_name}")
        raise

      try:
        dirtype = vrt_config.get(identifier, "type")
      except configparser.NoSectionError:
        print("Could not find []")
        raise
      except configparser.NoOptionError:
        print("Missing type field")
        raise

      if dirtype == "onprem":
        self.address = identifier
        self.username = vrt_config.get(identifier, "username")
        self.apikey = vrt_config.get(identifier, "apikey")
      elif dirtype == "saas":
        self.address = vrt_config.get("msv_saas", "address")
        self.username = vrt_config.get(identifier, "username")
        self.apikey = vrt_config.get("msv_saas", "apikey")
        self.org_id = identifier
      else:
        raise ValueError('Director type must be "onprem" or "saas"')

    elif director_address and director_username and director_apikey:
      self.address = director_address
      self.username = director_username
      self.apikey = director_apikey
      if director_org_id:
        self.org_id = director_org_id

    else:
      raise ValueError("Invalid set of arguments provided")

    # If we have a config, check for VRT authority
    if vrt_config:
      try:
        val = vrt_config.get("msv", "vrt")
        if val:
          self._vrt_authority = True
      except (configparser.NoSectionError, configparser.NoOptionError):
        pass

    # ----------------------------------------------------------------------

    self._build_dimensions_cache()

    self.actors: dict[int:Actor] = {item.id: item for item in self.get_actors()}
    self.action_user_profiles: dict[int:ActionUserProfile] = {
        item.aup_id: item for item in self.get_action_user_profiles()
    }
    self.email_profiles: list[EmailProfile] = self.get_email_profiles()

  def __repr__(self):
    return f"Director client for {self.address}"

  def _build_dimensions_cache(self) -> None:
    """Private function used to create a dictionary of dimension IDs.

    Should not need to be called by users.
    """
    response = self._request("GET", "/manage_sims/actions/get_dimensions.json")
    response_json = response.json()
    for category in response_json:
      self._dimension_cache[category["name"]] = {}
      for entry in category["children"]:
        self._dimension_cache[category["name"]][entry["name"]] = entry["value"]
        if entry["children"]:
          for subentry in entry["children"]:
            self._dimension_cache[category["name"]][subentry["name"]] = (
                subentry["value"]
            )

  def _request(
      self,
      method: str,
      resource: str,
      **kwargs,
  ) -> requests.Response:
    """Makes an HTTP request to the director.

    Wrapper around a requests Session. Used to handle all HTTP communication
    with the director. Not intended for users to call, but it can be used to
    make calls to endpoints that the SDK does not cover.

    Args:
      method: The HTTP method to use (e.g., "GET", "POST").
      resource: The resource to request (e.g.. "/endpoint.json")
      **kwargs: Keyword arguments, passed directly to requests.Session.

    Returns:
      A requests Response object from the director.
    """

    if method not in ["GET", "POST", "DELETE", "PUT"]:
      raise ValueError("Method must be one of GET, POST, DELETE, PUT")

    kwargs["headers"] = kwargs.get("headers", {})

    if "Authorization" not in kwargs["headers"]:
      kwargs["headers"]["Authorization"] = f"Bearer {self.apikey}"

    if self.org_id and "Mandiant-Organization" not in kwargs["headers"]:
      kwargs["headers"]["Mandiant-Organization"] = f"Id {self.org_id}"

    if method == "GET":
      response = self._session_object.get(
          "https://" + self.address + resource,
          **kwargs,
      )
    elif method == "POST":
      response = self._session_object.post(
          "https://" + self.address + resource,
          **kwargs,
      )
    elif method == "DELETE":
      response = self._session_object.delete(
          "https://" + self.address + resource,
          **kwargs,
      )
    elif method == "PUT":
      response = self._session_object.put(
          "https://" + self.address + resource,
          **kwargs,
      )
    else:
      raise ValueError("Must use one of {GET|POST|DELETE|PUT}")

    if response.status_code == 404 and "not found" in response.reason.lower():
      raise VidNotFoundError(f"Could not find specified content")

    elif response.status_code == 401 and response.reason == "Unauthorized":
      raise AuthenticationError(
          "HTTP 401: Unauthorized - Suspected invalid creds"
      )

    elif (
        response.status_code == 422
        and response.text
        == '{"sha256sum":["must be unique within the file library"]}'
    ):
      raise FileExistsOnDirectorError

    try:
      response.raise_for_status()
    except requests.exceptions.HTTPError:
      # print(response.reason)
      # print(response.text)
      raise

    return response

  def generate_trees(
      self,
      attack_vector: str | AttackVectorDimensionEnum,
      attacker_location: str | AttackerLocationDimensionEnum,
      behavior_type: str | BehaviorTypeDimensionEnum,
      covert: str | CovertDimensionEnum,
      os_platform: str | OSPlatformDimensionEnum,
      stage_of_attack: str | StageOfAttackDimensionEnum,
  ) -> dict[str : dict[str:int]]:
    """Generate a dimensions dictionary as expected by the director.

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
    """

    if isinstance(attack_vector, AttackVectorDimensionEnum):
      attack_vector = attack_vector.value

    if isinstance(attacker_location, AttackerLocationDimensionEnum):
      attacker_location = attacker_location.value

    if isinstance(behavior_type, BehaviorTypeDimensionEnum):
      behavior_type = behavior_type.value

    if isinstance(covert, CovertDimensionEnum):
      covert = covert.value

    if isinstance(os_platform, OSPlatformDimensionEnum):
      os_platform = os_platform.value

    if isinstance(stage_of_attack, StageOfAttackDimensionEnum):
      stage_of_attack = stage_of_attack.value

    return {
        "0": {"id": self.lookup_dimension_id_by_name(attack_vector)},
        "1": {"id": self.lookup_dimension_id_by_name(attacker_location)},
        "2": {"id": self.lookup_dimension_id_by_name(behavior_type)},
        "3": {"id": self.lookup_dimension_id_by_name(covert)},
        "4": {"id": self.lookup_dimension_id_by_name(os_platform)},
        "5": {"id": self.lookup_dimension_id_by_name(stage_of_attack)},
    }

  def get_director_version(self) -> str:
    """Get the version of this director.

    Returns:
      The version as a string (i.e. "4.11.0.0-95")
    """

    response = self._request("GET", "/version.json")
    return response.json()["version"]

  def get_all_partial_actions(self) -> list[PartialAction]:
    """Obtains all partial actions from "/manage_sims/actions.json".

    Returns:
      A list of PartialAction objects
    """

    response = self._request("GET", "/manage_sims/actions.json")
    partial_action_jsons: list[dict] = response.json()
    output: list[PartialAction] = []
    for item in partial_action_jsons:
      action = PartialAction(item)
      output.append(action)

    return output

  def get_full_action_by_id(self, action_id: int | str) -> FullActionSubclass:
    """Obtains the full action JSON from "/manage_sims/actions/{action_id}.json".

    Args:
      action_id: Action ID, as int or string.

    Returns:
      A subclass of FullAction, dependent upon what type of Action is returned.
    """

    response = self._request("GET", f"/manage_sims/actions/{action_id}.json")
    full_action_json = response.json()
    output = interpret_full_action(full_action_json)

    # Only feasible way to handle dimensions is
    # to identify them as we build the FullAction object
    for item in output.trees:
      for category in self._dimension_cache:
        for dimension in self._dimension_cache[category]:
          if item["name"] == dimension:
            if category == "Behavior Type":
              output.dimension_behavior_type = item["name"]
            elif category == "OS/Platform":
              output.dimension_OS_platform = item["name"]
            elif category == "Attacker Location":
              output.dimension_attacker_location = item["name"]
            elif category == "Stage of Attack":
              output.dimension_stage_of_attack = item["name"]
            elif category == "Attack Vector":
              output.dimension_attack_vector = item["name"]
            elif category == "Covert":
              output.dimension_covert = item["name"]

    return output

  def get_full_action_by_vid(self, vid: str) -> FullActionSubclass:
    """Obtains the full action JSON from "/manage_sims/actions/{vid}.json?lookup_type=vid".

    Args:
      vid: String like "A101-140".

    Returns:
      A subclass of FullAction, dependent upon what type of Action is returned.
    """

    response = self._request(
        "GET", f"/manage_sims/actions/{vid}.json?lookup_type=vid"
    )
    full_action_json = response.json()
    output = interpret_full_action(full_action_json)

    # Only feasible way to handle dimensions is
    # to identify them as we build the FullAction object
    for item in output.trees:
      for category in self._dimension_cache:
        for dimension in self._dimension_cache[category]:
          if item["name"] == dimension:
            if category == "Behavior Type":
              output.dimension_behavior_type = item["name"]
            elif category == "OS/Platform":
              output.dimension_OS_platform = item["name"]
            elif category == "Attacker Location":
              output.dimension_attacker_location = item["name"]
            elif category == "Stage of Attack":
              output.dimension_stage_of_attack = item["name"]
            elif category == "Attack Vector":
              output.dimension_attack_vector = item["name"]
            elif category == "Covert":
              output.dimension_covert = item["name"]

    return output

  def get_all_full_actions(
      self, multi_threaded: bool = True
  ) -> list[FullActionSubclass]:
    """Obtains a list of full action jsons and instantiate them as objects.

    First pulls all partial actions by querying
    "/manage_sims/library_actions_list.json". Then uses the VIDs from each
    partial action to obtain the full action.

    Args:
      multi_threaded: Whether to pull full action JSONs in parallel. Defaults to
        True.

    Returns:
      A list of instances that are subclasses of FullAction,
      dependent upon what type of Action is returned
    """

    response = self._request("GET", "/manage_sims/library_actions_list.json")
    response_json = response.json()
    output: list[FullActionSubclass] = []

    if not multi_threaded:
      for action in response_json:
        full_action = self.get_full_action_by_vid(action["vid"])
        output.append(full_action)
      return output

    def _add_to_output(vid: str):
      result = self.get_full_action_by_vid(vid)
      output.append(result)

    with concurrent.futures.ThreadPoolExecutor() as executor:
      executor.map(_add_to_output, [x["vid"] for x in response_json])

    return output

  def get_evaluations(self) -> list[Evaluation]:
    """Obtain a list of all evaluations from /simulations.json.

    Returns:
      A list of Evaluation objects
    """
    params = {"sim_type": "eval"}
    response = self._request("GET", resource="/simulations.json", params=params)
    response_json = response.json()
    output = []
    for entry in response_json:
      output.append(Evaluation(entry))
    return output

  def get_sequences(self) -> list[Sequence]:
    """Obtain a list of all evaluations from /simulations.json.

    Returns:
      A list of Sequence objects
    """
    params = {"sim_type": "sequence"}
    response = self._request("GET", resource="/simulations.json", params=params)
    response_json = response.json()
    output = []
    for entry in response_json:
      output.append(Sequence(entry))
    return output

  def get_simulation_by_vid(self, vid: str) -> Sequence | Evaluation:
    """Given a VID, obtain the full simulation json.

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
    """
    response = self._request("GET", f"/simulations/{vid}.json?lookup_type=vid")
    response_json = response.json()

    if response_json["simulation_type"] == "sequence":
      return Sequence(response_json)
    elif response_json["simulation_type"] == "eval":
      return Evaluation(response_json)
    else:
      raise ContentParsingError(
          "Error getting simulation by VID, could not determine simulation type"
          " or other error"
      )

  def get_simulation_by_id(
      self, simulation_id: int | str
  ) -> Sequence | Evaluation:
    """Given a VID, obtain the full simulation json.

     Calls "/simulations/{vid}.json?lookup_type=vid".

    Args:
      simulation_id: ID of the simulation to obtain, as an integer or string

    Returns:
      Either a Sequence or Evaluation,
      dependent upon what type of simulation is returned

    Raises:
      ContentParsingError: If the response does not appear to be a valid
      Sequence or Evaluation
    """
    response = self._request("GET", f"/simulations/{simulation_id}.json")
    response_json = response.json()

    if response_json["simulation_type"] == "sequence":
      return Sequence(response_json)
    elif response_json["simulation_type"] == "eval":
      return Evaluation(response_json)
    else:
      raise ContentParsingError(
          "Error getting simulation by id, could not determine simulation type"
          " or other error"
      )

  def get_all_files(self) -> list[VRTFile]:
    """Obtains all files from the director from "/manage_sims/file_library.json".

    Returns:
      A list of VRTFile objects representing the file library.
    """
    response = self._request("GET", "/manage_sims/file_library.json")
    response_json = response.json()
    output = []
    for entry in response_json:
      output.append(VRTFile(entry))
    return output

  def get_job(self, job_id: int | str) -> Job:
    """Retrieve information about a given job by ID.

    This will provide more detail than the `get_all_jobs` method.

    Args:
      job_id: ID of the job to obtain, as an integer or string

    Returns:
      A Job object containing detailed data about a job.
    """

    response = self._request("GET", f"/jobs/{str(job_id)}.json")
    response_json = response.json()
    return Job(response_json)

  def get_all_jobs(self) -> list[dict[str:any]]:
    """Obtain a list of dictionaries containing abridged job data.

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
    """

    response = self._request("GET", f"/jobs.json")
    response_json = response.json()
    return response_json

  def get_action_user_profiles(self) -> list[ActionUserProfile]:
    """Obtain a list of ActionUserProfiles from "/action_user_profiles.json".

    This is called by the Director class on object initialization.

    To get a specific ActionUserProfile, it is better to call "lookup_aup_by_id"
    to check the cached values on the Director object.

    Returns:
      A list of ActionUserProfiles
    """
    response = self._request("GET", "/action_user_profiles.json")
    response_json = response.json()
    output = []
    for entry in response_json:
      output.append(ActionUserProfile(entry))
    output.append(
        SYSTEM_ACTIONUSERPROFILE
    )  # SYSTEM is not technically a user profile, but we treat it as one to simplify interactions
    return output

  def get_email_profiles(self) -> list[EmailProfile]:
    """Obtain a list of email profiles associated with this director

    from "/settings/email_profiles.json".

    This is called by the Director class on object initialization.

    Returns:
      A list of EmailProfiles
    """
    response = self._request("GET", "/settings/email_profiles.json")
    response_json = response.json()
    output = []
    for entry in response_json:
      output.append(EmailProfile(entry))

    return output

  def get_actors(self) -> list[Actor]:
    """Obtain a list of actors associated with this director from "/nodes.json"

    This will ignore Protected *Theaters*, which are NOT the same as Protected
    *Actors*.

    Returns:
      A list of Actors. Will be empty if an error is encountered.
    """
    response = self._request("GET", "/nodes.json")
    response_json = response.json()

    if "error" in response_json:
      return []

    output = []

    for entry in response_json["registered"]:
      new_actor = Actor(entry)
      if new_actor.node_type == "sandbox":
        continue
      output.append(new_actor)
    return output

  def get_action_compatible_environment(
      self, target_action: str | int | Action
  ) -> CompatibleEnvironment:
    """Return information about action compatibility from

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
    """

    if isinstance(target_action, str):
      target_id = self.get_full_action_by_vid(target_action).id
    elif isinstance(target_action, int):
      target_id = target_action
    elif isinstance(target_action, Action):
      target_id = target_action.id
    else:
      raise ValueError("Target must be vid, id, or Action object")

    response = self._request(
        "GET", f"/manage_sims/actions/{target_id}/actors.json"
    )

    response_json = response.json()

    au_profiles: list[ActionUserProfile] = [
        ActionUserProfile(x) for x in response_json["action_user_profiles"]
    ]
    email_profiles: list[EmailProfile] = [
        EmailProfile(x) for x in response_json["email_profiles"]
    ]
    actor_ids: list[int] = list(response_json["actors"].keys())
    step_options = None

    return CompatibleEnvironment(
        au_profiles, email_profiles, actor_ids, step_options
    )

  def add_tag_to_action(
      self,
      target_action: str | int | Action,
      tag: Enum | str,
      tag_type: str = "",
  ) -> dict:
    """Adds a tag to an action.

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
    """

    if isinstance(target_action, str):
      target_id = self.get_full_action_by_vid(target_action).id
    elif isinstance(target_action, int):
      target_id = target_action
    elif isinstance(target_action, Action):
      target_id = target_action.id
    else:
      raise ValueError("Target must be vid, id, or Action object")

    if isinstance(tag, vrt_sdk.OSTagEnum):
      tag_type = "os"
    elif isinstance(tag, vrt_sdk.ControlTagEnum):
      tag_type = "control"
    elif isinstance(tag, vrt_sdk.RunAsTagEnum):
      tag_type = "run_as"
    elif isinstance(tag, vrt_sdk.SrcDstTagEnum):
      tag_type = "src_destination"

    if isinstance(tag, enum.Enum):
      tag = tag.value

    if tag_type == "os" or tag_type == "user_os":
      tag.replace("OS:", "")
      tag = f"OS:{tag}"
    elif tag_type == "control" or tag_type == "user_control":
      tag.replace("Control:", "")
      tag = f"Control:{tag}"
    elif tag_type == "run_as" or tag_type == "user_run_as":
      tag.replace("RunAs:", "")
      tag = f"RunAs:{tag}"
    elif tag_type == "src_destination" or tag_type == "user_src_destination":
      pass
    elif tag_type == "mitre_mitigation" or tag_type == "user_mitre_mitigation":
      pass
    elif tag_type == "nist_control" or tag_type == "user_nist_control":
      pass
    elif tag_type == "verodin":
      pass
    elif tag_type == "user":
      pass

    if not self._vrt_authority:
      if tag_type == "verodin":
        tag_type = "user"
      elif tag_type in [
          "os",
          "control",
          "run_as",
          "src_destination",
          "mitre_mitigation",
          "nist_control",
      ]:
        tag_type = "user_" + tag_type

    response = self._request(
        "POST",
        "/tags/change/add.json",
        data={"tag": tag},
        params={"type": "action", "id": target_id, "tag_context": tag_type},
    )

    return response.json()

  def remove_tag_from_action(
      self,
      target_action: str | int | Action,
      tag: Enum | str,
      tag_type: str = "",
  ) -> dict:
    """Removes a tag from an Action.

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
    """
    if isinstance(target_action, str):
      target_id = self.get_full_action_by_vid(target_action).id
    elif isinstance(target_action, int):
      target_id = target_action
    elif isinstance(target_action, Action):
      target_id = target_action.id
    else:
      raise ValueError("Target must be vid, id, or Action object")

    if isinstance(tag, vrt_sdk.OSTagEnum):
      tag_type = "os"
    elif isinstance(tag, vrt_sdk.ControlTagEnum):
      tag_type = "control"
    elif isinstance(tag, vrt_sdk.RunAsTagEnum):
      tag_type = "run_as"
    elif isinstance(tag, vrt_sdk.SrcDstTagEnum):
      tag_type = "src_destination"

    if isinstance(tag, enum.Enum):
      tag = tag.value

    if tag_type == "os":
      tag.replace("OS:", "")
      tag = f"OS:{tag}"
    elif tag_type == "control":
      tag.replace("Control:", "")
      tag = f"Control:{tag}"
    elif tag_type == "run_as":
      tag.replace("RunAs:", "")
      tag = f"RunAs:{tag}"
    elif tag_type == "src_destination":
      pass
    elif tag_type == "mitre_mitigation":
      pass
    elif tag_type == "nist_control":
      pass
    elif tag_type == "verodin":
      pass
    elif tag_type == "user":
      pass

    if not self._vrt_authority:
      if tag_type == "verodin":
        tag_type = "user"
      elif tag_type in [
          "os",
          "control",
          "run_as",
          "src_destination",
          "mitre_mitigation",
          "nist_control",
      ]:
        tag_type = "user_" + tag_type

    response = self._request(
        "POST",
        "/tags/change/remove.json",
        data={"tag": tag},
        params={"type": "action", "id": target_id, "tag_context": tag_type},
    )
    return response.json()

  def add_tag_to_file(
      self, target_file: int | VRTFile, tag: Enum | str
  ) -> dict:
    """Adds a tag to a file_transfer_library entry.

    Be aware that the file library can be slow to update. If you add a tag to a
    file and then immediately attempt to pull the file library again, it is
    possible that the update will not yet have occurred.

    Args:
      target_file: File to add a tag to.
      tag: Tag to apply to the file.

    Returns:
      The JSON data from the response, if successful
    """

    if isinstance(target_file, int):
      target_id = target_file
    elif isinstance(target_file, VRTFile):
      target_id = target_file.id
    else:
      raise TypeError("Target must be id (int) or VRTFile object")

    if isinstance(tag, enum.Enum):
      tag = tag.value

    response = self._request(
        "POST",
        "/tags/change/add.json",
        data={"tag": tag},
        params={
            "type": "file_transfer_library",
            "id": target_id,
            "tag_context": "verodin" if self._vrt_authority else "user",
        },
    )
    return response.json()

  def remove_tag_from_file(
      self, target_file: int | VRTFile, tag: Enum | str
  ) -> dict:
    """Removes a tag from a file_transfer_library entry.

    Args:
      target_file: File to remove a tag from.
      tag: Tag to remove from the file.

    Returns:
      The JSON data from the response, if successful
    """
    if isinstance(target_file, int):
      target_id = target_file
    elif isinstance(target_file, VRTFile):
      target_id = target_file.id
    else:
      raise TypeError("Target must be id (int) or VRTFile object")

    if isinstance(tag, enum.Enum):
      tag = tag.value

    response = self._request(
        "POST",
        "/tags/change/remove.json",
        data={"tag": tag},
        params={
            "type": "file_transfer_library",
            "id": target_id,
            "tag_context": "verodin" if self._vrt_authority else "user",
        },
    )
    return response.json()

  def add_tag_to_simulation(
      self,
      target_simulation: str | int | Sequence | Evaluation,
      tag: Enum | str,
  ) -> dict:
    """Adds a verodin/user tag to a Sequence or Evaluation.

    Args:
      target_simulation: Sequence or Evaluation to add a tag to.
      tag: Tag to apply to the simulation.

    Returns:
      The JSON data from the response, if successful
    """
    if isinstance(target_simulation, str):
      target_id = self.get_simulation_by_vid(target_simulation).id
    elif isinstance(target_simulation, int):
      target_id = target_simulation
    elif isinstance(target_simulation, Simulation):
      target_id = target_simulation.id
    else:
      raise TypeError("Target must be vid, id, or Simulation object")

    if isinstance(tag, enum.Enum):
      tag = tag.value

    # This is objectively bad for performance, but the alternative
    # is to split this method into two, which I'd argue is worse.
    sim = self.get_simulation_by_id(target_id)
    if isinstance(sim, Evaluation):
      response = self._request(
          "POST",
          "/tags/change/add.json",
          data={"tag": tag},
          params={
              "type": "eval",
              "id": target_id,
              "tag_context": "verodin" if self._vrt_authority else "user",
          },
      )
      return response.json()
    elif isinstance(sim, Sequence):
      response = self._request(
          "POST",
          "/tags/change/add.json",
          data={"tag": tag},
          params={
              "type": "sequence",
              "id": target_id,
              "tag_context": "verodin" if self._vrt_authority else "user",
          },
      )
      return response.json()
    else:
      raise TypeError

  def remove_tag_from_simulation(
      self,
      target_simulation: str | int | Sequence | Evaluation,
      tag: Enum | str,
  ) -> dict:
    """Removes a tag from a Sequence or Evaluation.

    Args:
      target_simulation: Sequence or Evaluation to remove a tag from.
      tag: Tag to remove from the simulation.

    Returns:
      The JSON data from the response, if successful
    """
    if isinstance(target_simulation, str):
      target_id = self.get_simulation_by_vid(target_simulation).id
    elif isinstance(target_simulation, int):
      target_id = target_simulation
    elif isinstance(target_simulation, Simulation):
      target_id = target_simulation.id
    else:
      raise TypeError("Target must be vid, id, or Simulation object")

    if isinstance(tag, enum.Enum):
      tag = tag.value

    # This is objectively bad for performance, but the alternative
    # is to split this method into two, which I'd argue is worse.
    sim = self.get_simulation_by_id(target_id)
    if isinstance(sim, Evaluation):
      response = self._request(
          "POST",
          "/tags/change/remove.json",
          data={"tag": tag},
          params={
              "type": "eval",
              "id": target_id,
              "tag_context": "verodin" if self._vrt_authority else "user",
          },
      )
      return response.json()
    elif isinstance(sim, Sequence):
      response = self._request(
          "POST",
          "/tags/change/remove.json",
          data={"tag": tag},
          params={
              "type": "sequence",
              "id": target_id,
              "tag_context": "verodin" if self._vrt_authority else "user",
          },
      )
      return response.json()
    else:
      raise TypeError

  def upload_file(
      self,
      file_bytes: bytes,
      file_name: str,
      file_restrictions: str | FileRestrictionsEnum,
      file_notes: str,
      os_value: str | OSPlatformDimensionEnum,
  ) -> int:
    """Uploads a file to the file_transfer_library.

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
    """

    if isinstance(file_restrictions, FileRestrictionsEnum):
      file_restrictions = file_restrictions.value

    if file_restrictions not in [
        "pending_approval",
        "restricted_malicious",
        "none",
    ]:
      raise ValueError("Need to specify a valid type of file restriction")

    if isinstance(os_value, OSPlatformDimensionEnum):
      os_value = os_value.value
    os_id = self.lookup_dimension_id_by_name(os_value)

    if not os_id:
      raise ValueError(
          f"Unable to identify dimension ID for {os_value}, possible bad input"
      )

    m = MultipartEncoder(
        fields={
            "file_transfer_library[file_upload]": (
                file_name,
                file_bytes,
                "application/octet-stream",
            ),
            "file_transfer_library[file_restrictions]": file_restrictions,
            "file_transfer_library[file_notes]": file_notes,
            "file_transfer_library[os_tree_id]": str(os_id),
        }
    )
    resp = self._request(
        "POST",
        "/manage_sims/file_transfer_libraries.json",
        data=m,
        headers={"Content-Type": m.content_type},
    )

    if resp.status_code != 201:
      raise FileUploadError(
          f"Response code {resp.status_code}. {resp.reason}. Director file"
          " upload has likely failed."
      )

    return resp.json()["id"]

  def create_file_transfer_action(
      self,
      action_name: str,
      action_description: str,
      target_file: VRTFile | None = None,
      file_id: int | None = None,
      os_value: str | OSPlatformDimensionEnum | None = None,
      method: str = "get",
      app_layer: str = "http",
      target_port: str | int = "80",
  ) -> PartialAction:
    """Creates a file transfer action (MFT).

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
    """

    if target_file:
      file_id = target_file.id
      os_value = target_file.os_tree_id

    elif file_id and os_value:
      if isinstance(os_value, OSPlatformDimensionEnum):
        os_value = os_value.value

    else:
      raise ValueError(
          "Must provide VRTFile object or both file_id and os_value"
      )

    val = {
        "sim_action": {
            "action_type": "file_transfer",
            "timeout_ms": 10000,
            "name": action_name,
            "desc": action_description,
            "file_transfer_action_attributes": {
                "file_transfer_library_id": str(file_id),
                "compare_transfer": 1,
                "keep_after_compare": 0,
                "content_encoding": "",
                "method": method,
                "app_layer": app_layer,
                "target_port": str(target_port),
                "tunnel_cidr": None,
                "tunnel_protocol": None,
                "dns_domain": None,
                "dns_server_ip": None,
            },
        },
        "trees": self.generate_trees(
            "HTTP(S)",
            "General-Location",
            "Download-MFT",
            "No",
            os_value,
            "Delivery",
        ),
    }

    response = self._request("POST", "/manage_sims/actions.json", json=val)
    return PartialAction(response.json())

  def create_dns_action(
      self, action_name: str, action_description: str, domain: str
  ) -> PartialAction:
    """Creates a DNS Query Action.

    Args:
      action_name: The name of the Action.
      action_description: The description of the Action.
      domain: The domain to be used in this Action.

    Returns:
      A PartialAction object representing the created Action. Be aware that not
      all fields are guaranteed to be populated.
    """

    val = {
        "sim_action": {
            "action_type": "dns",
            "name": action_name,
            "desc": action_description,
            "dns_query_action_attributes": {
                "dns_server_id": None,
                "query_type": "A",
                "domain": domain,
            },
        },
        "trees": {
            "0": {"id": self.lookup_dimension_id_by_name("Command & Control")}
        },
    }

    response = self._request("POST", "/manage_sims/actions.json", json=val)
    return PartialAction(response.json())

  def create_email_action(
      self,
      action_name: str,
      action_description: str,
      body: str = "Placeholder",
      subject: str = "Email",
      mime_type: str = "html",
      file_attachment: VRTFile | int | None = None,
  ) -> PartialAction:
    """Creates an Email Action.

    Args:
      action_name: The name of the Action.
      action_description: The description of the Action.
      body: The body of the email.
      subject: The subject line of the email. Defaults to "Email".
      mime_type: The mime_type of the email. Must be "html" or "plain". Defaults
        to "html".
      file_attachment: Either a VRTFile object or the id of the
        file_transfer_library entry (file) to use for this Action. May be None
        if no file is used (such as if the Action contains only  a malicious
        link).

    Returns:
      A PartialAction object representing the created Action. Be aware that not
      all fields are guaranteed to be populated.
    """

    if isinstance(file_attachment, VRTFile):
      file_attachment = file_attachment.id
    elif isinstance(file_attachment, int) or file_attachment is None:
      pass
    else:
      raise ValueError("File attachment must be VRTFile, int, or None")

    val = {
        "sim_action": {
            "action_type": "email",
            "name": action_name,
            "desc": action_description,
            "timeout_ms": 10000,
            "email_action_attributes": {
                "subject": subject,
                "body": body,
                "mime_text_type": mime_type,
                "block_matching_scheme": "any",
            },
        },
        "trees": self.generate_trees(
            "Email",
            "External",
            "Phishing",
            "No",
            "General-OS/Platform",
            "Delivery",
        ),
    }

    if file_attachment:

      val["sim_action"]["email_action_attributes"][
          "email_action_file_transfer_libraries"
      ] = {
          file_attachment: {
              "attachment_encoding": "",
              "ignore_if_missing": "0",
          }
      }

    response = self._request("POST", "/manage_sims/actions.json", json=val)

    return PartialAction(response.json())

  def create_host_action(
      self, host_factory: HostActionFactory
  ) -> PartialAction:
    """Creates a Host Action (Host CLI or PT) from a `HostActionFactory` object.

    Args:
      host_factory: A configured HostActionFactory. See documentation for
        HostActionFactory for details on how to configure.

    Returns:
      A PartialAction object representing the created Action. Be aware that not
      all fields are guaranteed to be populated.
    """

    val = host_factory.build_payload()
    response = self._request("POST", "/manage_sims/actions.json", json=val)
    return PartialAction(response.json())

  def create_simulation(
      self,
      factory: SimulationFactory | None = None,
      actions: list[FullActionSubclass] | None = None,
      simulation_name: str = "",
      simulation_description: str = "",
      simulation_type: str = "",
  ) -> dict:
    """Create a simulation (Sequence or Evaluation).

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
    """
    if factory:
      payload = factory.build_payload()
    elif (
        actions
        and simulation_name
        and simulation_description
        and simulation_type in ["eval", "sequence"]
    ):
      factory = SimulationFactory(
          simulation_name, simulation_description, simulation_type
      )
      factory.auto_build_from_actions(actions)
      payload = factory.build_payload()
    else:
      raise ValueError(
          "Must provide a configured SimulationFactory or a list of FullActions"
          " with a name, description, and valid type"
      )

    response = self._request("POST", "/simulations.json", json=payload)
    return response.json()

  def run_action(
      self,
      action: Action | str | int,
      source_actor: Actor | int = None,
      destination_actor: Actor | int = None,
      action_user_profile: ActionUserProfile | int = None,
      source_email_profile: EmailProfile | int = None,
      destination_email_profile: EmailProfile | int = None,
      proxy: bool = False,
      job_name: str = "",
      user_variables: dict[str, str] = None
  ) -> int:
    """Runs a single Action with the given settings.

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
      user_variables: For Host CLI actions, any variable names and values set by 
        the user. Does not default to anything, since different actions will have
        different variable requirements.

    Returns:
      The id of the created job as an integer.
    """

    payload = {}

    # While we can accept vids and ids as action inputs for convenience
    # we do need to know the action type to determine appropriate actor/user information
    if not (isinstance(action, Action) or issubclass(type(action), Action)):
      if isinstance(action, int):
        action = self.get_full_action_by_id(action)
      elif isinstance(action, str):
        action = self.get_full_action_by_vid(action)
      else:
        raise TypeError(
            "Expected Action object, integer (action id), or string (action"
            " vid)"
        )

    compatibility_data = self.get_action_compatible_environment(action)

    # If we don't have a source actor, get a compatible one at random
    if not source_actor:
      source_actor = random.choice(compatibility_data.actor_ids)
    if isinstance(source_actor, Actor):
      source_actor = source_actor.id
    payload["attack_node_id_1"] = source_actor

    # If this action requires a destination actor
    if action.action_type not in ["dns", "host_cli"]:

      # If we weren't provided an actor, find one
      if not destination_actor:

        checked_nodes = set()

        while target_node_id := random.choice(compatibility_data.actor_ids):

          if target_node_id != payload["attack_node_id_1"]:
            break
          else:
            checked_nodes.add(target_node_id)

          if checked_nodes == set(compatibility_data.actor_ids):
            raise ValueError("No viable destination Actors found")

      # If our actor is an Actor object, pull out the id
      elif isinstance(destination_actor, Actor):
        target_node_id = destination_actor.id
      elif isinstance(destination_actor, int):
        target_node_id = destination_actor
      else:
        raise ValueError("No target node id found")

      payload["target_node_id_1"] = target_node_id

    # If this action is a Host CLI
    if action.action_type == "host_cli":

      # we must have an action user profile
      if not action_user_profile:
        raise NotImplementedError(
            "Cannot run Host CLI Actions without specifying action user profile."
        )
      else:
        if isinstance(action_user_profile, ActionUserProfile):
          payload["action_user_profile_id"] = {"1": action_user_profile.aup_id}
        else:
          payload["action_user_profile_id"] = {"1": action_user_profile}

      # Validate user variables if required by the action
      if action.user_variables:
        user_variables = user_variables or {}
        missing_vars = list(set(action.user_variables) - set(user_variables.keys()))
        if missing_vars:
            raise ValueError(
                f"Missing required variable(s) for host action: {', '.join(missing_vars)}"
            )
        # Add validated variables to payload
        payload["action_variables"] = {"1": { action.id: user_variables }}

    # If this action is an email action
    if action.action_type == "email":

      if not source_email_profile:
        source_email_profile = random.choice(
            compatibility_data.email_profiles
        ).ep_id
      if isinstance(source_email_profile, EmailProfile):
        source_email_profile = source_email_profile.ep_id

      payload["from_email_profile_id_1"] = source_email_profile

      if not destination_email_profile:

        checked_profiles = set()

        while destination_email_profile := random.choice(
            compatibility_data.email_profiles
        ).ep_id:
          if destination_email_profile != payload["from_email_profile_id_1"]:
            break
          else:
            checked_profiles.add(destination_email_profile)

          if checked_profiles == set(
              item.ep_id for item in compatibility_data.email_profiles
          ):
            raise ValueError(
                "No viable or insufficient number of Email profiles found"
            )

      if isinstance(destination_email_profile, EmailProfile):
        destination_email_profile = destination_email_profile.ep_id
      payload["to_email_profile_id_1"] = destination_email_profile

    if proxy:
      payload["proxy_comm_id"] = {"1": 1}

    if not job_name:
      payload["job_name"] = (
          f"{self.username.split('@')[0]} || {action.vid}:{action.name}"
      )
    else:
      payload["job_name"] = job_name

    response = self._request(
        "POST", f"/manage_sims/actions/{action.id}/run", json=payload
    )
    response_json = response.json()
    return response_json["id"]

  def export_all_content(self) -> bytes:
    """Export all content from `/settings/content_export.json`.

    Returns:
      Bytes representing a vas file
    """

    payload = {"content_export": "all"}
    response = self._request(
        "POST", "/settings/content_export.json", json=payload
    )
    vas_bytes = response.content
    return vas_bytes

  def lookup_dimension_id_by_name(self, dimension_name: str) -> int:
    """Obtains the numerical ID of a dimension, given the name.

    Args:
      dimension_name: A string representing a dimension name, like
        "Download-MFT".

    Returns:
      The integer representation of the dimension's ID, like 50.
    """
    for key in self._dimension_cache:
      for subkey in self._dimension_cache[key]:
        if subkey.lower() == dimension_name.lower():
          return self._dimension_cache[key][subkey]

  def lookup_dimension_name_by_id(self, dimension_id: int) -> str:
    """Obtains the string name of a dimension, given the numerical ID.

    Args:
      dimension_id: The integer representation of a dimension's ID, like 50.

    Returns:
      A string representing the dimension name, like "Download-MFT".
    """
    for key in self._dimension_cache:
      for subkey in self._dimension_cache[key]:
        if self._dimension_cache[key][subkey] == dimension_id:
          return subkey

  def set_host_factory_dimensions(
      self,
      factory: HostActionFactory,
      attack_vector: str | AttackVectorDimensionEnum = "General-Vector",
      attacker_location: (
          str | AttackerLocationDimensionEnum
      ) = "General-Location",
      behavior_type: str | BehaviorTypeDimensionEnum = "General-Behavior",
      covert: str | CovertDimensionEnum = "No",
      os_platform: str | OSPlatformDimensionEnum = "General-OS/Platform",
      stage_of_attack: str | StageOfAttackDimensionEnum = "Execution",
  ) -> None:
    """Sets the dimensions of the HostActionFactory.

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
    """
    trees = self.generate_trees(
        attack_vector,
        attacker_location,
        behavior_type,
        covert,
        os_platform,
        stage_of_attack,
    )
    factory.trees = trees

  def lookup_aup_by_friendly_name(self, aup_name: str) -> ActionUserProfile:
    """Looks up an ActionUserProfile.

    Use this instead of "get_action_user_profiles", as this does not require a
    network call.

    Args:
      aup_name: The friendly name of the ActionUserProfile to find (case-
        insensitive).

    Returns:
      The ActionUserProfile with the given ID.
    """
    for aup in self.action_user_profiles.values():
      if aup.friendly_name.lower() == aup_name.lower():
        return aup

  def lookup_aup_by_desc_substring(
      self, substring: str
  ) -> list[ActionUserProfile]:
    """Obtains any ActionUserProfile w/a description containing the string.

    Args:
      substring: String to search for. Case insensitive

    Returns:
      A list of ActionUserProfiles that contain the provided string in their
      description
    """
    output: list[ActionUserProfile] = []
    for aup in self.action_user_profiles.values():
      if substring.lower() in aup.description.lower():
        output.append(aup)
    return output

  def lookup_actor_by_name(self, actor_name: str) -> Actor | None:
    """Looks up an Actor by name.

    Use this instead of "get_actors", as this does not require a network call.

    Args:
      actor_name: The name of the actor (i.e., "brt-rnd-vna-01") to look up.

    Returns:
      The Actor with the given name. If no such Actor exists, returns None.
    """

    for item in list(self.actors.values()):
      if item.name == actor_name:
        return item

  def lookup_actor_by_os(self, actor_os: OSTagEnum) -> Actor | None:
    """Return the first actor that matches the specified OS.

    Args:
      actor_os: Operating System to find an Actor for

    Returns:
      The first Actor with the given Operating System. If no such Actor exists,
      return None.
    """
    for item in list(self.actors.values()):
      if item.guessed_true_os == actor_os:
        return item
