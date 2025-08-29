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

from .content import FullAction, FullActionSubclass, PartialAction, interpret_full_action
from .enumerations import *


class JobAction:

  def __init__(self, job_action_json: dict):
    """A class representing a Job Action in the MSV Platform.

    We may often refer to this as a "job" or a "result", but it is a JobAction
    in the director schema.

    A JobAction contains a single FullAction and details about
    an execution of that FullAction.
    A Job Step (which may refer to these as a "group") contains
    one or more Job Actions.

    A Job Action JSON contains more fields than are defined on this class.

    Args:
      job_action_json: A dictionary containing Job Action data in JSON format
    """

    self._raw = job_action_json

    self.action: PartialAction = PartialAction(job_action_json["action"])
    self.job_id: int = job_action_json["job_id"]
    self.job_step_id: int = job_action_json["step_id"]

    self.blocked: bool = job_action_json["blocked"]
    self.detected: bool = job_action_json["detected"]
    self.passed: bool = job_action_json["passed"]

    self.attack_node_id: int = job_action_json["attack_node_id"]
    self.target_node_id: int = job_action_json["target_node_id"]

    self.action_user_profile_id: int = job_action_json["action_user_profile_id"]

    self.status: JobActionResultEnum = JobActionResultEnum(
        job_action_json["status"]
    )

    self.action_type: str = job_action_json["action_type"]

  def __repr__(self):
    return (
        f"Job Action ({self.action.vid}), step {self.job_step_id} in job"
        f" {self.job_id}"
    )


class JobStep:

  def __init__(self, job_step_json: dict):
    """A class representing a Job Step in the MSV Platform.

    We may refer to this as a "Group" in the GUI.

    A Job contains one or more Job Steps.
    A JobStep contains one or more JobActions.

    Args:
      job_step_json: A dictionary containing Job Step data in JSON format
    """
    self._raw = job_step_json

    self.job_id: int = job_step_json["job_id"]
    self.step_id: int = job_step_json["step_id"]
    self.step_order: int = job_step_json["step_order"]
    self.job_actions: list[JobAction] = []

    for j_action in job_step_json["job_actions"]:
      j_action_object = JobAction(j_action)
      self.job_actions.append(j_action_object)

  def __repr__(self):
    return (
        f"Job Step {self.step_id}, step {self.step_order} (1-indexed) of job"
        f" {self.job_id}"
    )


class Job:

  def __init__(self, job_json: dict):
    """A class representing a Job in the MSV platform.

    A Job contains JobSteps, which contains JobActions.
    JobActions finally contain a JSON similar to a "FullAction" JSON,
    which is interpreted as a FullAction subclass.

    Jobs run via the UI by default will not have a name,
    and so the name attribute will be None.
    If the job is given a name (via UI or API) it will be a string.

    Job descriptions vary.
    If there is a single action, it will be the name of that action,
    *possibly* with a timestamp appended.
    If there are multiple actions,
    it might be something like `Run Queue Actions @ {TIMESTAMP}`.

    The UI displays the name first in the job list, and if there is no name,
    then uses the description.
    However, these are not perfect matches,
    so the values in the JSON and Job-type objects may not match
    what is displayed in the UI. I don't know why.

    Args:
      job_json: A dictionary containing Job data in JSON format
    """

    self._raw = job_json

    self.desc: str = job_json["desc"]
    self.id: int = job_json["id"]
    self.name: str | None = job_json["name"]
    self.plan_id: int = job_json["plan_id"]
    self.progress: str = job_json["progress"]
    self.simulation_id: int = job_json["simulation_id"]
    self.status_desc: str = job_json["status_desc"]
    self.user_id: int = job_json["user_id"]

    # Has multiple job steps
    # Each job step can contain multiple job actions
    self.job_steps: list[JobStep] = []
    for step in job_json["job_steps"]:
      step_object = JobStep(step)
      self.job_steps.append(step_object)

    self.status: JobStatusEnum = JobStatusEnum(job_json["status"])

  @property
  def actions(self) -> list[FullActionSubclass]:
    """A deduplicated (by vid) list of Actions contained within this Job"""
    output: list[FullActionSubclass] = []
    for js in self.job_steps:
      for ja in js.job_actions:
        if ja.action.vid in [item.vid for item in output]:
          continue
        output.append(ja.action)
    return output

  @property
  def executions(self) -> list[JobAction]:
    """A list of all JobActions, each representing an execution of an Action"""
    output: list[JobAction] = []
    for js in self.job_steps:
      for ja in js.job_actions:
        output.append(ja)
    return output

  def __repr__(self):
    return f"Job {self.id} - {self.name}"
