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

import re


class MitreAttackTactic:
  """Small class representing a MITRE Attack Tactic on an Action"""

  def __init__(self, json: dict):
    self.tactic_id: str = json["tactic_id"]
    self.tactic_name: str = json["tactic_name"]

  def __repr__(self):
    return f"Mitre Attack Tactic {self.tactic_id} - {self.tactic_name}"


class MitreAttackTechnique:
  """Small class representing a MITRE Attack Technique on an Action"""

  def __init__(self, json: dict):
    self.guid: str = json["guid"]
    self.id: str = json["id"]
    self.name: str = json["name"]
    self.tactics: list[MitreAttackTactic] = []
    for item in json["tactics"]:
      tactic = MitreAttackTactic(item)
      self.tactics.append(tactic)

  def __repr__(self):
    return f"Mitre Attack Technique {self.id} - {self.name}"


class CDA:
  """Small class representing a Common Detection Alert.

  Note that VRT has since stopped publishing Common Detection Alerts on Actions.
  """

  def __init__(self, cda_json):
    self.id: int = cda_json["id"]
    self.sim_action_id: int = cda_json["sim_action_id"]
    self.message: str = cda_json["message"]
    self.source: str = cda_json["source"]
    self.source_identifier: str = cda_json["source_identifier"]
    self.created_at: str = cda_json["created_at"]
    self.updated_at: str = cda_json["updated_at"]
    self.organization_id: str = cda_json["organization_id"]


def check_vid_validity(vid: str) -> bool:
  """Determine if a VID is valid, irrespective of production status or

  content type.

  Args:
    vid: The vid to check

  Returns:
    A boolean indicating if the vid is valid
  """

  if re.match("[AS][1-3][0-9]{2}-[0-9]{3}(?!.)", vid):
    return True
  return False
