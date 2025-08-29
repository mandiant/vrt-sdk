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

from vrt_sdk.enumerations import AUPUserTypeEnum


class ActionUserProfile:

  def __init__(self, aup_json: dict):
    """Represents an Action User Profile."""

    self._raw = aup_json

    self.aup_id: int = aup_json["id"]
    self.username: str = aup_json["username"]
    self.description: str = aup_json["description"]
    self.domain: str = aup_json["domain"]
    self.friendly_name: str = aup_json["friendly_name"]

    user_type_str = aup_json.get("user_type", "")
    if user_type_str == "":
      if "nonadmin" in self.username.lower().replace(" ", "").replace("-", ""):
        user_type_str = "User"
      elif "admin" in self.username.lower().replace(" ", "").replace("-", ""):
        user_type_str = "Admin"
      elif "nodeone" in self.username.lower().replace(" ", "").replace("-", ""):
        user_type_str = "Admin"
    self.user_type: AUPUserTypeEnum = AUPUserTypeEnum(user_type_str)

  def __repr__(self):
    name = self.friendly_name if self.friendly_name else self.username
    return (
        f"Action User Profile: {name} (ID:{self.aup_id}) - Type:"
        f" {self.user_type.value}"
    )


_SYSTEM = {
    "username": "SYSTEM",
    "friendly_name": "SYSTEM",
    "description": "Auto-generated user profile added by VRT SDK",
    "user_type": "SYSTEM",
    "id": None,
    "domain": "",
}

SYSTEM_ACTIONUSERPROFILE = ActionUserProfile(_SYSTEM)
