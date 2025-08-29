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


class EmailProfile:

  def __init__(self, ep_json: dict):
    """Represents an Email Profile in a director."""

    self._raw = ep_json

    self.email_address = ep_json["email_address"]
    self.ep_id = ep_json["id"]

  def __repr__(self):
    return f"Email Profile: {self.email_address} (ID: {self.ep_id})"
