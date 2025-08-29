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

import json

from vrt_sdk import Director

"""
This script demonstrates using the director client to apply additional tags to
Actions based on their MITRE ATT&CK tags.

This can be used with arbitrary mappings to other types of frameworks.
A short example JSON file named `example_framework_mappings.json` is used in
this example.
"""

client = Director("DIRECTOR_NAME")

# Obtain all Actions from the director
all_actions = client.get_all_partial_actions()

# Read JSON file mapping MITRE techniques to various framework tags
with open("example_framework_mappings.json", "r") as f:
  mappings: dict[str:list[str]] = json.load(f)

for action in all_actions:

  for tech in action.mitre_attack_techniques:

    # If the technique has associated CWE tags
    # apply each additional tag to the Action
    if cwe_tags := mappings["cwe_mapping"].get(tech.id, None):
      for entry in cwe_tags:
        client.add_tag_to_action(action, entry, "user")
        print(f"Added {entry} to {action}")

    # If the technique has associated NIST tags
    # apply each additional tag to the Action
    if nist_tags := mappings["nist_mapping"].get(tech.id, None):
      for entry in nist_tags:
        client.add_tag_to_action(action, entry, "user_nist_control")
        print(f"Added {entry} to {action}")
