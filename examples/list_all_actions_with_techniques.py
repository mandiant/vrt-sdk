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

from vrt_sdk import Director

"""
This script demonstrates using the director client to display each action and
its associated mitre attack techniques.

To do this, we need to pull all actions from the director.
Each Action has its mitre techniques parsed and represented as
MitreAttackTechnique objects.
We iterate over each such object in the action object's list of techniques and
print the `id` and `name` attributes.
"""

client = Director("DIRECTOR_NAME")
all_actions = client.get_all_partial_actions()

for action in all_actions:
  print("---")
  print(action)
  mitre_techniques = []
  for technique in action.mitre_attack_techniques:
    print(f"{technique.id} - {technique.name}")
