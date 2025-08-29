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
its associated dimensions.
"""

client = Director("DIRECTOR_NAME")
all_actions = client.get_all_partial_actions()

for action in all_actions:
  print("---")
  print(action)

  print(f"Behavior Type: {action.dimension_behavior_type}")
  print(f"OS: {action.dimension_OS_platform}")
  print(f"Attacker Location: {action.dimension_attacker_location}")
  print(f"Stage of Attack: {action.dimension_stage_of_attack}")
  print(f"Attack Vector: {action.dimension_attack_vector}")
  print(f"Covert?: {action.dimension_covert}")
