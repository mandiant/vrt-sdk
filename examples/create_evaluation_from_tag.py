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
from vrt_sdk import SimulationFactory

"""
This script demonstrates using the director client to collect all Actions with a
given tag and create an Evaluation out of them.
"""

client = Director("DIRECTOR_NAME")

# Collect all actions with a given tag
partial_actions = [
    action
    for action in client.get_all_partial_actions()
    if "ACTOR2" in action.verodin_tags
]

# Collect the full details for all actions with the tag of interest.
# It is typically faster to identify these actions via abridged data (above) and
# request the full details for each action individually than to request the full
# details for all actions.
full_actions = [
    client.get_full_action_by_vid(action.vid) for action in partial_actions
]

# Create a SimulationFactory to help build the payload
factory = SimulationFactory(
    "VRT SDK Evaluation Example",
    "This Evaluation is created from an example script provided with the VRT"
    " SDK. It is safe to delete.",
    "eval",
)

# Call method to automatically sort Actions into appropriate groups
factory.auto_build_from_actions(full_actions)

# Provide configured factory to director client to send the request
response = client.create_simulation(factory)
