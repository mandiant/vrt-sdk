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
from vrt_sdk import DnsAction

"""
This script demonstrates using the director client to display each DNS Action
and its domain on a director.

To do this, we need to pull all full actions from the director,
because only full actions have the `sim_action` key containing execution data.

Then we check whether the action we obtained is a DnsAction.
The Director client will automatically attempt to create the appropriate
subclass for each action.
The DnsAction will have all the attributes inherited from Action and FullAction,
but also DNS-specific attributes extracted from `sim_action`.
"""

client = Director("DIRECTOR_NAME")
all_actions = client.get_all_full_actions()

for action in all_actions:
  if isinstance(action, DnsAction):
    print(
        f"{action.vid} -"
        f' {action.domain.replace(".", "[.]").replace("http", "hxxp")}'
    )
