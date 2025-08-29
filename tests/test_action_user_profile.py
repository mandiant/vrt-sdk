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
from vrt_sdk import ActionUserProfile

from .fixtures import *  # noqa


class TestActionUserProfileCreation:

  def test_action_user_profile_creation_standard(self, action_user_profiles_1):
    aups = []
    for item in action_user_profiles_1:
      new_aup = ActionUserProfile(item)
      aups.append(new_aup)
    assert len(aups) == 8

  def test_action_user_profile_creation_from_compatible_actors_response(
      self, compatible_actors_response_dns_action
  ):
    aups = []
    for item in compatible_actors_response_dns_action["action_user_profiles"]:
      new_aup = ActionUserProfile(item)
      aups.append(new_aup)
    assert len(aups) == 8
