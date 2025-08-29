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

from vrt_sdk import *

from .fixtures import email_profile_response


class TestEmailProfile:

  def test_email_profile(self, test_dir, email_profile_response, monkeypatch):
    client = Director(director_name=test_dir)

    monkeypatch.setattr(
        requests.models.Response, "json", email_profile_response
    )

    email_profiles = client.get_email_profiles()

    assert len(email_profiles) == 2
    assert any(map(lambda x: x.ep_id == 4, email_profiles))
    assert any(map(lambda x: x.ep_id == 5, email_profiles))
    assert any(
        map(lambda x: x.email_address == "fake@mandiant.com", email_profiles)
    )
    assert any(
        map(lambda x: x.email_address == "also_fake@mandiant.com", email_profiles)
    )
