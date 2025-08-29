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

from vrt_sdk import CompatibleEnvironment
from vrt_sdk import Director

from .fixtures import *


@pytest.mark.skip(reason="These tests are dependent upon environment details")
class TestRunActions:

  def test_run_dns_action_1(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A199-002")
    director.run_action(action)

  def test_run_dns_action_2(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A199-003")
    job_id = director.run_action(action)
    result = director.get_job(job_id)
    assert len(result.executions) == 1
    assert result.executions[0].action.vid == "A199-003"

  def test_run_mft_action_1(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A199-014")
    director.run_action(action)

  @pytest.mark.skip("Need to specify action user profile, environment-specific")
  def test_run_host_cli_action_1(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A199-012")
    director.run_action(action)

  @pytest.mark.skip("Automatic selection of email profiles known to be weak")
  def test_run_email_action_1(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A199-006")
    director.run_action(action)


class TestExport:

  @pytest.mark.skip(
      "VRT specific test, requires specific license"
  )
  def test_brta_export(self, test_dir):
    # Only intended to verify that no exception is raised
    director = Director(director_name=test_dir)
    vas_bytes = director.export_all_content()
    assert vas_bytes


@pytest.mark.skip(reason="These tests are dependent upon environment details")
class TestGetActionCompatibleEnvironment:

  def test_1(self, test_dir):
    director = Director(director_name=test_dir)
    result = director.get_action_compatible_environment(12969)
    assert isinstance(result, CompatibleEnvironment)

  def test_2(self, test_dir):
    director = Director(director_name=test_dir)
    result = director.get_action_compatible_environment(12512)
    assert isinstance(result, CompatibleEnvironment)
