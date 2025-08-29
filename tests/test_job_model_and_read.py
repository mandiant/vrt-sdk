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

from collections import Counter

from vrt_sdk import *

from .fixtures import *


class TestJob:

  def test_basic_job_creation(self, job_fixture_1):
    test_job = Job(job_fixture_1)
    assert test_job.id == 8601
    assert "This description is redacted" in test_job.desc
    assert test_job.status == JobStatusEnum.COMPLETED

    assert len(test_job.job_steps) == 1
    assert len(test_job.job_steps[0].job_actions) == 1
    assert test_job.job_steps[0].job_actions[0].action.vid == "A106-923"
    assert test_job.actions[0].vid == "A106-923"

  def test_job_action_list_deduplication(self, job_fixture_2):
    test_job = Job(job_fixture_2)
    assert test_job.id == 8880
    assert len(test_job.actions) == 1


@pytest.mark.skip(reason="These tests are dependent upon environment details")
class TestJobs:

  def test_get_job_1(self, test_dir):
    director = Director(test_dir)
    job = director.get_job(8740)
    assert job.name is None
    assert job.desc == "Description"
    assert len(job.actions) == 1
    assert job.actions[0].vid == "A999-999"

  def test_get_job_2(self, test_dir):
    director = Director(test_dir)
    job = director.get_job("8880")
    assert job.name is None
    assert len(job.job_steps) == 12
    assert len(job.actions) == 1
    assert len(job.executions) == 12

    assert not any(map(lambda x: x, [item.detected for item in job.executions]))

    count = Counter([item.blocked for item in job.executions])
    assert count[True] == 3
    assert count[False] == 9

    count = Counter([item.passed for item in job.executions])
    assert count[True] == 3
    assert count[False] == 9

  def test_get_job_3(self, test_dir):
    director = Director(test_dir)
    job = director.get_job("8881")
    assert job.name == "Name"
    assert job.desc == "Description"

  def test_get_all_jobs(self, test_dir):
    client = Director(test_dir)
    job_stubs = client.get_all_jobs()
    all_jobs = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
      executor.map(
          lambda x: all_jobs.append(client.get_job(x["id"])), job_stubs
      )

    # Environment dependent
    # assert len(all_jobs) > 1000
