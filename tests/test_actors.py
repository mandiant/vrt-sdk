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
import requests

from vrt_sdk import Actor, Director
from .fixtures import actor_response  # noqa


class TestActors:

  def test_get_actors_rnd(self, test_dir, actor_response, monkeypatch):

    director = Director(director_name=test_dir)

    monkeypatch.setattr(requests.models.Response, "json", actor_response)

    actors = director.get_actors()
    assert all(map(lambda x: isinstance(x, Actor), actors))
    assert len(actors) == 22
    assert any(map(lambda x: "win" in x.name, actors))
    assert any(map(lambda x: "vna" in x.name, actors))
    for actor in actors:
      if "vna" in actor.name:
        assert actor.os_base.lower() == "centos"
      if "ubu" in actor.name:
        assert actor.os_base.lower() == "ubuntu"
      if "win" in actor.name:
        assert actor.os_base.lower() == "windows"
