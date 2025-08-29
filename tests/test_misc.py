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


class TestRegex:

  def test_vid_regex(self):

    assert check_vid_validity("S100-200")
    assert check_vid_validity("S300-200")
    assert check_vid_validity("A300-209")
    assert not check_vid_validity("A101-2000")
    assert not check_vid_validity("A101-20")
    assert not check_vid_validity("A10120")
    assert not check_vid_validity("E101-120")
    assert not check_vid_validity("S101-2000")
    assert not check_vid_validity("S101-20")
    assert not check_vid_validity("S10120")
    assert not check_vid_validity("a101-020")
    assert not check_vid_validity("a109-120")
    assert not check_vid_validity("a409-120")
