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

import pytest
from vrt_sdk.enumerations import MalwareToolTypeEnum


class TestMalwareToolTypeEnum:

  def test_list_of_tool_type_tags(self):
    assert "Tool_Type:FRAMEWORK" in MalwareToolTypeEnum.list_of_tool_type_tags()

  def test_list_of_malware_type_tags(self):
    assert (
        "Malware_Type:BACKDOOR" in MalwareToolTypeEnum.list_of_tool_type_tags()
    )

  def test_coerce_to_type_tag(self):
    assert (
        MalwareToolTypeEnum.coerce_to_type_tag("BACKDOOR")
        == "Malware_Type:BACKDOOR"
    )
    assert (
        MalwareToolTypeEnum.coerce_to_type_tag("backdoor")
        == "Malware_Type:BACKDOOR"
    )
    assert (
        MalwareToolTypeEnum.coerce_to_type_tag("backdoor", "tool")
        == "Tool_Type:BACKDOOR"
    )
    assert (
        MalwareToolTypeEnum.coerce_to_type_tag("TOOLTYPE:BACKDOOR")
        == "Tool_Type:BACKDOOR"
    )
    assert (
        MalwareToolTypeEnum.coerce_to_type_tag("TOOLTYPE: BACKDOOR")
        == "Tool_Type:BACKDOOR"
    )
    assert (
        MalwareToolTypeEnum.coerce_to_type_tag("MALWARETYPE: BACKDOOR")
        == "Malware_Type:BACKDOOR"
    )

    assert (
        MalwareToolTypeEnum.coerce_to_type_tag(
            "MALWARETYPE:LIGHTWEIGHT-BACKDOOR"
        )
        == "Malware_Type:LIGHTWEIGHT_BACKDOOR"
    )
    assert (
        MalwareToolTypeEnum.coerce_to_type_tag(
            "MALWARETYPE:LIGHTWEIGHT BVACKDOOR"
        )
        == "Malware_Type:LIGHTWEIGHT_BACKDOOR"
    )

    assert (
        MalwareToolTypeEnum.coerce_to_type_tag("Dropper (Memory Only)")
        == "Malware_Type:DROPPER_MEMORY_ONLY"
    )
    assert (
        MalwareToolTypeEnum.coerce_to_type_tag("Point-Of-Sale Malware")
        == "Malware_Type:POINT_OF_SALE"
    )
