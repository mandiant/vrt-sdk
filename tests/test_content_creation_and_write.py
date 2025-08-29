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

import hashlib
import time

import pytest
from vrt_sdk import *


class TestCreateContent:

  def test_upload_file(self, test_dir):
    director = Director(director_name=test_dir)

    test_file_string = f"VRT_SDK_TEST_FILE_{random.randint(10001, 99999)}"
    test_file_bytes = random.randbytes(200)
    test_file_md5 = hashlib.md5(test_file_bytes).hexdigest()
    file_id_response = director.upload_file(
        test_file_bytes,
        test_file_string,
        "restricted_malicious",
        "This is a test file of random bytes used for VRT SDK tests. If you see"
        " this, it is safe to delete.",
        OSPlatformDimensionEnum.GENERAL_OS_PLATFORM,
    )

    files = director.get_all_files()

    assert file_id_response in [file.id for file in files]

    for file in files:
      if file.id == file_id_response:
        assert file.md5sum == test_file_md5
        assert file.orig_file_name == test_file_string

  def test_create_mft(self, test_dir):
    director = Director(director_name=test_dir)

    test_identifier = random.randint(10001, 99999)

    test_file_string = f"VRT_SDK_TEST_FILE_{test_identifier}"
    test_file_bytes = random.randbytes(200)
    test_file_md5 = hashlib.md5(test_file_bytes).hexdigest()
    file_id_response = director.upload_file(
        test_file_bytes,
        test_file_string,
        "restricted_malicious",
        "This is a test file of random bytes used for VRT SDK tests. If you see"
        " this, it is safe to delete.",
        OSPlatformDimensionEnum.GENERAL_OS_PLATFORM,
    )

    files = director.get_all_files()

    assert file_id_response in [file.id for file in files]

    for file in files:
      if file.id == file_id_response:
        assert file.md5sum == test_file_md5
        assert file.orig_file_name == test_file_string

    action_result = director.create_file_transfer_action(
        f"VRT SDK TEST - MFT - {test_identifier}",
        "This is a test action created during VRT SDK tests. If you see this,"
        " it is safe to delete.",
        file_id=file_id_response,
        os_value="Windows",
    )

    action: FileTransferAction = director.get_full_action_by_id(
        action_result.id
    )

    assert action.name == f"VRT SDK TEST - MFT - {test_identifier}"
    assert action.file_transfer_library_id == file_id_response

  def test_create_dns(self, test_dir):
    director = Director(director_name=test_dir)

    test_identifier = random.randint(10001, 99999)

    action_result = director.create_dns_action(
        f"VRT SDK TEST - DNS - {test_identifier}",
        "This is a test action created during VRT SDK tests. If you see this,"
        " it is safe to delete.",
        "www.google.com",
    )

    action: DnsAction = director.get_full_action_by_id(action_result.id)

    assert action.name == f"VRT SDK TEST - DNS - {test_identifier}"
    assert action.domain == "www.google.com"

  def test_create_email_attachment(self, test_dir):
    director = Director(director_name=test_dir)

    test_identifier = random.randint(10001, 99999)

    test_file_string = f"VRT_SDK_TEST_FILE_{test_identifier}"
    test_file_bytes = random.randbytes(200)
    test_file_md5 = hashlib.md5(test_file_bytes).hexdigest()
    file_id_response = director.upload_file(
        test_file_bytes,
        test_file_string,
        "restricted_malicious",
        "This is a test file of random bytes used for VRT SDK tests. If you see"
        " this, it is safe to delete.",
        OSPlatformDimensionEnum.GENERAL_OS_PLATFORM,
    )

    files = director.get_all_files()

    assert file_id_response in [file.id for file in files]

    for file in files:
      if file.id == file_id_response:
        assert file.md5sum == test_file_md5
        assert file.orig_file_name == test_file_string

    action_result = director.create_email_action(
        f"VRT SDK TEST - EMAIL (ATTACHMENT) - {test_identifier}",
        "This is a test action created during VRT SDK tests. If you see this,"
        " it is safe to delete.",
        "EMAIL BODY",
        file_attachment=file_id_response,
    )

    action = director.get_full_action_by_id(action_result.id)

    assert (
        action.name == f"VRT SDK TEST - EMAIL (ATTACHMENT) - {test_identifier}"
    )
    assert action.email_action_file_transfer_libraries

  def test_create_email_link(self, test_dir):
    director = Director(director_name=test_dir)

    test_identifier = random.randint(10001, 99999)

    action_result = director.create_email_action(
        f"VRT SDK TEST - EMAIL (LINK) - {test_identifier}",
        "This is a test action created during VRT SDK tests. If you see this,"
        " it is safe to delete.",
        '<a href="www.google.com">Click here</a>',
    )

    action: EmailAction = director.get_full_action_by_id(action_result.id)

    assert action.name == f"VRT SDK TEST - EMAIL (LINK) - {test_identifier}"
    assert not action.email_action_file_transfer_libraries

  def test_create_host_cli_no_files(self, test_dir):
    director = Director(director_name=test_dir)

    test_identifier = random.randint(10001, 99999)

    factory = HostActionFactory(
        f"VRT SDK TEST - HOST CLI - {test_identifier}",
        "This is a test action created during VRT SDK tests. If you see this,"
        " it is safe to delete.",
        "cmd.exe",
        protected=False,
    )

    factory.add_step("echo 'I AM A WIZARD'", criteria="success_match:WIZARD")
    factory.add_step("echo 'Success Zero Check'")
    factory.add_step("echo 'Expanded Time Values'", sleep=8, timeout="120")
    factory.add_step("echo 'Cleanup Check'", criteria="cleanup")

    director.set_host_factory_dimensions(factory)

    action_result = director.create_host_action(factory)

    action: HostAction = director.get_full_action_by_id(action_result.id)

    assert action.name == f"VRT SDK TEST - HOST CLI - {test_identifier}"
    assert not action.require_endpoint

  def test_create_protected_theater_no_files(self, test_dir):
    director = Director(director_name=test_dir)

    test_identifier = random.randint(10001, 99999)

    factory = HostActionFactory(
        f"VRT SDK TEST - PROTECTED THEATER - {test_identifier}",
        "This is a test action created during VRT SDK tests. If you see this,"
        " it is safe to delete.",
        "cmd.exe",
    )

    factory.add_step("echo 'I AM A WIZARD'", criteria="success_match:WIZARD")
    factory.add_step("echo 'Success Zero Check'")
    factory.add_step("echo 'Expanded Time Values'", sleep=8, timeout="120")
    factory.add_step("echo 'Cleanup Check'", criteria="cleanup")

    director.set_host_factory_dimensions(factory)

    action_result = director.create_host_action(factory)

    action: HostAction = director.get_full_action_by_id(action_result.id)

    assert (
        action.name == f"VRT SDK TEST - PROTECTED THEATER - {test_identifier}"
    ), "Action name does not match"
    assert action.require_endpoint, "Expecting Action to require PT"

  def test_create_host_cli_w_files(self, test_dir):
    director = Director(director_name=test_dir)

    test_file_string = f"VRT_SDK_TEST_FILE_{random.randint(10001, 99999)}"
    test_file_bytes = random.randbytes(200)
    test_file_md5 = hashlib.md5(test_file_bytes).hexdigest()
    file_id_response_1 = director.upload_file(
        test_file_bytes,
        test_file_string,
        "restricted_malicious",
        "This is a test file of random bytes used for VRT SDK tests. If you see"
        " this, it is safe to delete.",
        OSPlatformDimensionEnum.GENERAL_OS_PLATFORM,
    )

    files = director.get_all_files()

    assert file_id_response_1 in [file.id for file in files]

    for file in files:
      if file.id == file_id_response_1:
        assert file.md5sum == test_file_md5
        assert file.orig_file_name == test_file_string

    test_file_string = f"VRT_SDK_TEST_FILE_{random.randint(10001, 99999)}"
    test_file_bytes = random.randbytes(200)
    test_file_md5 = hashlib.md5(test_file_bytes).hexdigest()
    file_id_response_2 = director.upload_file(
        test_file_bytes,
        test_file_string,
        "restricted_malicious",
        "This is a test file of random bytes used for VRT SDK tests. If you see"
        " this, it is safe to delete.",
        OSPlatformDimensionEnum.GENERAL_OS_PLATFORM,
    )

    files = director.get_all_files()

    assert file_id_response_2 in [file.id for file in files]

    for file in files:
      if file.id == file_id_response_2:
        assert file.md5sum == test_file_md5
        assert file.orig_file_name == test_file_string

    test_identifier = random.randint(10001, 99999)

    factory = HostActionFactory(
        f"VRT SDK TEST - HOST CLI - {test_identifier}",
        "This is a test action created during VRT SDK tests. If you see this,"
        " it is safe to delete.",
        "cmd.exe",
    )

    factory.add_step("echo 'I AM A WIZARD'", criteria="success_match:WIZARD")
    factory.add_step("echo 'Success Zero Check'")
    factory.add_step("echo 'Expanded Time Values'", sleep=8, timeout="120")
    factory.add_step("echo 'Cleanup Check'", criteria="cleanup")

    director.set_host_factory_dimensions(factory)

    factory.add_file(file_id_response_1, "c:/windows/temp/", "TEST_FILE_1")
    factory.add_file(
        file_id_response_2, "c:/users/public/documents/", "TEST_FILE_2"
    )

    action_result = director.create_host_action(factory)

    action: HostAction = director.get_full_action_by_id(action_result.id)

    assert (
        action.name == f"VRT SDK TEST - HOST CLI - {test_identifier}"
    ), "Action name does not match"
    assert action.require_endpoint, "Expecting Action to require PT"

    assert len(action.host_cli_action_file_transfer_libraries) == 2

  def test_create_protected_theater_w_files(self, test_dir):
    director = Director(director_name=test_dir)

    test_file_string = f"VRT_SDK_TEST_FILE_{random.randint(10001, 99999)}"
    test_file_bytes = random.randbytes(200)
    test_file_md5 = hashlib.md5(test_file_bytes).hexdigest()
    file_id_response_1 = director.upload_file(
        test_file_bytes,
        test_file_string,
        "restricted_malicious",
        "This is a test file of random bytes used for VRT SDK tests. If you see"
        " this, it is safe to delete.",
        OSPlatformDimensionEnum.GENERAL_OS_PLATFORM,
    )

    files = director.get_all_files()

    assert file_id_response_1 in [file.id for file in files]

    for file in files:
      if file.id == file_id_response_1:
        assert file.md5sum == test_file_md5
        assert file.orig_file_name == test_file_string

    test_file_string = f"VRT_SDK_TEST_FILE_{random.randint(10001, 99999)}"
    test_file_bytes = random.randbytes(200)
    test_file_md5 = hashlib.md5(test_file_bytes).hexdigest()
    file_id_response_2 = director.upload_file(
        test_file_bytes,
        test_file_string,
        "restricted_malicious",
        "This is a test file of random bytes used for VRT SDK tests. If you see"
        " this, it is safe to delete.",
        OSPlatformDimensionEnum.GENERAL_OS_PLATFORM,
    )

    files = director.get_all_files()

    assert file_id_response_2 in [file.id for file in files]

    for file in files:
      if file.id == file_id_response_2:
        assert file.md5sum == test_file_md5
        assert file.orig_file_name == test_file_string

    test_identifier = random.randint(10001, 99999)

    factory = HostActionFactory(
        f"VRT SDK TEST - PROTECTED THEATER - {test_identifier}",
        "This is a test action created during VRT SDK tests. If you see this,"
        " it is safe to delete.",
        "cmd.exe",
    )

    factory.add_step("echo 'I AM A WIZARD'", criteria="success_match:WIZARD")
    factory.add_step("echo 'Success Zero Check'")
    factory.add_step("echo 'Expanded Time Values'", sleep=8, timeout="120")
    factory.add_step("echo 'Cleanup Check'", criteria="cleanup")

    director.set_host_factory_dimensions(factory)

    factory.add_file(file_id_response_1, "c:/windows/temp/", "TEST_FILE_1")
    factory.add_file(
        file_id_response_2, "c:/users/public/documents/", "TEST_FILE_2"
    )

    action_result = director.create_host_action(factory)

    action: HostAction = director.get_full_action_by_id(action_result.id)

    assert (
        action.name == f"VRT SDK TEST - PROTECTED THEATER - {test_identifier}"
    ), "Action name does not match"
    assert action.require_endpoint, "Expecting Action to require PT"

    assert len(action.host_cli_action_file_transfer_libraries) == 2


class TestTagContent:

  def test_action_tags(self, test_dir):
    director = Director(director_name=test_dir)

    test_identifier = random.randint(10001, 99999)

    action_result = director.create_dns_action(
        f"VRT SDK TEST - DNS - {test_identifier}",
        "This is a test action created during VRT SDK tests. If you see this,"
        " it is safe to delete.",
        "www.google.com",
    )

    action = director.get_full_action_by_id(action_result.id)

    assert action.name == f"VRT SDK TEST - DNS - {test_identifier}"

    director.add_tag_to_action(action, "DUMMY_VERODIN_TAG", "verodin")
    director.add_tag_to_action(action, RunAsTagEnum.ROOT)
    director.add_tag_to_action(action, SrcDstTagEnum.SRC_INTERNAL_TRUSTED)
    director.add_tag_to_action(action, OSTagEnum.WINDOWS)
    director.add_tag_to_action(action, "M1234", "mitre_mitigation")
    director.add_tag_to_action(action, "nist_example", "nist_control")
    director.add_tag_to_action(action, ControlTagEnum.NGFW)

    action = director.get_full_action_by_id(action_result.id)

    assert "DUMMY_VERODIN_TAG" in action.verodin_tags
    assert "RunAs:" + RunAsTagEnum.ROOT.value in action.run_as_tags
    assert (
        SrcDstTagEnum.SRC_INTERNAL_TRUSTED.value in action.src_destination_tags
    )
    assert "OS:" + OSTagEnum.WINDOWS.value in action.os_tags
    assert "M1234" in action.mitre_mitigation_tags
    assert "nist_example" in action.nist_control_tags
    assert "Control:" + ControlTagEnum.NGFW.value in action.control_tags

    director.remove_tag_from_action(action, "DUMMY_VERODIN_TAG", "verodin")
    director.remove_tag_from_action(action, RunAsTagEnum.ROOT)
    director.remove_tag_from_action(action, SrcDstTagEnum.SRC_INTERNAL_TRUSTED)
    director.remove_tag_from_action(action, OSTagEnum.WINDOWS)
    director.remove_tag_from_action(action, "M1234", "mitre_mitigation")
    director.remove_tag_from_action(action, "nist_example", "nist_control")
    director.remove_tag_from_action(action, ControlTagEnum.NGFW)

    action = director.get_full_action_by_id(action_result.id)

    assert not action.verodin_tags
    assert not action.run_as_tags
    assert not action.src_destination_tags
    assert not action.os_tags
    assert not action.mitre_mitigation_tags
    assert not action.nist_control_tags
    assert not action.control_tags

  @pytest.mark.skip(reason="Failing due to MSV platform bug at time of writing")
  def test_file_tags(self, test_dir):
    director = Director(director_name=test_dir)

    test_file_string = f"VRT_SDK_TEST_FILE_{random.randint(10001, 99999)}"
    test_file_bytes = random.randbytes(200)
    test_file_md5 = hashlib.md5(test_file_bytes).hexdigest()
    file_id_response = director.upload_file(
        test_file_bytes,
        test_file_string,
        "restricted_malicious",
        "This is a test file of random bytes used for VRT SDK tests. If you see"
        " this, it is safe to delete.",
        OSPlatformDimensionEnum.GENERAL_OS_PLATFORM,
    )

    files = director.get_all_files()

    assert file_id_response in [file.id for file in files]

    for file in files:
      if file.id == file_id_response:
        assert file.md5sum == test_file_md5
        assert file.orig_file_name == test_file_string
        assert file.verodin_tags == []

    director.add_tag_to_file(file_id_response, "TEST_TAG")

    time.sleep(4)  # File library is slow to update

    files = director.get_all_files()

    assert file_id_response in [file.id for file in files]

    for file in files:
      if file.id == file_id_response:
        assert file.md5sum == test_file_md5
        assert file.orig_file_name == test_file_string
        assert file.verodin_tags == ["TEST_TAG"]

    director.remove_tag_from_file(file_id_response, "TEST_TAG")

    time.sleep(4)  # File library is slow to update

    files = director.get_all_files()

    assert file_id_response in [file.id for file in files]

    for file in files:
      if file.id == file_id_response:
        assert file.md5sum == test_file_md5
        assert file.orig_file_name == test_file_string
        assert file.verodin_tags == []

  def test_sequence_tags(self, test_dir):
    director = Director(director_name=test_dir)

    test_sequence = director.get_simulation_by_vid("S199-004")

    director.add_tag_to_simulation(test_sequence, "TEST_TAG")
    test_sequence = director.get_simulation_by_vid("S199-004")
    assert set(test_sequence.verodin_tags) == {"ACTOR1", "TEST_TAG"}

    director.remove_tag_from_simulation(test_sequence, "TEST_TAG")
    test_sequence = director.get_simulation_by_vid("S199-004")
    assert set(test_sequence.verodin_tags) == {"ACTOR1"}

  def test_eval_tags(self, test_dir):
    director = Director(director_name=test_dir)

    test_eval = director.get_simulation_by_vid("S199-001")

    director.add_tag_to_simulation(test_eval, "TEST_TAG")
    test_eval = director.get_simulation_by_vid("S199-001")
    assert set(test_eval.verodin_tags) == {"ACTOR1", "TEST_TAG"}

    director.remove_tag_from_simulation(test_eval, "TEST_TAG")
    test_eval = director.get_simulation_by_vid("S199-001")
    assert set(test_eval.verodin_tags) == {"ACTOR1"}
