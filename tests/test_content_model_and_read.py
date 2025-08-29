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
from .fixtures import *


class TestTagEnums:

  def test_control_tag_enums(self, test_dir):
    assert "Control:IDS/IPS" in ControlTagEnum.list_of_control_tags()
    assert "Control:NGFW" in ControlTagEnum.list_of_control_tags()
    assert "Control:Proxy" in ControlTagEnum.list_of_control_tags()
    assert "IDS/IPS" not in ControlTagEnum.list_of_control_tags()
    assert "NGFW" not in ControlTagEnum.list_of_control_tags()
    assert "Proxy" not in ControlTagEnum.list_of_control_tags()

  def test_src_dst_tag_enums(self, test_dir):
    assert "Src:Internal:Trusted" in SrcDstTagEnum.list_of_src_dst_tags()
    assert (
        "Src:Internal:Trusted+Dst:External:Untrusted"
        in SrcDstTagEnum.list_of_src_dst_tags()
    )

  def test_os_tag_enums(self, test_dir):
    assert "OS:ANY" in OSTagEnum.list_of_os_tags()
    assert "OS:Windows" in OSTagEnum.list_of_os_tags()
    assert "OS:Windows:10" in OSTagEnum.list_of_os_tags()
    assert "ANY" not in OSTagEnum.list_of_os_tags()
    assert "Windows" not in OSTagEnum.list_of_os_tags()
    assert "Windows:10" not in OSTagEnum.list_of_os_tags()


class TestPartialAction:

  def test_partial_action_fixture(self, partial_action_mft):
    test = PartialAction(partial_action_mft)

    assert test.action_type == "file_transfer"
    assert test._raw["action_type"] == "file_transfer"

    assert test.approved_version == 1
    assert test._raw["approved_version"] == 1

    assert test.brt_version == "0.0.3"
    assert test._raw["brt_version"] == "0.0.3"

    assert test.brt_version_updated_at == "2023-12-15T16:04:35.175Z"
    assert test._raw["brt_version_updated_at"] == "2023-12-15T16:04:35.175Z"

    assert test.cda_version == "0.1"
    assert test._raw["cda_version"] == "0.1"

    assert test.control_tags == [
        "Control:IDS/IPS",
        "Control:NGFW",
        "Control:Proxy",
    ]
    assert test._raw["control_tags"] == [
        "Control:IDS/IPS",
        "Control:NGFW",
        "Control:Proxy",
    ]

    assert test.created == "2023-12-15T14:32:55.278Z"
    assert test._raw["created"] == "2023-12-15T14:32:55.278Z"

    assert test.created_at == "2023-12-15T15:43:51.699Z"
    assert test._raw["created_at"] == "2023-12-15T15:43:51.699Z"

    assert test.decommissioned is False
    assert test._raw["decommissioned"] is False

    assert "This description is redacted" in test.desc
    assert "This description is redacted" in test._raw["desc"]

    assert test.disabled is False
    assert test._raw["disabled"] is False

    assert test.execution_plan == []
    assert test._raw["execution_plan"] == []

    assert test.hex is False
    assert test._raw["hex?"] is False

    assert test.hex_http is False
    assert test._raw["hex_http"] is False

    assert test.http is False
    assert test._raw["http?"] is False

    assert test.id == 12717
    assert test._raw["id"] == 12717

    assert test.metadata_version == 2
    assert test._raw["metadata_version"] == 2

    assert test.min_version is None
    assert test._raw["min_version"] is None

    # assert test.mitre_attack_techniques ==
    assert test._raw["mitre_attack_techniques"] == {
        "techniques": [{
            "guid": "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add",
            "id": "T1105",
            "name": "Ingress Tool Transfer",
            "tactics": [
                {"tactic_id": "TA0011", "tactic_name": "Command and Control"}
            ],
        }],
        "version": "12.1",
    }

    assert all(
        map(
            lambda x: isinstance(x, MitreAttackTechnique),
            test.mitre_attack_techniques,
        )
    )
    assert (
        test.mitre_attack_techniques[0].guid
        == "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add"
    )
    assert test.mitre_attack_techniques[0].id == "T1105"
    assert test.mitre_attack_techniques[0].name == "Ingress Tool Transfer"
    assert test.mitre_attack_techniques[0].tactics[0].tactic_id == "TA0011"
    assert (
        test.mitre_attack_techniques[0].tactics[0].tactic_name
        == "Command and Control"
    )

    assert test.mitre_mitigation_tags == []
    assert test._raw["mitre_mitigation_tags"] == []

    assert "Malicious File Transfer" in test.name
    assert "Malicious File Transfer" in test._raw["name"]

    assert test.nist_control_tags == []
    assert test._raw["nist_control_tags"] == []

    assert test.notes is None
    assert test._raw["notes"] is None

    assert test.organization_id == -999
    assert test._raw["organization_id"] == -999

    assert test.os_tags == ["OS:ANY"]
    assert test._raw["os_tags"] == ["OS:ANY"]

    assert test.require_endpoint is False
    assert test._raw["require_endpoint"] is False

    assert test.required_license is None
    assert test._raw["required_license"] is None

    assert test.run_as_tags == []
    assert test._raw["run_as_tags"] == []

    assert test.runtime is None
    assert test._raw["runtime"] is None

    assert test.sectech_logo_id is None
    assert test._raw["sectech_logo_id"] is None

    assert test.sectech_url is None
    assert test._raw["sectech_url"] is None

    assert test.src_destination_tags == [
        "Src:Internal:Trusted+Dst:External:Untrusted"
    ]
    assert test._raw["src_destination_tags"] == [
        "Src:Internal:Trusted+Dst:External:Untrusted"
    ]

    assert test.status is None
    assert test._raw["status"] is None

    assert test.timeout_ms == 10000
    assert test._raw["timeout_ms"] == 10000

    assert test.tls is False
    assert test._raw["tls?"] is False

    assert test.dimension_behavior_type == "Download-MFT"
    assert test.dimension_OS_platform == "General-OS/Platform"
    assert test.dimension_attacker_location == "General-Location"
    assert test.dimension_stage_of_attack == "Delivery"
    assert test.dimension_attack_vector == "HTTP(S)"
    assert test.dimension_covert == "No"
    assert test._raw["trees"][5]["name"] == "No"

    assert test.updated_at == "2023-12-15T16:04:35.175Z"
    assert test._raw["updated_at"] == "2023-12-15T16:04:35.175Z"

    assert test.user_control_tags == []
    assert test._raw["user_control_tags"] == []

    assert test.user_mitre_mitigation_tags == []
    assert test._raw["user_mitre_mitigation_tags"] == []

    assert test.user_nist_control_tags == []
    assert test._raw["user_nist_control_tags"] == []

    assert test.user_os_tags == []
    assert test._raw["user_os_tags"] == []

    assert test.user_run_as_tags == []
    assert test._raw["user_run_as_tags"] == []

    assert test.user_src_destination_tags == []
    assert test._raw["user_src_destination_tags"] == []

    assert test.user_tags == []
    assert test._raw["user_tags"] == []

    assert test.uuid == "80317688-e8b4-43bf-b5a2-503bb357c9b5"
    assert test._raw["uuid"] == "80317688-e8b4-43bf-b5a2-503bb357c9b5"

    assert test.ver == 2
    assert test._raw["ver"] == 2

    assert test.verodin_tags == [
        "ATT&CK:Command and Control",
        "ATT&CK:T1105",
        "Malware:Redacted",
        "Redacted",
    ]
    assert test._raw["verodin_tags"] == [
        "ATT&CK:Command and Control",
        "ATT&CK:T1105",
        "Malware:Redacted",
        "Redacted",
    ]

    assert test.vid == "A300-041"
    assert test._raw["vid"] == "A300-041"


class TestFullAction:

  def test_full_action_fixture(self, full_action_mft):
    test = FullAction(full_action_mft)

    # Below are duplicated tests from PartialAction, since we should have all of these already

    assert test._raw["sim_action"]["common_detection_alerts"] == [
        {
            "id": 60,
            "sim_action_id": 271,
            "message": (
                "SERVER-SAMBA Samba LDAP modify dnsRecord buffer overflow"
                " attempt"
            ),
            "source": "Cisco Firepower",
            "source_identifier": "43053",
            "created_at": "2023-11-28T15:43:25.119Z",
            "updated_at": "2023-11-28T15:43:25.119Z",
            "organization_id": -999,
        },
        {
            "id": 59,
            "sim_action_id": 271,
            "message": (
                "SERVER-OTHER Novell eDirectory LDAP server buffer overflow"
                " attempt"
            ),
            "source": "Cisco Firepower",
            "source_identifier": "44604",
            "created_at": "2023-11-28T15:43:25.116Z",
            "updated_at": "2023-11-28T15:43:25.116Z",
            "organization_id": -999,
        },
    ]
    assert len(test.common_detection_alerts) == 2

    assert test.action_type == "file_transfer"
    assert test._raw["sim_action"]["action_type"] == "file_transfer"

    assert test.approved_version == 1
    assert test._raw["sim_action"]["approved_version"] == 1

    assert test.brt_version == "0.0.3"
    assert test._raw["sim_action"]["brt_version"] == "0.0.3"

    assert test.brt_version_updated_at == "2023-12-15T16:04:35.175Z"
    assert (
        test._raw["sim_action"]["brt_version_updated_at"]
        == "2023-12-15T16:04:35.175Z"
    )

    assert test.cda_version == "0.1"
    assert test._raw["sim_action"]["cda_version"] == "0.1"

    assert test.control_tags == [
        "Control:IDS/IPS",
        "Control:NGFW",
        "Control:Proxy",
    ]
    assert test._raw["control_tags"] == [
        "Control:IDS/IPS",
        "Control:NGFW",
        "Control:Proxy",
    ]

    assert test.created == "2023-12-15T14:32:55.278Z"
    assert test._raw["sim_action"]["created"] == "2023-12-15T14:32:55.278Z"

    assert test.created_at == "2023-12-15T15:43:51.699Z"
    assert test._raw["sim_action"]["created_at"] == "2023-12-15T15:43:51.699Z"

    assert test.decommissioned is False
    assert test._raw["sim_action"]["decommissioned"] is False

    assert "This description is redacted" in test.desc
    assert "This description is redacted" in test._raw["sim_action"]["desc"]

    assert test.disabled is False
    assert test._raw["sim_action"]["disabled"] is False

    assert test.execution_plan == []
    assert test._raw["sim_action"]["execution_plan"] == []

    assert test.hex is False
    assert test._raw["hex?"] is False

    assert test.hex_http is False
    assert test._raw["sim_action"]["hex_http"] is False

    assert test.http is False
    assert test._raw["http?"] is False

    assert test.id == 12717
    assert test._raw["sim_action"]["id"] == 12717

    assert test.metadata_version == 2
    assert test._raw["sim_action"]["metadata_version"] == 2

    assert test.min_version is None
    assert test._raw["sim_action"]["min_version"] is None

    # assert test.mitre_attack_techniques ==
    assert test._raw["mitre_attack_techniques"] == {
        "techniques": [{
            "guid": "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add",
            "id": "T1105",
            "name": "Ingress Tool Transfer",
            "tactics": [
                {"tactic_id": "TA0011", "tactic_name": "Command and Control"}
            ],
        }],
        "version": "12.1",
    }

    assert all(
        map(
            lambda x: isinstance(x, MitreAttackTechnique),
            test.mitre_attack_techniques,
        )
    )
    assert (
        test.mitre_attack_techniques[0].guid
        == "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add"
    )
    assert test.mitre_attack_techniques[0].id == "T1105"
    assert test.mitre_attack_techniques[0].name == "Ingress Tool Transfer"
    assert test.mitre_attack_techniques[0].tactics[0].tactic_id == "TA0011"
    assert (
        test.mitre_attack_techniques[0].tactics[0].tactic_name
        == "Command and Control"
    )

    assert test.mitre_mitigation_tags == []
    assert test._raw["mitre_mitigation_tags"] == []

    assert "Malicious File Transfer" in test.name
    assert "Malicious File Transfer" in test._raw["sim_action"]["name"]

    assert test.nist_control_tags == []
    assert test._raw["nist_control_tags"] == []

    assert test.notes is None
    assert test._raw["sim_action"]["notes"] is None

    assert test.organization_id == -999
    assert test._raw["sim_action"]["organization_id"] == -999

    assert test.os_tags == ["OS:ANY"]
    assert test._raw["os_tags"] == ["OS:ANY"]

    assert test.require_endpoint is False
    assert test._raw["sim_action"]["require_endpoint"] is False

    assert test.required_license is None
    assert test._raw["sim_action"]["required_license"] is None

    assert test.run_as_tags == []
    assert test._raw["run_as_tags"] == []

    assert test.runtime is None
    assert test._raw["sim_action"]["runtime"] is None

    assert test.sectech_logo_id is None
    assert test._raw["sim_action"]["sectech_logo_id"] is None

    assert test.sectech_url is None
    assert test._raw["sim_action"]["sectech_url"] is None

    assert test.src_destination_tags == [
        "Src:Internal:Trusted+Dst:External:Untrusted"
    ]
    assert test._raw["src_destination_tags"] == [
        "Src:Internal:Trusted+Dst:External:Untrusted"
    ]

    assert test.status is None
    assert test._raw["sim_action"]["status"] is None

    assert test.timeout_ms == 10000
    assert test._raw["sim_action"]["timeout_ms"] == 10000

    assert test.tls is False
    assert test._raw["tls?"] is False

    # These won't actually work, because we have to rely on the director client to populate this for FullActions
    # When returning the JSON for a full action, we actually get LESS dimension data than for a partial action
    # assert test.dimension_behavior_type == "Download-MFT"
    # assert test.dimension_OS_platform == "General-OS/Platform"
    # assert test.dimension_attacker_location == "General-Location"
    # assert test.dimension_stage_of_attack == "Delivery"
    # assert test.dimension_attack_vector == "HTTP(S)"
    # assert test.dimension_covert == "No"
    assert test._raw["sim_action"]["trees"][5]["name"] == "No"

    assert test.updated_at == "2023-12-15T16:04:35.175Z"
    assert test._raw["sim_action"]["updated_at"] == "2023-12-15T16:04:35.175Z"

    assert test.user_control_tags == []
    assert test._raw["user_control_tags"] == []

    assert test.user_mitre_mitigation_tags == []
    assert test._raw["user_mitre_mitigation_tags"] == []

    assert test.user_nist_control_tags == []
    assert test._raw["user_nist_control_tags"] == []

    assert test.user_os_tags == []
    assert test._raw["user_os_tags"] == []

    assert test.user_run_as_tags == []
    assert test._raw["user_run_as_tags"] == []

    assert test.user_src_destination_tags == []
    assert test._raw["user_src_destination_tags"] == []

    assert test.user_tags == []
    assert test._raw["user_tags"] == []

    assert test.uuid == "80317688-e8b4-43bf-b5a2-503bb357c9b5"
    assert (
        test._raw["sim_action"]["uuid"]
        == "80317688-e8b4-43bf-b5a2-503bb357c9b5"
    )

    assert test.ver == 2
    assert test._raw["sim_action"]["ver"] == 2

    assert test.verodin_tags == [
        "ATT&CK:Command and Control",
        "ATT&CK:T1105",
        "Malware:MALWARE",
        "ACTOR",
    ]
    assert test._raw["verodin_tags"] == [
        "ATT&CK:Command and Control",
        "ATT&CK:T1105",
        "Malware:MALWARE",
        "ACTOR",
    ]

    assert test.vid == "A300-041"
    assert test._raw["sim_action"]["vid"] == "A300-041"


class TestEvaluation:

  def test_evaluation_fixture(self, full_eval):
    eval = Evaluation(full_eval)


class TestSequence:

  def test_sequence_fixture(self, full_seq):
    sequence = Sequence(full_seq)


class TestVRTFile:

  def test_msv_file_fixture(self, vrt_file):
    test_file = VRTFile(vrt_file)
    assert test_file.id == 4365
    assert test_file.md5sum == "1234abcd1234abcd1234abcd1234abcd"
    assert test_file.orig_file_name == "redacted123asdff._mal"
    assert len(test_file.related_actions) == 2


class TestFullActionTypes:

  def test_full_action_mft_fixture(self, full_action_mft):
    test = FileTransferAction(full_action_mft)
    assert test.file_transfer_library_id == 4428
    assert test.target_port == 80
    assert (
        test.id == 12717
    )  # The id value from outside the file_transfer_action dict
    assert isinstance(test.file_transfer_library, VRTFile)
    assert (
        test.file_transfer_library.md5sum == "1234abcd1234abcd1234abcd1234abcd"
    )
    assert len(test.mitre_attack_techniques) >= 1
    assert all(
        map(
            lambda x: isinstance(x, MitreAttackTechnique),
            test.mitre_attack_techniques,
        )
    )
    technique = test.mitre_attack_techniques[0]
    assert technique.id == "T1105"
    assert technique.tactics[0].tactic_name == "Command and Control"
    assert len(test.common_detection_alerts) == 2

    assert isinstance(test, FileTransferAction)
    assert issubclass(type(test), FullAction)

  def test_pcap_action_fixture(self, full_action_pcap):
    test = PcapAction(full_action_pcap)
    assert "TCP/80" in test.attacker_ports
    assert "TCP/60299" in test.target_ports
    assert test.id == 40088

    assert isinstance(test, PcapAction)
    assert issubclass(type(test), FullAction)

  def test_web_action_fixture(self, full_action_web):
    test = WebAction(full_action_web)

    assert isinstance(test, WebAction)
    assert issubclass(type(test), FullAction)

  def test_email_action_domain_fixture(self, full_action_email_domain):
    test = EmailAction(full_action_email_domain)

    assert isinstance(test, EmailAction)
    assert issubclass(type(test), FullAction)

  def test_email_action_attachment_fixture(self, full_action_email_attachment):
    test = EmailAction(full_action_email_attachment)

    assert isinstance(test, EmailAction)
    assert issubclass(type(test), FullAction)

  def test_dns_action_fixture(self, full_action_dns):
    test = DnsAction(full_action_dns)

    assert isinstance(test, DnsAction)
    assert issubclass(type(test), FullAction)

  def test_host_action_fixture(self, full_action_host_cli):
    test = HostAction(full_action_host_cli)

    assert isinstance(test, HostAction)
    assert issubclass(type(test), FullAction)

  def test_pt_action_fixture(self, full_action_protected_theater):
    test = HostAction(full_action_protected_theater)

    assert isinstance(test, HostAction)
    assert issubclass(type(test), FullAction)

  def test_captive_ioc_dns_action_fixture(self, full_action_captive_ioc_dns):
    test = CaptiveDnsAction(full_action_captive_ioc_dns)

    assert isinstance(test, CaptiveDnsAction)
    assert issubclass(type(test), FullAction)

  def test_captive_ioc_pcap_action_fixture(self, full_action_captive_ioc_pcap):
    test = CaptivePcapAction(full_action_captive_ioc_pcap)

    assert isinstance(test, CaptivePcapAction)
    assert issubclass(type(test), FullAction)

  def test_captive_ioc_url_action_fixture(self, full_action_captive_ioc_url):
    test = CaptiveUrlAction(full_action_captive_ioc_url)

    assert isinstance(test, CaptiveUrlAction)
    assert issubclass(type(test), FullAction)

  def test_socket_action_fixture(self, full_action_socket):
    test = SocketAction(full_action_socket)

    assert isinstance(test, SocketAction)
    assert issubclass(type(test), FullAction)

  @pytest.mark.skip(reason="We do very little with port scan actions")
  def test_port_scan_action_fixture(self, test_dir):
    raise NotImplementedError

  def test_cloud_action_fixture(self, full_action_cloud):
    test = CloudAction(full_action_cloud)

    assert isinstance(test, CloudAction)
    assert issubclass(type(test), FullAction)


class TestInterpretFullActionJsons:

  def test_file_transfer(self, full_action_mft):
    action = interpret_full_action(full_action_mft)
    assert isinstance(action, FileTransferAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)

  def test_pcap(self, full_action_pcap):
    action = interpret_full_action(full_action_pcap)
    assert isinstance(action, PcapAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)

  def test_web(self, full_action_web):
    action = interpret_full_action(full_action_web)
    assert isinstance(action, WebAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)

  def test_email_attachment(self, full_action_email_attachment):
    action = interpret_full_action(full_action_email_attachment)
    assert isinstance(action, EmailAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)

  def test_email_domain(self, full_action_email_domain):
    action = interpret_full_action(full_action_email_domain)
    assert isinstance(action, EmailAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)

  def test_dns(self, full_action_dns):
    action = interpret_full_action(full_action_dns)
    assert isinstance(action, DnsAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)

  def test_host_cli(self, full_action_host_cli):
    action = interpret_full_action(full_action_host_cli)
    assert isinstance(action, HostAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)

  def test_protected_theater(self, full_action_protected_theater):
    action = interpret_full_action(full_action_protected_theater)
    assert isinstance(action, HostAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)

  def test_captive_dns(self, full_action_captive_ioc_dns):
    action = interpret_full_action(full_action_captive_ioc_dns)
    assert isinstance(action, CaptiveDnsAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)

  def test_captive_pcap(self, full_action_captive_ioc_pcap):
    action = interpret_full_action(full_action_captive_ioc_pcap)
    assert isinstance(action, CaptivePcapAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)

  def test_captive_url(self, full_action_captive_ioc_url):
    action = interpret_full_action(full_action_captive_ioc_url)
    assert isinstance(action, CaptiveUrlAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)

  def test_socket(self, full_action_socket):
    action = interpret_full_action(full_action_socket)
    assert isinstance(action, SocketAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)

  @pytest.mark.skip
  def test_port_scan(self, test_dir):
    raise NotImplementedError

  def test_cloud(self, full_action_cloud):
    action = interpret_full_action(full_action_cloud)
    assert isinstance(action, CloudAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)


class TestDimensions:

  @pytest.mark.skip(reason="Version dependent")
  def test_dimensions_cache_build(self, test_dir):
    director = Director(director_name=test_dir)
    assert director._dimension_cache["Attacker Location"]["Internal"] == 50

  @pytest.mark.skip(reason="Version dependent")
  def test_dimensions_cache_lookup(self, test_dir):
    director = Director(director_name=test_dir)
    assert director.lookup_dimension_id_by_name("Internal") == 50
    assert director.lookup_dimension_name_by_id(50) == "Internal"
    assert director.lookup_dimension_id_by_name("Download-MFT") == 29
    assert director.lookup_dimension_name_by_id(29) == "Download-MFT"


class TestGetContent:

  def test_get_all_partial_actions(self, test_dir):
    director = Director(director_name=test_dir)
    partial_actions = director.get_all_partial_actions()
    assert all(map(lambda x: isinstance(x, Action), partial_actions))
    assert all(map(lambda x: x.vid, partial_actions))
    assert all(map(lambda x: x.name, partial_actions))

  def test_get_full_action(self, test_dir):
    director = Director(director_name=test_dir)
    example_action = director.get_full_action_by_vid("A199-001")
    assert isinstance(example_action, FullAction)
    assert isinstance(example_action, DnsAction)
    assert example_action.vid == "A199-001"
    assert example_action.name == "VRT SDK TEST - DNS - 1"
    assert (
        example_action.dimension_behavior_type
        == enumerations.BehaviorTypeDimensionEnum.MALICIOUS_DNS_QUERY.value
    )
    assert (
        example_action.dimension_OS_platform
        == enumerations.OSPlatformDimensionEnum.GENERAL_OS_PLATFORM.value
    )
    assert (
        example_action.dimension_attacker_location
        == enumerations.AttackerLocationDimensionEnum.INTERNAL.value
    )
    assert (
        example_action.dimension_stage_of_attack
        == enumerations.StageOfAttackDimensionEnum.COMMAND_AND_CONTROL.value
    )
    assert (
        example_action.dimension_attack_vector
        == enumerations.AttackVectorDimensionEnum.DNS.value
    )
    assert (
        example_action.dimension_covert
        == enumerations.CovertDimensionEnum.NO.value
    )

  def test_get_all_full_actions(self, test_dir):
    director = Director(director_name=test_dir)
    actions = director.get_all_full_actions()
    assert all(map(lambda x: x.vid, actions))
    assert all(map(lambda x: x.name, actions))
    assert all(map(lambda x: isinstance(x, Action), actions))
    assert all(map(lambda x: isinstance(x, FullAction), actions))
    assert any(map(lambda x: isinstance(x, FileTransferAction), actions))
    # assert any(map(lambda x: isinstance(x, PcapAction), actions))
    # assert any(map(lambda x: isinstance(x, WebAction), actions))
    assert any(map(lambda x: isinstance(x, HostAction), actions))

  @pytest.mark.skip(reason="Extremely slow, no reason to test if not debugging")
  def test_get_all_full_actions_no_multithread(self, test_dir):
    director = Director(director_name=test_dir)
    actions = director.get_all_full_actions(multi_threaded=False)
    assert all(map(lambda x: x.vid, actions))
    assert all(map(lambda x: x.name, actions))
    assert all(map(lambda x: isinstance(x, Action), actions))
    assert all(map(lambda x: isinstance(x, FullAction), actions))
    assert any(map(lambda x: isinstance(x, FileTransferAction), actions))
    assert any(map(lambda x: isinstance(x, PcapAction), actions))
    assert any(map(lambda x: isinstance(x, WebAction), actions))
    assert any(map(lambda x: isinstance(x, HostAction), actions))

  @pytest.mark.skip(reason="Sanity check, no reason to test if not debugging")
  def test_get_all_full_actions_compare_multithread_vs_no_multithread(
      self, test_dir
  ):
    director = Director(director_name=test_dir)
    actions_serial = director.get_all_full_actions(multi_threaded=False)
    actions_multithreaded = director.get_all_full_actions(multi_threaded=True)
    assert len(actions_serial) == len(actions_multithreaded)

  def test_get_evaluation(self, test_dir):
    director = Director(director_name=test_dir)
    evaluation = director.get_simulation_by_vid("S199-001")
    assert isinstance(evaluation, Evaluation)
    assert evaluation.vid == "S199-001"

  def test_get_sequence(self, test_dir):
    director = Director(director_name=test_dir)
    sequence = director.get_simulation_by_vid("S199-004")
    assert isinstance(sequence, Sequence)
    assert sequence.vid == "S199-004"

  def test_get_evaluations(self, test_dir):
    director = Director(director_name=test_dir)
    evaluations = director.get_evaluations()
    assert len(evaluations) > 0
    assert all(map(lambda x: isinstance(x, Evaluation), evaluations))
    assert all(map(lambda x: x.vid, evaluations))

  def test_get_sequences(self, test_dir):
    director = Director(director_name=test_dir)
    sequences = director.get_sequences()
    assert len(sequences) > 0
    assert all(map(lambda x: isinstance(x, Sequence), sequences))
    assert all(map(lambda x: x.vid, sequences))

  def test_get_files(self, test_dir):
    director = Director(director_name=test_dir)
    files = director.get_all_files()
    assert all(map(lambda x: isinstance(x, VRTFile), files))
    assert all(map(lambda x: x.md5sum, files))
    assert all(map(lambda x: x.orig_file_name, files))


class TestGetFullActionTypes:

  def test_file_transfer_action(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A199-013")
    assert action.vid == "A199-013"
    assert action.name == "VRT SDK TEST - MFT - 1"
    assert isinstance(action, FileTransferAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)
    assert action.app_layer == "http"
    assert action.target_port == 80

  @pytest.mark.skip
  def test_pcap_action(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A333-333")
    assert action.vid == "A333-333"
    assert action.name == ""
    assert isinstance(action, PcapAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)
    assert "TCP/80" in action.attacker_ports
    assert "TCP/60299" in action.target_ports

  @pytest.mark.skip
  def test_website_action(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A333-333")
    assert action.vid == "A333-333"
    assert action.name == ""
    assert isinstance(action, WebAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)
    assert len(action.web_action_steps) == 1
    assert isinstance(action.web_action_steps[0], WebActionStep)
    assert action.server_port == 80
    assert action.http_ver == "1.1"

  def test_email_action_attachment(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A199-004")
    assert action.vid == "A199-004"
    assert action.name == "VRT SDK TEST - EMAIL (ATTACHMENT) - 1"
    assert isinstance(action, EmailAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)
    assert "Placeholder" in action.body
    assert "Email" in action.subject

  def test_email_action_domain(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A199-007")
    assert action.vid == "A199-007"
    assert action.name == "VRT SDK TEST - EMAIL (LINK) - 1"
    assert isinstance(action, EmailAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)
    assert "www.google.com" in action.body
    assert "Email" in action.subject

  def test_dns_action(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A199-001")
    assert action.vid == "A199-001"
    assert action.name == "VRT SDK TEST - DNS - 1"
    assert isinstance(action, DnsAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)
    assert "google" in action.domain
    assert action.query_type == "A"

  def test_host_action(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A199-011")
    assert action.vid == "A199-011"
    assert action.name == "VRT SDK TEST - HOST CLI - 2"
    assert isinstance(action, HostAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)
    assert len(action.host_cli_action_steps) == 1
    assert "whoami" in action.host_cli_action_steps[0].command
    assert all(
        map(
            lambda x: isinstance(x, HostActionStep),
            action.host_cli_action_steps,
        )
    )

  def test_pt_action(self, test_dir):
    director = Director(director_name=test_dir)
    action = director.get_full_action_by_vid("A199-019")
    assert action.vid == "A199-019"
    assert action.name == "VRT SDK TEST - PT - 2"
    assert isinstance(action, HostAction)
    assert isinstance(action, FullAction)
    assert issubclass(type(action), FullAction)
    assert len(action.host_cli_action_steps) == 1
    assert "whoami" in action.host_cli_action_steps[0].command
    assert all(
        map(
            lambda x: isinstance(x, HostActionStep),
            action.host_cli_action_steps,
        )
    )
