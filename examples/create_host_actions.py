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

import random
from vrt_sdk import Director
from vrt_sdk import HostActionFactory
from vrt_sdk import OSPlatformDimensionEnum
from vrt_sdk import StageOfAttackDimensionEnum

"""
This script demonstrates using the director client to create host Actions.
"""
client = Director("DIRECTOR_NAME")

# ------------------------------------------------------------------------------
# Create a Protected Theater Action

# Upload a file of random bytes
test_file_string = f"VRT_SDK_EXAMPLE_FILE_{random.randint(1000001, 9999999)}"
test_file_bytes = random.randbytes(200)
file_id_response = client.upload_file(
    test_file_bytes,
    test_file_string,
    "restricted_malicious",
    "This is a file of random bytes used for a VRT SDK example. If you see"
    " this, it is safe to delete.",
    OSPlatformDimensionEnum.GENERAL_OS_PLATFORM,
)

# Create a factory for a PT (omitting `protected` defaults to `True`)
factory = HostActionFactory(
    action_name=(
        f"VRT_SDK_EXAMPLE_PROTECTED_THEATER_{random.randint(1000001, 9999999)}"
    ),
    action_description=(
        "This is a VRT SDK example. If you see this, it is safe to delete."
    ),
    shell="cmd.exe",
)

# Add steps to the action
factory.add_step("echo 'LV 12 WIZARD'", criteria="success_match:WIZARD")
factory.add_step("echo 'Success Zero Check'")
factory.add_step("echo 'Expanded Time Values'", sleep=8, timeout="120")
factory.add_step("echo 'Cleanup Check'", criteria="cleanup")

# Ask the director client to give the factory the correct dimensions
# (omitted dimensions result in generic defaults)
client.set_host_factory_dimensions(
    factory, stage_of_attack=StageOfAttackDimensionEnum.EXECUTION
)

# Add a file to the Host Action
factory.add_file(file_id_response, "C:\\Windows\\Temp", "example_evil_file.bin")

# Provide the director client with the factory, which will provide all required
# information for action creation
client.create_host_action(factory)

# ------------------------------------------------------------------------------
# Create a Host CLI Action - completely identical to the above,
# ust with "protected" explicitly set to False

# Upload a file of random bytes
test_file_string = f"VRT_SDK_EXAMPLE_FILE_{random.randint(1000001, 9999999)}"
test_file_bytes = random.randbytes(200)
file_id_response = client.upload_file(
    test_file_bytes,
    test_file_string,
    "none",
    "This is a file of random bytes used for a VRT SDK example. If you see"
    " this, it is safe to delete.",
    OSPlatformDimensionEnum.GENERAL_OS_PLATFORM,
)

# Create a factory for a Host CLI
factory = HostActionFactory(
    action_name=f"VRT_SDK_EXAMPLE_HOST_CLI_{random.randint(1000001, 9999999)}",
    action_description=(
        "This is a VRT SDK example. If you see this, it is safe to delete."
    ),
    shell="cmd.exe",
    protected=False,
)

# Add steps to the action
factory.add_step("echo 'LV 12 WIZARD'", criteria="success_match:WIZARD")
factory.add_step("echo 'Success Zero Check'")
factory.add_step("echo 'Expanded Time Values'", sleep=8, timeout="120")
factory.add_step("echo 'Cleanup Check'", criteria="cleanup")

# Ask the director client to give the factory the correct dimensions
# (omitted dimensions result in generic defaults)
client.set_host_factory_dimensions(
    factory, stage_of_attack=StageOfAttackDimensionEnum.EXECUTION
)

# Add a file to the Host Action
factory.add_file(file_id_response, "C:\\Windows\\Temp", "example_evil_file.bin")

# Provide the director client with the factory, which will provide all required
# information for action creation
client.create_host_action(factory)
