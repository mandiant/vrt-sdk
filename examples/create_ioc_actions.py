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
from vrt_sdk import OSPlatformDimensionEnum

"""
This script demonstrates using the director client to create various types of IOC Actions.
"""
client = Director("DIRECTOR_NAME")

identifier = random.randint(1000001, 9999999)

# Upload a file of random bytes
test_file_string = f"VRT_SDK_EXAMPLE_FILE_{identifier}"
test_file_bytes = random.randbytes(200)
file_id_response = client.upload_file(
    test_file_bytes,
    test_file_string,
    "restricted_malicious",
    "This is a file of random bytes used for a VRT SDK example. If you see"
    " this, it is safe to delete.",
    OSPlatformDimensionEnum.GENERAL_OS_PLATFORM,
)

# Create an MFT Action from the file
client.create_file_transfer_action(
    action_name=f"VRT_SDK_EXAMPLE_MFT_{identifier}",
    action_description=(
        "This is a VRT SDK example. If you see this, it is safe to delete."
    ),
    file_id=file_id_response,
    os_value=OSPlatformDimensionEnum.GENERAL_OS_PLATFORM,
)

# Create a DNS Action
client.create_dns_action(
    action_name=f"VRT_SDK_EXAMPLE_DNS_{identifier}",
    action_description=(
        "This is a VRT SDK example. If you see this, it is safe to delete."
    ),
    domain="www.google.com",
)

# Create a Phishing Action from the file
client.create_email_action(
    action_name=f"VRT_SDK_EXAMPLE_PHISH_ATTACH_{identifier}",
    action_description=(
        "This is a VRT SDK example. If you see this, it is safe to delete."
    ),
    body="GET PHISHED",
    file_attachment=file_id_response,
)

# Create a Phishing Action without a file
client.create_email_action(
    action_name=f"VRT_SDK_EXAMPLE_PHISH_LINK_{identifier}",
    action_description=(
        "This is a VRT SDK example. If you see this, it is safe to delete."
    ),
    body='<a href="https://www.google.com>Click here</a>',
)
