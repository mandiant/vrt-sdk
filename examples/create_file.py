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
This script demonstrates using the director client to upload a file to a
director.
"""
client = Director("DIRECTOR_NAME")

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
