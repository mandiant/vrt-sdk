# VRT-SDK

Google Threat Intelligence Group (GTIG) Validation Research Team's (VRT) Python
SDK for interacting with the Mandiant Security Validation (MSV) platform API.

# Disclaimers

## Ownership

This SDK was developed by VRT specifically for our team's use cases involving
the creation of validation content.

## Reliability & Bug Fixes

The SDK is provided **as is** so that external parties can benefit. VRT may
update this code at our discretion. VRT makes no representations or
warranties that this code will operate in other environments, that it is
free from defects, or that future updates will be provided.

## Affiliation with Mandiant Security Validation API

VRT is **not** involved in the creation,
development, or maintenance of the MSV API in any way.
Official documentation for the
Mandiant Security Validation API can be
found [here](https://docs.mandiant.com/home/security-validation-api).

VRT assumes **no responsibility** for addressing any defects, updates, or
changes
in the MSV API.

## On-Premises vs. SaaS

The Software-as-a-Service (SaaS) version of MSV is being deprecated.
Consequently, no assurances are provided regarding the reliability of this
library for interaction with SaaS instances.

While most, but not all, functionality is available for SaaS as of the
time of writing, **no** efforts will be undertaken to maintain such
compatibility.

## Tests

Pytest was utilized during the development process and to mitigate the
impact of breaking changes in the MSV API on this library.

Several tests necessitate an active connection to an MSV director for proper
execution, as well as the "VRT SDK Test Pack" available on the content
portal. These tests require pytest to be invoked with
`--director {director_name}` (see _usage_ section below for details on
configuring
an .ini file with director names).

While many tests are not currently in active use, they have been retained
within the test suite for potential future utility.

# Installation

Clone this repository, then run `pip install .`

# Documentation

It is recommended to use the provided examples and the documentation rendered in
your IDE for guidance. However, some incomplete documentation has been provided
in `DOCS.md`.

# Usage

## Configuration File

Using a .ini config file simplifies the management of multiple environments
considerably.

Create a .ini file using the format below.

Then set an environment variable named `VRTCONFIG` containing the absolute
path of the .ini file.

### Example .ini Configuration

```ini
[msv_directors]  # Mapping of names to the org ID (for SaaS) or URL (for on-prem)
saas_rnd = 1
saas_stg = 2
on_prem_rnd = 127.0.0.1
on_prem_stg = stg.example.com

[msv_saas]  # Section only required if SaaS directors are in use
address = msv.example.com
apikey = EXAMPLE

[1]
username = user@example.com
type = saas

[2]
username = user@example.com
type = saas

[127.0.0.1]
username = user@example.com
apikey = EXAMPLE
type = onprem

[stg.example.com]
username = user@example.com
apikey = EXAMPLE
type = onprem
```

The `msv_directors` section contains key-value pairs mapping human-readable
names to either the org ID (for SaaS directors) or the URL (for on-prem
directors).

Each value under the `msv_directors` section is used as the name for a section
containing additional information about a director. All director entries must
contain a username key (typically an email address) and a type key, which must
be one of _{saas|onprem}_. On-premises director entries must contain the
_apikey_ key as well.

If any entries are SaaS directors, then an `msv_saas` section is required,
pointing to the URL of the MSV SaaS platform in use and providing the API key
for use with the SaaS director (typically shared across all SaaS orgs).

## Creating a Director Client

### Via human-readable name

If you have set up a configuration file as described above, then you should be
able to provide a human-readable name directly to the Director class to create a
client.

```python
import vrt_sdk

client = vrt_sdk.Director("saas_rnd")
client = vrt_sdk.Director("saas_stg")
client = vrt_sdk.Director("on_prem_rnd")
client = vrt_sdk.Director("on_prem_stg")
```

### Via director name w/config file

If no environment variable is set, the config path can be provided manually.

```python
import vrt_sdk

client = vrt_sdk.Director("saas_rnd", vrt_config_path="/home/user/config.ini")
```

### Via credentials directly

If a configuration file is unavailable, arguments can be passed directly to the
Director class instead.

```python
import vrt_sdk

on_prem_client = vrt_sdk.Director(
  director_address="hxxps://mandiant[.]com",
  director_username="johndoe",
  director_apikey="1234abcd",
)
saas_client = vrt_sdk.Director(
  director_address="hxxps://mandiant[.]com",
  director_username="johndoe",
  director_apikey="1234abcd",
  director_org_id=1,
)
```

## Tag Contexts

The Director client possesses methods to apply and remove tags to content.
Depending on their usage, these may require specifying the appropriate context.
For external users, the "user_" version of contexts displayed in the column on
the right should be used.

External users attempting to use the equivalent contexts on the left will
receive undefined behaviors (most likely an error response or simply no change
to the content).

| Verodin (Mandiant) Tag Contexts | User Tag Contexts     |
|---------------------------------|-----------------------|
| verodin                         | user                  |
| run_as                          | user_run_as           |
| src_destination                 | user_src_destination  |
| os                              | user_os               |
| control                         | user_control          |
| mitre_mitigation                | user_mitre_mitigation |
| nist_control                    | user_nist_control     |

## Example Scripts

Example scripts for the following tasks are provided under the `examples`
directory

- List all Actions and their dimensions
- List all Actions and their mitre techniques
- List all Malicious File Transfer Actions and their associated files
- List all DNS Query Actions and their associated domains
- Upload a file to the director file library
- Create IOC Actions (Malicious File Transfer, DNS, Email)
- Create endpoint Actions (Host CLI, Protected Theater)
- Create an Evaluation from all Actions with a specific tag

WARNING - THIS CAN CAUSE THE CREATION OF A LARGE AMOUNT OF TAGS

- **Apply framework tags to Actions based on a user-provided mapping of MITRE
  techniques to other frameworks**

