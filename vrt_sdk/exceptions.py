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


class ContentParsingError(Exception):
  """Signals that we were unable to parse a content JSON"""

  pass


class VidNotFoundError(Exception):
  """Signals that we could not find a piece of content with the given VID"""

  pass


class InvalidVidError(Exception):
  """Signals that a VID is not valid"""

  pass


class FileExistsOnDirectorError(Exception):
  """Signals that the file already exists on the director"""

  pass


class FileUploadError(Exception):
  """Signals that we could not upload a file"""

  pass


class ActionCreationError(Exception):
  """Signals that we could not create an Action"""

  pass


class AuthenticationError(Exception):
  """Signals that we likely failed to authenticate to the director"""

  pass


class UnprocessableEntityError(Exception):
  """Unprocessable Entity is returned by the MSV director frequently on validation errors"""

  pass
