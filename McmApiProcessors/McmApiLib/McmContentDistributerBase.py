#!/usr/local/autopkg/python
# pylint: disable=invalid-name
# -*- coding: utf-8 -*-
#
# Copyright 2025 Ian Cohn
# https://www.github.com/autopkg/iancohn-recipes
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, 
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import requests

from autopkglib import (  # pylint: disable=import-error
    ProcessorError,
)

# to use a base/external module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
import os.path
import sys

sys.path.insert(0,os.path.dirname(__file__))
from McmApiLib.McmApiBase import ( #noqa: E402
    McmApiBase
)

class McmContentDistributerBase(McmApiBase):
   def initialize_all(self):
      self.initialize_headers()
      self.initialize_ntlm_auth()
      

"""restart_existing_distributions": {
            "required": False,
            "description": "Whether to redistribute (stop/start) the content to locations where it is already distributed.",
            "default": True
        },
        "distribution_point_group_names": {
            "required": False,
            "description": "A list of distribution point group names that should receive the content",
            "default": []
        },
        "distribution_point_nal_paths": {
            "required": False,
            "description": "A list of NALPath strings for distribution points that should receive the content",
            "default": []
        }
"""