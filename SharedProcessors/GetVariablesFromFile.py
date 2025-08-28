#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2025 Ian Cohn
# https://www.github.com/iancohn
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

import re,json,plistlib#,xml.etree,xml.etree.ElementTree as ET
from inspect import _void
from autopkglib import Processor, ProcessorError
from os import path

__all__ = ["GetVariablesFromFile"]

file_type_options = [
    #"xml",
    "plist",
    "json"
]
class GetVariablesFromFile(Processor):
    """Import processor variables from a file. Currently JSON and PLIST files are supported. XML to follow."""

    description = __doc__

    input_variables = {
        "file_type": {
            "required": False,
            "default": None,
            "description": (
                "Set the file type. If no file type is specified, the extension is used.",
                "Options: {}".format(file_type_options)
            ),
        },
        "input_file_path": {
            "required": True,
            "description": (
                "The pathname of the file to inspect."
            )
        },
        "include": {
            "required": False,
            "default": [],
            "description": (
                "An array of strings of keys to include."
            )
        },
        "exclude": {
            "required": False,
            "default": [],
            "description": (
                "An array of strings of keys to exclude."
            )
        }
    }
    output_variables = {}
    
    """
    def get_xml_variables(self,filePath,include:list = [],exclude:list = []) -> _void:
        self.output('Getting variables from XML file.',verbose_level=3)
        xml = ET.fromstring(etree.__loader__.get_data(filePath))

    """
    def get_plist_variables(self,filePath,include:list = [],exclude:list = []) -> _void:
        self.output('Getting variables from PLIST file.',verbose_level=3)
        with open(filePath,'rb') as file:
            plist = plistlib.load(file)
        
        self.output("{} content:\r\n{}".format('Plist', print(plist)),verbose_level=3)
        for key in plist.keys():
            if False == exclude.__contains__(key) and (len(include) == 0 or include.__contains__(key)):
                self.env[key] = plist[key]

    def get_json_variables(self,filePath,include:list = [],exclude:list = []) -> _void:
        self.output('Getting variables from JSON file.',verbose_level=3)
        with open(filePath,'rb') as file:
            js = json.load(file)
        
        self.output("{} content:\r\n{}".format('Json', print(js)),verbose_level=3)
        for key in js.keys():
            if False == exclude.__contains__(key) and (len(include) == 0 or include.__contains__(key)):
                self.env[key] = js[key]

    def main(self):
        fileType = self.env.get("file_type", self.input_variables["file_type"]["default"])
        filePath = self.env["input_file_path"]
        if fileType == None:
            fileType = path.splitext(filePath)[1].replace('.','')

        self.output("Using '{}' as file type".format(fileType), verbose_level=2)

        actionFunctions = {
            #"xml": self.get_xml_variables,
            "plist": self.get_plist_variables,
            "json": self.get_json_variables
        }
        
        try:
            self.output("Loading file; setting variables", verbose_level=1)
            actionFunctions[fileType](
                filePath,
                self.env.get("include", self.input_variables["include"]["default"]),
                self.env.get("exclude", self.input_variables["exclude"]["default"])
            )

            self.output("Done",verbose_level=1)

        except Exception as e:
            raise ProcessorError(e)

if __name__ == "__main__":
    PROCESSOR = GetVariablesFromFile()
    PROCESSOR.execute_shell()
