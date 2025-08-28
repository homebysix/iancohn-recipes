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

__all__ = ["DictionaryFileCreator"]

file_type_options = [
    #"xml",
    "plist",
    "json"
]
dictionary_file_creator_options = [
    "COMPRESS_JSON"
]
class DictionaryFileCreator(Processor):
    """Create a file from the contents of a dictionary. Plist and JSON supported, XML to (possibly) follow."""

    description = __doc__

    input_variables = {
        "output_file_path": {
            "required": False,
            "description": (
                "The pathname of the file to write. Defaults to '%RECIPE_CACHE_DIR%/dictionary.plist'"
            )
        },
        "file_type": {
            "required": False,
            "default": None,
            "description": (
                "Set the file type. If no file type is specified, the extension of output_file_path is used.",
                "Options: {}".format(file_type_options)
            ),
        },
        "dictionary": {
            "required": False,
            "default": {},
            "description": (
                "A dictionary to write to a file."
            )
        },
        "options": {
            "required": False,
            "default": [],
            "description": (
                "An array of strings representing options. Available options: {}".format(dictionary_file_creator_options)
            )
        }
    }
    output_variables = {
        "output_file_path": {
            "description": "The path of the file created."
        }
    }

    def write_json(self,filePath,dictionary,options=[]) -> _void:
        with open(filePath,"w") as f:
            if "COMPRESS_JSON" in options:
                indent = None
            else:
                indent = 2

            json.dump(dictionary,f,indent=indent)
    
    def write_plist(self,filePath,dictionary,options=[]) -> _void:
        with open(filePath,"wb") as f:
            plistlib.dump(dictionary, f)

    def main(self):
        if self.env.get("output_file_path") == None or self.env.get("output_file_path") == "":
            filePath = self.env.get("RECIPE_CACHE_DIR") + "/dictionary.plist"
        else:
            filePath = self.env.get("output_file_path")

        fileType = self.env.get("file_type", self.input_variables["file_type"]["default"])
        if fileType == None:
            fileType = path.splitext(filePath)[1].replace('.','')
        
        if False == (fileType in file_type_options):
            raise Exception("Unhandled file type specified.")

        self.output("Using '{}' as file type".format(fileType), verbose_level=2)

        actionFunctions = {
            "plist": self.write_plist,
            "json": self.write_json
        }
        
        try:
            actionFunctions[fileType](
                filePath,
                self.env.get("dictionary", self.input_variables["dictionary"]["default"]),
                self.env.get("options", self.input_variables["options"]["default"])
            )

            self.output("Done",verbose_level=1)

        except Exception as e:
            raise ProcessorError(e)

if __name__ == "__main__":
    PROCESSOR = DictionaryFileCreator()
    PROCESSOR.execute_shell()
