#!/usr/bin/env python3
import json
from json2html import *
import os
language=os.getenv('LANGUAGE')
def remove_commons(element):
        if 'id' in element:
            del element['id']
        if 'category' in element:
            del element['category']
        if 'scanner' in element:
            del element['scanner'] 
        if 'identifiers' in element:
            del element['identifiers']
        if 'name' in element:
            del element['name']
        if 'cve' in element:
            del element['cve']

error_message=str("No file extension has been found in a include/require function. This implies that some PHP code is not scanned by PHPCS.")
try:
    with open('gl-sast-report.json') as f:
        data = json.load(f)
except IOError:
    print("File not accessible")
    exit(0)

list_vuln = data["vulnerabilities"]
data["vulnerabilities"] = [vulnerability for vulnerability in list_vuln if vulnerability['message'] != error_message]

if language == "php":
    for element in data["vulnerabilities"]:
        remove_commons(element)
        if 'message' in element:
            del element['message']

if language == "javascript":
    for element in data["vulnerabilities"]:
        remove_commons(element)
if language == "dotnet":
    for element in data["vulnerabilities"]:
        remove_commons(element)
        if 'message' in element:
            del element['message']

with open('sast-report.html', 'w') as data_file:
    data_file.write(json2html.convert(json = data))
