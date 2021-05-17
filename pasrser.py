#!/usr/bin/env python3
import json
from json2html import *
error_message=str("No file extension has been found in a include/require function. This implies that some PHP code is not scanned by PHPCS.")
with open('gl-sast-report.json') as f:
    data = json.load(f)

remove = [k for k in data["vulnerabilities"] if k['message'] == error_message]

for element in data["vulnerabilities"]:
    if 'id' in element:
        del element['id']
    if 'category' in element:
        del element['category']
    if 'scanner' in element:
        del element['scanner'] 
    if 'identifiers' in element:
        del element['identifiers']
    if 'message' in element:
        del element['message']
    if 'description' in element:
        del element['description']
    if 'cve' in element:
        del element['cve']   
with open('sast-report.html', 'w') as data_file:
    data_file.write(json2html.convert(json = data))
