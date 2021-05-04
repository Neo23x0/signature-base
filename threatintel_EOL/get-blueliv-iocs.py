#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Get-MISP-IOCs
# Retrieves IOCs from MISP and stores them in appropriate format

API_KEY = '--- YOUR API KEY ---'

import sys
import json
import argparse
import os
import re
import io
import logging
from sdk.blueliv_api import BluelivAPI


class BlueLivReceiver():

    hash_iocs = {}
    filename_iocs = {}
    c2_iocs = {}
    yara_rules = {}

    debugon = False

    # Output
    siem_mode = False
    separator = ";"
    use_headers = False
    use_filename_regex = True

    def __init__(self, api_key, host, siem_mode=False, debugon=False):
        self.debugon = debugon
        self.api_key = api_key
        self.host = host
        if siem_mode:
            self.siem_mode = True
            self.separator = ","
            self.use_headers = True
            self.use_filename_regex = False

    def get_iocs_last(self):

        __LOG_FILE = 'blueliv.log'
        logging.basicConfig(filename=__LOG_FILE)
        logger = logging.getLogger('main')

        proxy = None
        # If you have a proxy, comment the line above and uncomment
        # these lines below:
        """
        proxy = {'http': '50.60.110.152:80',
                 'https': '50.60.110.152:80'}
        """
        print("https://{0}".format(self.host))
        api = BluelivAPI(base_url="https://{0}".format(self.host),
                         token=self.api_key,
                         log_level=logging.INFO,
                         proxy=proxy)

        # Get available resources
        print(api.crime_servers.get_resources())
        # Get last malware updates
        response = api.crime_servers.test()
        print(response)
        try:
            # WORK WITH MALWARE DATA
            # Get all the items returned
            print(response.updated_at)
            print(response.total_size)
            print(response.items)  # malwares
            print(response.next_update)
        except Exception as e:
            logger.error('{}'.format(e))
        else:
            print('Success!')

    def add_ioc(self, ioc_type, value, comment, uuid, info):
        # Cleanup value
        value = value.encode('unicode_escape')
        # Debug
        if self.debugon:
            print("{0} = {1}".format(ioc_type, value))
        # C2s
        if ioc_type in ('hostname', 'ip-dst', 'domain'):
            if value == '127.0.0.1':
                return
            self.c2_iocs[value] = comment
        # Hash
        if ioc_type in ('md5', 'sha1', 'sha256'):
            # No empty files
            if value == 'd41d8cd98f00b204e9800998ecf8427e' or \
                            value == 'da39a3ee5e6b4b0d3255bfef95601890afd80709' or \
                            value == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855':
                return
            self.hash_iocs[value] = comment
        # Filenames
        if ioc_type in ('filename', 'filepath'):
            # Add prefix to filenames
            if not re.search(r'^([a-zA-Z]:|%)', value):
                if not self.siem_mode:
                    value = "\\\\{0}".format(value)
            if self.use_filename_regex:
                self.filename_iocs[my_escape(value)] = comment
            else:
                self.filename_iocs[value.decode('string_escape')] = comment

    def write_iocs(self, output_path, output_path_yara):
        # Write C2 IOCs
        self.write_file(os.path.join(output_path, "misp-c2-iocs.txt"), self.c2_iocs, "c2")
        # Write Filename IOCs
        self.write_file(os.path.join(output_path, "misp-filename-iocs.txt"), self.filename_iocs, "filename")
        # Write Hash IOCs
        self.write_file(os.path.join(output_path, "misp-hash-iocs.txt"), self.hash_iocs, "hash")

    def write_file(self, ioc_file, iocs, ioc_type):
        with open(ioc_file, 'w') as file:
            if self.use_headers:
                file.write("{0}{1}description\n".format(ioc_type, self.separator))
            for ioc in iocs:
                file.write("{0}{2}{1}\n".format(ioc,iocs[ioc],self.separator))
        print("{0} IOCs written to file {1}".format(len(iocs), ioc_file))


def generate_identifier(string):
    valid_chars = '-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(char for char in string if char in valid_chars)


def my_escape(string):
    # Escaping
    string = re.sub(r'([\-\(\)\.\[\]\{\}\\\+])',r'\\\1',string)
    # Fix the cases in which the value has already been escaped
    string = re.sub(r'\\\\\\\\',r'\\\\',string)
    return string


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='BlueLiv IOC Receiver')
    parser.add_argument('-k', help='BlueLiv API key', metavar='APIKEY', default=API_KEY)
    parser.add_argument('-l', help='Time frame (e.g. 2d, 12h - default=30d)', metavar='tframe', default='30d')
    parser.add_argument('-o', help='Output directory', metavar='dir', default='../iocs')
    parser.add_argument('-y', help='YARA rule output directory', metavar='yara-dir', default='../iocs/yara')
    parser.add_argument('--nonfree', action='store_true', help='Use the non-free API', default=False)
    parser.add_argument('--siem', action='store_true', help='CSV Output for use in SIEM systems (Splunk)', default=False)
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    if len(args.k) != 36:
        print("Set an API key in script or via -k APIKEY.")
        sys.exit(0)

    host = "freeapi.blueliv.com"
    if args.nonfree:
        host = "api.blueliv.com"

    # Create a receiver
    blueliv_receiver = BlueLivReceiver(api_key=args.k, host=host, siem_mode=args.siem, debugon=args.debug)

    # Retrieve the events and store the IOCs
    blueliv_receiver.get_iocs_last()

    # Write IOC files
    blueliv_receiver.write_iocs(args.o, args.y)

