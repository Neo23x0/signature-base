#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Get-OTX-IOCs
# Retrieves IOCs from Open Threat Exchange
#
# Create an account and select your feeds
# https://otx.alienvault.com
#
# Changes:
# 16.12.2017 - Merged the changes by Scott with the code base
# 22.11.2017 - Scott Carpenter uberbigun@gmail.com
#
# v2 takes the --siem logic of outputing csv and switches the default to use csv and --siem using txt with only raw output
# based on the indicator type. McAfee ESM watchlists must contain only type of IPv4, IPv6, Hash, Filename and cannot be mixed.
# Towards that end, the C2 indicators have been separated into three files rather than one.


from OTXv2 import OTXv2
import re
import os
import sys
import traceback
import argparse

OTX_KEY = ''

HASH_WHITELIST = ['e617348b8947f28e2a280dd93c75a6ad',
                  '125da188e26bd119ce8cad7eeb1fc2dfa147ad47',
                  '06f7826c2862d184a49e3672c0aa6097b11e7771a4bf613ec37941236c1a8e20',
                  'd378bffb70923139d6a4f546864aa61c']
DOMAIN_WHITELIST = ['proofpoint.com']


class WhiteListedIOC(Exception): pass


class OTXReceiver():
    # IOC Strings
    hash_iocs = ""
    filename_iocs = ""
    c2_iocs_ipv4 = ""
    c2_iocs_ipv6 = ""
    c2_iocs_domain = ""

    # Output format
    separator = ";"
    use_csv_header = False
    extension = "txt"
    hash_upper = True
    filename_regex_out = True

    def __init__(self, api_key, siem_mode, debug, proxy, csvheader, extension):
        self.debug = debug
        self.otx = OTXv2(api_key, proxy)

        if siem_mode:
            self.separator = ","
            self.use_csv_header = csvheader
            self.extension = extension
            self.hash_upper = True
            self.filename_regex_out = False

    def get_iocs_last(self):
        # mtime = (datetime.now() - timedelta(days=days_to_load)).isoformat()
        print("Starting OTX feed download ...")
        self.events = self.otx.getall()
        print("Download complete - %s events received" % len(self.events))
        # json_normalize(self.events)

    def write_iocs(self, ioc_folder):

        hash_ioc_file = os.path.join(ioc_folder, "otx-hash-iocs.{0}".format(self.extension))
        filename_ioc_file = os.path.join(ioc_folder, "otx-filename-iocs.{0}".format(self.extension))
        c2_ioc_ipv4_file = os.path.join(ioc_folder, "otx-c2-iocs-ipv4.{0}".format(self.extension))
        c2_ioc_ipv6_file = os.path.join(ioc_folder, "otx-c2-iocs-ipv6.{0}".format(self.extension))
        c2_ioc_domain_file = os.path.join(ioc_folder, "otx-c2-iocs.{0}".format(self.extension))

        print("Processing indicators ...")
        for event in self.events:
            try:
                for indicator in event["indicators"]:

                    try:
                        # Description
                        description = event["name"].encode('unicode-escape').replace(self.separator, " - ")

                        # Hash IOCs
                        if indicator["type"] in ('FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256'):

                            # Whitelisting
                            if indicator["indicator"].lower() in HASH_WHITELIST:
                                raise WhiteListedIOC

                            hash = indicator["indicator"]
                            if self.hash_upper:
                                hash = indicator["indicator"].upper()

                            self.hash_iocs += "{0}{3}{1} {2}\n".format(
                                hash,
                                description,
                                " / ".join(event["references"])[:80],
                                self.separator)

                        # Filename IOCs
                        if indicator["type"] == 'FilePath':

                            filename = indicator["indicator"]
                            if self.filename_regex_out:
                                filename = my_escape(indicator["indicator"])

                            self.filename_iocs += "{0}{3}{1} {2}\n".format(
                                filename,
                                description,
                                " / ".join(event["references"])[:80],
                                self.separator)

                        # C2 IOCs
                        # Whitelisting
                        if indicator["type"] in ('IPv4', 'IPv6', 'domain', 'hostname', 'CIDR'):
                            for domain in DOMAIN_WHITELIST:
                                if domain in indicator["indicator"]:
                                    print(indicator["indicator"])
                                    raise WhiteListedIOC

                        if indicator["type"] == 'IPv4':
                            self.c2_iocs_ipv4 += "{0}{3}{1} {2}\n".format(
                                indicator["indicator"],
                                description,
                                " / ".join(event["references"])[:80],
                                self.separator)

                        if indicator["type"] == 'IPv6':
                            self.c2_iocs_ipv6 += "{0}{3}{1} {2}\n".format(
                                indicator["indicator"],
                                description,
                                " / ".join(event["references"])[:80],
                                self.separator)

                        if indicator["type"] in ('domain', 'hostname', 'CIDR'):
                            self.c2_iocs_domain += "{0}{3}{1} {2}\n".format(
                                indicator["indicator"],
                                description,
                                " / ".join(event["references"])[:80],
                                self.separator)

                    except WhiteListedIOC as e:
                        pass

            except Exception as e:
                traceback.print_exc()

        # Write to files
        with open(hash_ioc_file, "w") as hash_fh:
            if self.use_csv_header:
                hash_fh.write('hash{0}'.format(self.separator) + 'source\n')
            hash_fh.write(self.hash_iocs)
            print("{0} hash iocs written to {1}".format(self.hash_iocs.count('\n'), hash_ioc_file))
        with open(filename_ioc_file, "w") as fn_fh:
            if self.use_csv_header:
                fn_fh.write('filename{0}'.format(self.separator) + 'source\n')
            fn_fh.write(self.filename_iocs)
            print("{0} filename iocs written to {1}".format(self.filename_iocs.count('\n'), filename_ioc_file))
        with open(c2_ioc_ipv4_file, "w") as c24_fh:
            if self.use_csv_header:
                c24_fh.write('host{0}'.format(self.separator) + 'source\n')
            c24_fh.write(self.c2_iocs_ipv4)
            print("{0} c2 ipv4 iocs written to {1}".format(self.c2_iocs_ipv4.count('\n'), c2_ioc_ipv4_file))
        with open(c2_ioc_ipv6_file, "w") as c26_fh:
            if self.use_csv_header:
                c26_fh.write('host{0}'.format(self.separator) + 'source\n')
            c26_fh.write(self.c2_iocs_ipv6)
            print("{0} c2 ipv6 iocs written to {1}".format(self.c2_iocs_ipv6.count('\n'), c2_ioc_ipv6_file))
        with open(c2_ioc_domain_file, "w") as c2d_fh:
            if self.use_csv_header:
                c2d_fh.write('host{0}'.format(self.separator) + 'source\n')
            c2d_fh.write(self.c2_iocs_domain)
            print("{0} c2 domain iocs written to {1}".format(self.c2_iocs_domain.count('\n'), c2_ioc_domain_file))


def my_escape(string):
    return re.sub(r'([\-\(\)\.\[\]\{\}\\\+])', r'\\\1', string)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='OTX IOC Receiver')
    parser.add_argument('-k', help='OTX API key', metavar='APIKEY', default=OTX_KEY)
    # parser.add_argument('-l', help='Time frame in days (default=1)', default=1)
    parser.add_argument('-o', metavar='dir', help='Output directory', default='../iocs')
    parser.add_argument('-p', metavar='proxy', help='Proxy server (e.g. http://proxy:8080 or '
                                                    'http://user:pass@proxy:8080', default=None)
    parser.add_argument('--verifycert', action='store_true', help='Verify the server certificate', default=False)
    parser.add_argument('--siem', action='store_true', default=False,
                        help='CSV output for use in SIEM systems (e.g. Splunk)')
    parser.add_argument('--nocsvheader', action='store_true', default=False,
                        help='Disable header in CSV output (e.g. McAfee SIEM)')
    parser.add_argument('-e', metavar='ext', help='File extension', default='txt')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    if len(args.k) != 64:
        print("Set an API key in script or via -k APIKEY. Go to https://otx.alienvault.com create an account and get your own API key")
        sys.exit(0)

    # Create a receiver
    otx_receiver = OTXReceiver(api_key=args.k, siem_mode=args.siem, debug=args.debug, proxy=args.p,
                               csvheader=(not args.nocsvheader), extension=args.e)

    # Retrieve the events and store the IOCs
    # otx_receiver.get_iocs_last(int(args.l))
    otx_receiver.get_iocs_last()

    # Write IOC files
    otx_receiver.write_iocs(ioc_folder=args.o)