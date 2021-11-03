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
# 13.02.2018 - Reworked the hash whitelist
# 03.11.2021 - Updated to Python3
#

from OTXv2 import OTXv2
import re
import os
import sys
import traceback
import argparse

OTX_KEY = ''

# Hashes that are often included in pulses but are false positives
# Hashes that are often included in IOC lists but are false positives
HASH_WHITELIST = [
    # Empty file
    'd41d8cd98f00b204e9800998ecf8427e',
    'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    # One byte line break file (Unix) 0x0a
    '68b329da9893e34099c7d8ad5cb9c940',
    'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc',
    '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
    # One byte line break file (Windows) 0x0d0a
    '81051bcc2cf1bedf378224b0a93e2877',
    'ba8ab5a0280b953aa97435ff8946cbcbb2755a27',
    '7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6',
    # One byte file with 0x00
    '93b885adfe0da089cdf634904fd59f71',
    '5ba93c9db0cff93f52b521d7420e43f6eda2784f',
    '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
    # 1024 bytes 0x00
    '0f343b0931126a20f133d67c2b018a3b',
    '60cacbf3d72e1e7834203da608037b1bf83b40e8',
    '5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef',
    # 2048 bytes 0x00
    'c99a74c555371a433d121f551d6c6398',
    '605db3fdbaff4ba13729371ad0c4fbab3889378e',
    'e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad',
    # 4096 bytes 0x00
    '620f0b67a91f7f74151bc5be745b7110',
    '1ceaf73df40e531df3bfb26b4fb7cd95fb7bff1d',
    'ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7',
    # File filled with 99 zeros (probably caused by AV)
    'fa8715078d45101200a6e2bf7321aa04',
    'd991c16949bd5e85e768385440e18d493ce3aa46',
    '4b298058e1d5fd3f2fa20ead21773912a5dc38da3c0da0bbc7de1adfb6011f1c',
    # 1x1 pixel JPEG
    'c5e389341a0b19b6f045823abffc9814',
    'c82cee5f957ad01068f487eecd430a1389e0d922',
    '995c770caeb45f7f0c1bc3affc60f11d8c40e16027df2cf711f95824f3534b6f',
    # 1x1 tracking pixel GIF
    '325472601571f31e1bf00674c368d335',
    '2daeaa8b5f19f0bc209d976c02bd6acb51b00b0a',
    'b1442e85b03bdcaf66dc58c7abb98745dd2687d86350be9a298a1d9382ac849b',
    # Empty Word document
    'e617348b8947f28e2a280dd93c75a6ad',
    '125da188e26bd119ce8cad7eeb1fc2dfa147ad47',
    '06f7826c2862d184a49e3672c0aa6097b11e7771a4bf613ec37941236c1a8e20',
    # File that contains the word 'administrator'
    '200ceb26807d6bf99fd6f4f0d1ca54d4',
    'b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3',
    '4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9',
    # File that contains the word 'foo\x0a'
    'd3b07384d113edec49eaa6238ad5ff00',
    'f1d2d2f924e986ac86fdf7b36c94bcdf32beec15',
    'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c',
    # File that contains the word 'yes'
    'a6105c0a611b41b08f1209506350279e',
    'fb360f9c09ac8c5edb2f18be5de4e80ea4c430d0',
    '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d',
    # File that contains 2\x0d\x0a
    '10400c6faf166902b52fb97042f1e0eb',
    'f1d2d2f924e986ac86fdf7b36c94bcdf32beec15',
    'df4e26a04a444901b95afef44e4a96cfae34690fff2ad2c66389c70079cdff2b',
    # File that contains 44 43 48 01 18 40 80 25 03 00 06 00 DCH..@.%.... (unknown)
    '4b6c7f3146f86136507497232d2f04a0',
    'deabe082bc0f0f503292e537b2675c7c93dca40f',
    '4a15a6777284035dfd8df4ecf496b4f0557a9cc4ffaaf5887659031e843865e1',
    # WinPCap 4.1.3
    'a11a2f0cfe6d0b4c50945989db6360cd',
    'e2516fcd1573e70334c8f50bee5241cdfdf48a00',
    'fc4623b113a1f603c0d9ad5f83130bd6de1c62b973be9892305132389c8588de',
    # disallowedcertstl.cab
    '16e8e953c65d610c3bfc595240f3f5b7',
    '231a802e6ff1fae42f2b12561fff2767d473210b',
    '048846ed8ed185a26394adeb3f63274d1029bbd59cffa8e73a4ef8b19456de1d',
    # Powerpoint 2010
    'e24133dd836d99182a6227dcf6613d08',
    '72c2dbbb1fe642073002b30987fcd68921a6b140',
    '4dde54cfc600dbd9a610645d197a632e064115ffaa3a1b595c3a23036e501678',
    # Special CAB file
    '41f958d2d3e9ed4504b6a8863fd72b49',
    'f6d380b256b0e66ef347adc78195fd0f228b3e33',
    'c929701c67a05f90827563eedccf5eba8e65b2da970189a0371f28cd896708b8',
    # MS Notepad
    'd378bffb70923139d6a4f546864aa61c',
    'f00aa51c2ed8b2f656318fdc01ee1cf5441011a4',
    'c4232ddd4d37b9c0884bd44d8476578c54d7f98d58945728e425736a6a07e102',
    # MSVCR71.DLL
    '86f1895ae8c5e8b17d99ece768a70732',
    'd5502a1d00787d68f548ddeebbde1eca5e2b38ca',
    '8094af5ee310714caebccaeee7769ffb08048503ba478b879edfef5f1a24fefe',
    # RecordedTV.library-ms
    'b6f9aa44c5f0565b5deb761b1926e9b6',
    '183d0929423da2aa83441ee625de92b213f33948',
    '07c4c7ae2c4c7cb3ccd2ba9cd70a94382395ca8e2b0312c1631d09d790b6db33',
    # 404 error message
    '8e325dc2fea7c8900fc6c4b8c6c394fe',
    '1b3291d4eea179c84145b2814cb53e6a506ec201',
    '0b52c5338af355699530a47683420e48c7344e779d3e815ff9943cbfdc153cf2',
]
FILENAMES_WHITELIST = ['wncry']
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
                        description = event["name"].replace(self.separator, " - ")

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

                            # Whitelisting
                            for w in FILENAMES_WHITELIST:
                                if w in indicator["indicator"]:
                                    raise WhiteListedIOC

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
