/*
   Yara Rule Set
   Author: NCSC UK
   Date: 2017-11-23
   Identifier: Turla Neuron
   Reference: https://www.ncsc.gov.uk/alerts/turla-group-malware
*/

rule Neuron_common_strings {
    meta:
        description = "Rule for detection of Neuron based on commonly used strings"
        author = "NCSC UK"
        hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
        date = "2017/11/23"
        reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
        id = "168214d4-7436-531e-9c1f-48ca22215a1b"
    strings:
        $strServiceName = "MSExchangeService" ascii
        $strReqParameter_1 = "cadataKey" wide
        /* $strReqParameter_2 = "cid" wide */ /* disabled due to performance reasons */
        $strReqParameter_3 = "cadata" wide
        $strReqParameter_4 = "cadataSig" wide
        $strEmbeddedKey = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnZ3WXRKcnNRZjVTcCtWVG9Rb2xuaEVkMHVwWDFrVElFTUNTNEFnRkRCclNm clpKS0owN3BYYjh2b2FxdUtseXF2RzBJcHV0YXhDMVRYazRoeFNrdEpzbHljU3RFaHBUc1l4OVBEcURabVVZVklVb HlwSFN1K3ljWUJWVFdubTZmN0JTNW1pYnM0UWhMZElRbnl1ajFMQyt6TUhwZ0xmdEc2b1d5b0hyd1ZNaz08L01vZH VsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjwvUlNBS2V5VmFsdWU+" wide
        $strDefaultKey = "8d963325-01b8-4671-8e82-d0904275ab06" wide
        $strIdentifier = "MSXEWS" wide
        $strListenEndpoint = "443/ews/exchange/" wide
        $strB64RegKeySubstring = "U09GVFdBUkVcTWljcm9zb2Z0XENyeXB0b2dyYXBo" wide
        $strName = "neuron_service" ascii
        $dotnetMagic = "BSJB" ascii
    condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $dotnetMagic and 6 of ($str*)
}

rule Neuron_standalone_signature {
    meta:
        description = "Rule for detection of Neuron based on a standalone signature from .NET metadata"
        author = "NCSC UK"
        hash = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
        date = "2017/11/23"
        reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
        id = "e0be2fe2-32fd-5bdf-bfac-a596264be7ba"
    strings:
        $a = { eb073d151231011234080e12818d1d051281311d1281211d1281211d128121081d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281211d1281 }
        $dotnetMagic = "BSJB" ascii
    condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}

rule Nautilus_modified_rc4_loop {
    meta:
        description = "Rule for detection of Nautilus based on assembly code for a modified RC4 loop"
        author = "NCSC UK"
        hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
        date = "2017/11/23"
        reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
        id = "0c5da057-0f1d-5852-ad75-94bf40c133e4"
    strings:
        $a = {42 0F B6 14 04 41 FF C0 03 D7 0F B6 CA 8A 14 0C 43 32 14 13 41 88 12 49 FF C2 49 FF C9}
    condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $a
}

rule Nautilus_rc4_key {
    meta:
        description = "Rule for detection of Nautilus based on a hardcoded RC4 key"
        author = "NCSC UK"
        hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
        date = "2017/11/23"
        reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
        id = "124c8b95-46fb-5cc1-9b10-b10536e1781d"
    strings:
        $key = {31 42 31 34 34 30 44 39 30 46 43 39 42 43 42 34 36 41 39 41 43 39 36 34 33 38 46 45 45 41 38 42}
    condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $key
}

rule Nautilus_common_strings {
    meta:
        description = "Rule for detection of Nautilus based on common plaintext strings"
        author = "NCSC UK"
        hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
        date = "2017/11/23"
        reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
        id = "0e3af6ef-1a97-5324-a186-95e6f3d836f4"
    strings:
        $ = "nautilus-service.dll" ascii
        $ = "oxygen.dll" ascii
        $ = "config_listen.system" ascii
        $ = "ctx.system" ascii
        $ = "3FDA3998-BEF5-426D-82D8-1A71F29ADDC3" ascii
        $ = "C:\\ProgramData\\Microsoft\\Windows\\Caches\\{%s}.2.ver0x0000000000000001.db" ascii
    condition:
        (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and 3 of them
}

/* Forensic Artifacts */

rule Nautilus_forensic_artificats {
    meta:
        description = "Rule for detection of Nautilus related strings"
        author = "NCSC UK / Florian Roth"
        date = "2017/11/23"
        score = 60
        reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
        id = "0c0a24da-4dbc-543a-9ec0-a5b1ec75c889"
    strings:
        $ = "App_Web_juvjerf3.dll" fullword ascii
        $ = "App_Web_vcplrg8q.dll" fullword ascii
        $ = "ar_all2.txt" fullword ascii
        $ = "ar_sa.txt" fullword ascii
        $ = "Convert.FromBase64String(temp[1])" fullword ascii
        $ = "D68gq#5p0(3Ndsk!" fullword ascii
        $ = "dcomnetsrv" fullword ascii
        $ = "ERRORF~1.ASP" fullword ascii
        $ = "intelliAdminRpc" fullword ascii
        $ = "J8fs4F4rnP7nFl#f" fullword ascii
        $ = "Msnb.exe" fullword ascii
        $ = "nautilus-service.dll"
        $ = "Neuron_service" fullword ascii
        $ = "owa_ar2.bat" fullword ascii
        $ = "payload.x64.dll.system" fullword ascii
        $ = "service.x64.dll.system" fullword ascii
    condition:
        1 of them
}

rule APT_Neuron2_Loader_Strings {
   meta:
      description = "Rule for detection of Neuron2 based on strings within the loader"
      author = "NCSC"
      referer = "https://otx.alienvault.com/pulse/5dad718fa5ec6c21e85c1c66"
      hash = "51616b207fde2ff1360a1364ff58270e0d46cf87a4c0c21b374a834dd9676927"
      id = "eaef4710-1971-55a2-9079-07a9b8bd86eb"
   strings:
      $ = "dcom_api" ascii
      $ = "http://*:80/OWA/OAB/" ascii
      $ = "https://*:443/OWA/OAB/" ascii
      $ = "dcomnetsrv.cpp" wide
      $ = "dcomnet.dll" ascii
      $ = "D:\\Develop\\sps\\neuron2\\x64\\Release\\dcomnet.pdb" ascii
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and 2 of them
}
