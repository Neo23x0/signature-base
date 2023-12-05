/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-06-26
   Identifier: RANCOR
   Reference: https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT_RANCOR_JS_Malware {
   meta:
      description = "Rancor Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/"
      date = "2018-06-26"
      hash1 = "1dc5966572e94afc2fbcf8e93e3382eef4e4d7b5bc02f24069c403a28fa6a458"
      id = "83dd9567-199e-511c-8c9a-96422bd793e7"
   strings:
      $x1 = ",0,0 >%SystemRoot%\\system32\\spool\\drivers\\color\\fb.vbs\",0,0" fullword ascii
      $x2 = "CreateObject(\"Wscript.Shell\").Run \"explorer.exe \"\"http" ascii
      $x3 = "CreateObject(\"Wscript.Shell\").Run \"schtasks /create" ascii
   condition:
      uint16(0) == 0x533c and filesize < 1KB and 1 of them
}

rule APT_RANCOR_PLAINTEE_Variant {
   meta:
      description = "Detects PLAINTEE malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/"
      date = "2018-06-26"
      hash1 = "6aad1408a72e7adc88c2e60631a6eee3d77f18a70e4eee868623588612efdd31"
      hash2 = "bcd37f1d625772c162350e5383903fe8dbed341ebf0dc38035be5078624c039e"
      id = "f5b68079-0517-504d-a45f-f6ced532db82"
   strings:
      $s1 = "payload.dat" fullword ascii
      $s3 = "temp_microsoft_test.txt" fullword ascii
      $s4 = "reg add %s /v %s /t REG_SZ /d \"%s\"" fullword ascii
      $s6 = "%s %s,helloworld2" fullword ascii
      $s9 = "%s \\\"%s\\\",helloworld" fullword ascii
      $s16 = "recv plugin type %s size:%d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}

rule APT_RANCOR_PLAINTEE_Malware_Exports {
   meta:
      description = "Detects PLAINTEE malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/"
      date = "2018-06-26"
      hash1 = "c35609822e6239934606a99cb3dbc925f4768f0b0654d6a2adc35eca473c505d"
      id = "fa1e678d-8357-522b-9167-31321ab7753f"
   condition:
      uint16(0) == 0x5a4d and pe.exports("Add") and pe.exports("Sub") and pe.exports("DllEntryPoint") and pe.number_of_exports == 3
}

rule APT_RANCOR_DDKONG_Malware_Exports {
   meta:
      description = "Detects DDKONG malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/"
      date = "2018-06-26"
      hash1 = "c35609822e6239934606a99cb3dbc925f4768f0b0654d6a2adc35eca473c505d"
      id = "c94d4ea2-7c16-5003-98ea-253f8a2d01d1"
   condition:
      uint16(0) == 0x5a4d and pe.exports("ServiceMain") and pe.exports("Rundll32Call") and pe.exports("DllEntryPoint") and pe.number_of_exports == 3
}
