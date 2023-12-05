
/*
   Yara Rule Set
   Author: Ian.Ahl@fireeye.com @TekDefense, modified by Florian Roth
   Date: 2017-06-05
   Identifier: APT19
   Reference: https://www.fireeye.com/blog/threat-research/2017/06/phished-at-the-request-of-counsel.html
*/

rule Beacon_K5om {
   meta:
      description = "Detects Meterpreter Beacon - file K5om.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2017/06/phished-at-the-request-of-counsel.html"
      date = "2017-06-07"
      hash1 = "e3494fd2cc7e9e02cff76841630892e4baed34a3e1ef2b9ae4e2608f9a4d7be9"
      id = "9354d20a-d798-55bf-a735-820f21d4a861"
   strings:
      $x1 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
      $x2 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $x3 = "%d is an x86 process (can't inject x64 content)" fullword ascii

      $s1 = "Could not open process token: %d (%u)" fullword ascii
      $s2 = "0fd00b.dll" fullword ascii
      $s3 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
      $s4 = "Could not connect to pipe (%s): %d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) or 3 of them ) )
}

/* Rule Set ----------------------------------------------------------------- */

rule FE_LEGALSTRIKE_MACRO {
   meta:
      version=".1"
      filetype="MACRO"
      author="Ian.Ahl@fireeye.com @TekDefense - modified by Florian Roth"
      date="2017-06-02"
      description="This rule is designed to identify macros with the specific encoding used in the sample 30f149479c02b741e897cdb9ecd22da7."
      id = "eb15e5aa-16e5-5c07-a293-ad15c0c09d8e"
   strings:
      // OBSFUCATION
      $ob1 = "ChrW(114) & ChrW(101) & ChrW(103) & ChrW(115) & ChrW(118) & ChrW(114) & ChrW(51) & ChrW(50) & ChrW(46) & ChrW(101)" ascii wide
      // wscript
      $wsobj1 = "Set Obj = CreateObject(\"WScript.Shell\")" ascii wide
      $wsobj2 = "Obj.Run " ascii wide
   condition:
      all of them
}

rule FE_LEGALSTRIKE_RTF {
   meta:
      version=".1"
      filetype="MACRO"
      author="joshua.kim@FireEye. - modified by Florian Roth"
      date="2017-06-02"
      description="Rtf Phishing Campaign leveraging the CVE 2017-0199 exploit, to point to the domain 2bunnyDOTcom"
      id = "b62ceffa-445f-517e-b86b-56e47876c6c0"
   strings:
      $lnkinfo = "4c0069006e006b0049006e0066006f"
      $encoded1 = "4f4c45324c696e6b"
      $encoded2 = "52006f006f007400200045006e007400720079"
      $encoded3 = "4f0062006a0049006e0066006f"
      $encoded4 = "4f006c0065"
      $datastore = "\\*\\datastore"
   condition:
      uint32be(0) == 0x7B5C7274 and all of them
}
