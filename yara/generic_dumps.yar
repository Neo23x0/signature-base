/* Disabled due to Benjamin Delphys sig overlap
rule LSASS_memory_dump_file {
   meta:
      description = "Detects a LSASS memory dump file"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      date = "2015/03/31"
      memory = 0
      score = 50
   strings:
      $s1 = "lsass.exe" ascii fullword
      $s2 = "wdigest.DLL" wide nocase
   condition:
        uint32(0) == 0x504D444D and all of them
} */

rule NTLM_Dump_Output {
   meta:
      description = "NTML Hash Dump output file - John/LC format"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      date = "2015-10-01"
      score = 75
   strings:
      $s0 = "500:AAD3B435B51404EEAAD3B435B51404EE:" ascii
      $s1 = "500:aad3b435b51404eeaad3b435b51404ee:" ascii
   condition:
      1 of them
}

rule Gsecdump_password_dump_file {
   meta:
      description = "Detects a gsecdump output file"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://t.co/OLIj1yVJ4m"
      date = "2018-03-06"
      score = 65
   strings:
      $x1 = "Administrator(current):500:" ascii
   condition:
      uint32be(0) == 0x41646d69 and filesize < 3000 and $x1 at 0
}

rule SUSP_ZIP_NtdsDIT : T1003_003 {
   meta:
      description = "Detects ntds.dit files in ZIP archives that could be a left over of administrative activity or traces of data exfiltration"
      author = "Florian Roth"
      score = 50
      reference = "https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/"
      date = "2020-08-10"
   strings:
      $s1 = "ntds.dit" ascii 
   condition:
      uint16(0) == 0x4b50 and
      $s1 in (0..256)
}
