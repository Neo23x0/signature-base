/* Disabled due to Benjamin Delphys sig overlap
rule LSASS_memory_dump_file {
   meta:
      description = "Detects a LSASS memory dump file"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://t.co/OLIj1yVJ4m"
      date = "2018-03-06"
      score = 65
   strings:
      $x1 = "Administrator(current):500:" ascii
   condition:
      uint32be(0) == 0x41646d69 and filesize < 3000 and $x1 at 0
}
