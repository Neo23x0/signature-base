rule xDedic_SysScan_unpacked {
   meta:
      author = " Kaspersky Lab"
      maltype = "crimeware"
      type ="crimeware"
      description = "Detects SysScan APT tool"
      reference = "https://securelist.com/blog/research/75027/xdedic-the-shady-world-of-hacked-servers-for-sale/"
      filetype = "Win32 EXE"
      date = "2016-03-14"
      version = "1.0"
      hash1 = "fac495be1c71012682ebb27092060b43"
      hash2 = "e8cc69231e209db7968397e8a244d104"
      hash3 = "a53847a51561a7e76fd034043b9aa36d"
      hash4 = "e8691fa5872c528cd8e72b82e7880e98"
      hash5 = "F661b50d45400e7052a2427919e2f777"
   strings:
      $a1 = "/c ping -n 2 127.0.0.1 & del \"SysScan.exe\"" ascii wide
      $a2 = "SysScan DEBUG Mode!!!" ascii wide
      $a3 = "This rechecking? (set 0/1 or press enter key)" ascii wide
      $a4 = "http://37.49.224.144:8189/manual_result" ascii wide

      $b1 = "Checker end work!" ascii wide
      $b2 = "Trying send result..." ascii wide
   condition:
      uint16(0) == 0x5A4D and filesize < 5000000 and ( any of ($a*) or all of ($b*) )
}

rule xdedic_packed_syscan {
   meta:
      author = "Kaspersky Lab - modified by Florian Roth"
      company = "Kaspersky Lab"
   strings:
      $a1 = "SysScan.exe" nocase ascii wide
      $a2 = "1.3.4." wide
   condition:
      uint16(0) == 0x5A4D and filesize > 500KB and filesize < 1500KB and all of them
}
