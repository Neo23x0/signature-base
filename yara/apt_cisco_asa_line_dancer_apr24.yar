
rule Line_Dancer {
   meta:
      author = "NCSC"
      description = "Targets code sections of Line Dancer, a shellcode loader targeting Cisco ASA devices."
      reference = "https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/line/ncsc-tip-line-dancer.pdf"
      date = "2024-04-24"
      score = 75
      id = "3b49a861-8107-577a-bae1-ae28d424cc13"
   strings:
      $ = { 48 8D 5E 20 48 8D 3D BB FF FF FF BA 20 00 00 00 }
      $ = { 4C 89 EE 44 89 F2 48 8D 3D 9A 27 00 00 }
      $ = { 41 FF D7 41 5F 41 5E 41 5D 41 5C 5B 5D 48 C7 C0 01 00 00 00 5F }
   condition:
      all of them
}
