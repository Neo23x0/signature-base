
rule SUSP_Qakbot_Uninstaller_File {
   meta:
      description = "Detects Qakbot Uninstaller files used by the FBI and Dutch National Police in a disruption operation against the Qakbot in August 2023"
      author = "Florian Roth"
      reference = "https://www.justice.gov/usao-cdca/divisions/national-security-division/qakbot-resources"
      date = "2023-08-30"
      score = 60
   strings:
      $xc1 = { E8 00 00 00 00 58 55 89 E5 89 C2 68 03 00 00 00
               68 00 2C 00 00 05 20 0A 00 00 50 E8 05 00 00 00
               83 C4 04 C9 C3 81 EC 08 01 00 00 53 55 56 57 6A
               6B 58 6A 65 5B 6A 72 66 89 84 24 D4 00 00 00 33 }
   condition:
      $xc1
}
