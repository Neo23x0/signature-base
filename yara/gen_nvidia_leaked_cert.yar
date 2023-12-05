
import "pe"

rule SUSP_NVIDIA_LAPSUS_Leak_Compromised_Cert_Mar22_1 {
   meta:
      description = "Detects a binary signed with the leaked NVIDIA certifcate and compiled after March 1st 2022"
      author = "Florian Roth (Nextron Systems)"
      date = "2022-03-03"
      modified = "2022-03-04"
      score = 70
      reference = "https://twitter.com/cyb3rops/status/1499514240008437762"
      id = "8bc7460f-a1c4-5157-8c2d-34d3a6c9c7e9"
   condition:
      uint16(0) == 0x5a4d and filesize < 100MB and
      pe.timestamp > 1646092800 and  // comment out to find all files signed with that certificate
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "VeriSign Class 3 Code Signing 2010 CA" and (
            pe.signatures[i].serial == "43:bb:43:7d:60:98:66:28:6d:d8:39:e1:d0:03:09:f5" or
            pe.signatures[i].serial == "14:78:1b:c8:62:e8:dc:50:3a:55:93:46:f5:dc:c5:18"
         )
   )
}
