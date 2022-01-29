import "pe"

rule APT_RU_APT27_HyperBro_Vftrace_Loader_Jan22_1 {
    meta:
        description = "Yara rule to detect first Hyperbro Loader Stage, often called vftrace.dll. Detects decoding function."
        author = "Bundesamt fuer Verfassungsschutz (modified by Florian Roth)"
        date = "2022-01-14"
        sharing = "TLP:WHITE"
        reference = "https://www.verfassungsschutz.de/SharedDocs/publikationen/DE/cyberabwehr/2022-01-bfv-cyber-brief.pdf"
        hash1 = "333B52C2CFAC56B86EE9D54AEF4F0FF4144528917BC1AA1FE1613EFC2318339A"
    strings:
        $decoder_routine = { 8A ?? 41 10 00 00 8B ?? 28 ?? ?? 4? 3B ?? 72 ?? }
    condition:
        uint16(0) == 0x5a4d and
        filesize < 5MB and
        $decoder_routine and 
        pe.exports("D_C_Support_SetD_File")
}

rule APT_CN_APT27_Compromised_Certficate_Jan22_1 {
   meta:
      description = "Detects compromised certifcates used by APT27 malware"
      author = "Florian Roth"
      date = "2022-01-29"
      score = 80
      reference = "https://www.verfassungsschutz.de/SharedDocs/publikationen/DE/cyberabwehr/2022-01-bfv-cyber-brief.pdf"
   condition:
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert SHA2 Assured ID Code Signing CA" and
         pe.signatures[i].serial == "08:68:70:51:50:f1:cf:c1:fc:c3:fc:91:a4:49:49:a6"
   )
}
