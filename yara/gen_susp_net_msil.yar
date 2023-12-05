
rule SUSP_NET_Msil_Suspicious_Use_StrReverse {
   meta:
      /* 
         This combination of imports and usage of StrReverse appears often
         in .NET crypters and malware trying to evade static string analysis
      */
      description = "Detects mixed use of Microsoft.CSharp and VisualBasic to use StrReverse"
      author = "dr4k0nia, modified by Florian Roth"
      reference = "https://github.com/dr4k0nia/yara-rules"
      version = "1.1"
      date = "01/31/2023"
      modified = "02/22/2023"
      score = 70
      hash = "02ce0980427dea835fc9d9eed025dd26672bf2c15f0b10486ff8107ce3950701"
      id = "830dec40-4412-59c1-8b4d-a237f14acd30"
   strings:
      $a1 = ", PublicKeyToken="
      $a2 = ".NETFramework,Version="

      $csharp = "Microsoft.CSharp"
      $vbnet = "Microsoft.VisualBasic"
      $strreverse = "StrReverse"
   condition:
      uint16(0) == 0x5a4d
      and filesize < 50MB
      and all of ($a*)
      and $csharp
      and $vbnet
      and $strreverse
}
