import "pe"

rule MAL_Ryuk_Ransomware {
   meta:
      description = "Detects strings known from Ryuk Ransomware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://research.checkpoint.com/ryuk-ransomware-targeted-campaign-break/"
      date = "2018-12-31"
      hash1 = "965884f19026913b2c57b8cd4a86455a61383de01dabb69c557f45bb848f6c26"
      hash2 = "b8fcd4a3902064907fb19e0da3ca7aed72a7e6d1f94d971d1ee7a4d3af6a800d"
      id = "25d40631-4158-5d3d-913e-a2f1233489e0"
   strings:
      $x1 = "/v \"svchos\" /f" fullword wide
      $x2 = "\\Documents and Settings\\Default User\\finish" wide
      $x3 = "\\users\\Public\\finish" wide
      $x4 = "lsaas.exe" fullword wide
      $x5 = "RyukReadMe.txt" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and (
         pe.imphash() == "4a069c1abe5aca148d5a8fdabc26751e" or
         pe.imphash() == "dc5733c013378fa418d13773f5bfe6f1" or
         1 of them
      )
}
