
rule HKTL_AdaptixC2_Beacon_Apr26 {
   meta:
      description = "Detects the Windows beacon of the AdaptixC2 post-exploitation framework by its stock Itanium-ABI RTTI type names and default HTTP heartbeat header. Matches an unmodified build regardless of operator."
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://github.com/Adaptix-Framework/AdaptixC2"
      date = "2026-04-30"
      score = 80
      hash1 = "358edb5d7e3e38c2da0a2ef323a281283aa96d47a8649014d114923b06866c12"
      id = "952a09e1-dbbd-5758-ab76-bb9f215d96b5"
   strings:
      $a1 = "9Connector" ascii
      $a2 = "13ConnectorHTTP" ascii
      $a3 = "X-Beacon-Id" ascii

      $s1 = "GetVersions" ascii
      $s2 = "Mingw-w64 runtime failure:" ascii
   condition:
      uint16(0) == 0x5a4d
      and filesize < 300KB
      and all of ($a*)
      and 1 of ($s*)
}
