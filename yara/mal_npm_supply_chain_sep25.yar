rule MAL_JS_NPM_SupplyChain_Attack_Sep25 {
   meta:
      description = "Detects obfuscated JavaScript in NPM packages used in supply chain crypto stealer attacks in September 2025"
      author = "Florian Roth"
      reference = "https://www.linkedin.com/feed/update/urn:li:activity:7370889385992437760/"
      date = "2025-09-09"
      score = 85
      hash1 = "16f6c756bc8ce5ef5d9aa1ded0f811ec0c9cee3d8f85cc151b8ca1df7b8a4337"
   strings:
      $x1 = "const _0x112fa8=_0x180f;(function(_0x13c8b9" ascii

      $fp1 = "<html"
      $fp2 = "<xml "
   condition:
      filesize < 200KB
      and 1 of ($x*)
      and not 1 of ($fp*)
}
