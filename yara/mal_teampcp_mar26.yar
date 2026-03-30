rule MAL_LiteLLM_SupplyChain_Mar26 {
   meta:
      description = "Detects malicious indicators used in LiteLLM supply chain attack"
      author = "Marius Benthin"
      date = "2026-03-28"
      reference = "https://github.com/BerriAI/litellm/issues/24512"
      hash = "71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
      score = 80
   strings:
      $s1 = "exec(base64.b64decode("
      $s2 = "litellm." base64
      $s3 = "subprocess.DEVNULL"
   condition:
      filesize < 500KB
      and all of them
}

rule MAL_Telnyx_SupplyChain_Mar26 {
   meta:
      description = "Detects malicious indicators used in Telnyx supply chain attack"
      author = "Marius Benthin"
      date = "2026-03-28"
      reference = "https://www.aikido.dev/blog/telnyx-pypi-compromised-teampcp-canisterworm"
      hash = "ab4c4aebb52027bf3d2f6b2dcef593a1a2cff415774ea4711f7d6e0aa1451d4e"
      score = 80
   strings:
      $s1 = "bXNidWlsZC5leGU="  // msbuild.exe
      $s2 = "TW96aWxsY"  // Mozilla/
      $s3 = ".getnframes("  // number of WAV audio frames
      $s4 = "exec(base64.b64decode("
   condition:
      filesize < 500KB
      and 3 of them
}
