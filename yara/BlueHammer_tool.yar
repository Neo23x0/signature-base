rule HKTL_BlueHammer_Apr26 {
   meta:
      author = "AzizFarghly (Nextron-Systems)"
      description = "Detects Nightmare-Eclipse/BlueHammer (FunnyApp), a Windows local privilege escalation PoC that abuses a Defender signature-update RPC and a junction/symlink race to leak the SAM hive and derive NTLM hashes - giving an unprivileged user full SYSTEM-level credential access."
      date = "2026-04-07"
      reference = "https://github.com/Nightmare-Eclipse/BlueHammer"
      hash = "6514f56223999eb86a19ea9f2abbfb0f407934a1a0694ffb94a8ea37113073f4"
      hash = "93008c42764b74b759678fd376abd90696f74af408600727b6649286d8424270"
      hash = "b25e903988e530df00658ff3ad6d180e43d6660b705ad6d0def4a29ee1167e52"
      hash = "82eb727e2a2b3334a70fa2d357ba4f44dc989a650a6a18222dd5d1bb1444b496"
      hash = "b33f3f31c83fc655952fab73d72b673b92ed4f205daee56444903201316cfc4a"
      hash = "c6baa5ec9ea2c2802a90acad5a53453d176a02e04a31ac8e9b7b34b5e3329b84"
      hash = "552dba31a446e96416738d84d4366503c397ba508a732719531c89a41abf3704"
      hash = "c9bec499db6a0a2165bcd2a211c8887e5fadf954eb9a2e5d3c6ca833e4a5ef64"
      score = 90
   strings:
      $x1 = "Junction created %ws => %ws"
      $x2 = "connect to windows defender RPC port !!!"

      $s1 = "\\System32\\Config\\SAM" wide
      $s2 = "IMpService77BDAF73-B396-481F-9042-AD358843EC24" wide
      $s3 = "ServerMpUpdateEngineSignature"

      $op1 = { 8D 47 02 66 89 43 0C 66 C7 43 0E 02 00 48 8B C7 48 D1 E8 66 44 89 7C 43 12 }
   condition:
      uint16(0) == 0x5A4D
      and filesize < 7MB
      and (
         1 of ($x*)
         or all of ($s*)
         or $op1
      )
      or 3 of them
}
