
rule MAL_APT_Operation_ShadowHammer_MalSetup {
   meta:
      description = "Detects a malicious file used by BARIUM group in Operation ShadowHammer"
      date = "2019-03-25"
      author = "Florian Roth"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      score = 80
      hash1 = "ac0711afee5a157d084251f3443a40965fc63c57955e3a241df866cfc7315223"
      hash2 = "9acd43af36f2d38077258cb2ace42d6737b43be499367e90037f4605318325f8"
      hash3 = "bca9583263f92c55ba191140668d8299ef6b760a1e940bddb0a7580ce68fef82"
      hash4 = "c299b6dd210ab5779f3abd9d10544f9cae31cd5c6afc92c0fc16c8f43def7596"
      hash5 = "6aedfef62e7a8ab7b8ab3ff57708a55afa1a2a6765f86d581bc99c738a68fc74"
      hash6 = "cfbec77180bd67cceb2e17e64f8a8beec5e8875f47c41936b67a60093e07fcfd"
      reference = "https://securelist.com/operation-shadowhammer/89992/"
   strings:
      $x1 = "\\AsusShellCode\\Release" ascii
      $x2 = "\\AsusShellCode\\Debug"
   condition:
      uint16(0) == 0x5a4d and 1 of them
}
