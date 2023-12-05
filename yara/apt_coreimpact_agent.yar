/*
	Core Impact Agent known from RocketKitten and WoolenGoldfish APT
*/


rule CoreImpact_sysdll_exe {
   meta:
      description = "Detects a malware sysdll.exe from the Rocket Kitten APT"
      author = "Florian Roth (Nextron Systems)"
      score = 70
      date = "27.12.2014"
      modified = "2023-01-06"
      hash = "f89a4d4ae5cca6d69a5256c96111e707"
      id = "bac55c00-5d14-59ca-8597-f52b4577be0c"
   strings:
      $s0 = "d:\\nightly\\sandbox_avg10_vc9_SP1_2011\\source\\avg10\\avg9_all_vs90\\bin\\Rele" ascii

      $s1 = "Mozilla/5.0" fullword ascii
      $s3 = "index.php?c=%s&r=%lx" fullword ascii
      $s4 = "index.php?c=%s&r=%x" fullword ascii
      $s5 = "127.0.0.1" fullword ascii
      $s6 = "/info.dat" ascii
      $s7 = "needroot" fullword ascii
      $s8 = "./plugins/" ascii
   condition:
      $s0 or 6 of them
}
