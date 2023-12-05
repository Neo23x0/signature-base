/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-03
   Identifier: PowerShell Hacktools
   Reference: https://github.com/p3nt4/PowerShdll
*/

rule PowerShdll {
   meta:
      description = "Detects hack tool PowerShdll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/p3nt4/PowerShdll"
      date = "2017-08-03"
      hash1 = "4d33bc7cfa79d7eefc5f7a99f1b052afdb84895a411d7c30045498fd4303898a"
      hash2 = "f999db9cc3a0719c19f35f0e760f4ce3377b31b756d8cd91bb8270acecd7be7d"
      id = "cc0e01ca-77f0-5665-8b1e-48c8e947d0d3"
   strings:
      $x1 = "rundll32 PowerShdll,main -f <path>" fullword wide
      $x2 = "\\PowerShdll.dll" ascii
      $x3 = "rundll32 PowerShdll,main <script>" fullword wide
   condition:
      1 of them
}
