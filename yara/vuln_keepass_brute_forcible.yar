
rule VULN_KeePass_DB_Brute_Forcible {
   meta:
      description = "Detects KeePass .kdbx password stores, which could be brute forced to steal the credentials. With AES-KDF and less than 65536 iterations the cracking speed with a single GPU is 20k/s, for the old default of 6.000 iterations it's 200k/s. Best remediation is to change the key derivative function to Argon2d and delete all older versions of the .kdbx"
      author = "Arnim Rupp (https://github.com/ruppde)"
      date = "2023-07-20"
      score = 60
      reference = "https://keepass.info/help/base/security.html#secdictprotect"
      id = "b1a86e03-b3d1-5abc-9287-a4846451caff"
   strings:
      $keepass_magic = { 03 D9 A2 9A 67 FB 4B B5 }
      // bytes 3-5 (after 06 08) are the number of iterations. if byte 3 is 00 the iterations are below 65536
      $below_65536_rounds = { 06 08 00 ?? ?? 00 00 00 00 00 00 07 10 00 }
   condition:
      $keepass_magic at 0 and
      $below_65536_rounds at 108
}
