
/*
   Yara Rule Set
   Author: Cylance
   Date: 2017-02-28
   Identifier: Jap Threat
*/

/* Rule Set ----------------------------------------------------------------- */

rule Ham_backdoor {
   meta:
      description = "Detects Ham Trojan"
      author = "Cylance"
      reference = "https://www.cylance.com/en_us/blog/the-deception-project-a-new-japanese-centric-threat.html"
      date = "2017-02-28"
   strings:
   	$a = {8D 14 3E 8B 7D FC 8A 0C 11 32 0C 38 40 8B 7D 10 88 0A 8B 4D 08 3B C3}
   	$b = {8D 0C 1F 8B 5D F8 8A 04 08 32 04 1E 46 8B 5D 10 88 01 8B 45 08 3B F2}
   	$c = "uuuuuuuummmmjjmjjjejeeeeeee9,"
   condition:
   	$a or $b or $c
}

rule Tofu_Backdoor {
   meta:
      description = "Detects Tofu Trojan"
      author = "Cylance"
      reference = "https://www.cylance.com/en_us/blog/the-deception-project-a-new-japanese-centric-threat.html"
      date = "2017-02-28"
   strings:
   	$a = "Cookies: Sym1.0"
   	$b = "\\\\.\\pipe\\1[12345678]"
   	$c = {66 0F FC C1 0F 11 40 D0 0F 10 40 D0 66 0F EF C2 0F 11 40 D0 0F 10 40 E0}
   condition:
   	$a or $b or $c
}
