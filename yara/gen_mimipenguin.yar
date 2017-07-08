/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-01
   Identifier: Mimipenguin
*/

rule Mimipenguin_SH {
   meta:
      description = "Detects Mimipenguin Password Extractor - Linux"
      author = "Florian Roth"
      reference = "https://github.com/huntergregal/mimipenguin"
      date = "2017-04-01"
   strings:
      $s1 = "$(echo $thishash | cut -d'$' -f 3)" ascii
      $s2 = "ps -eo pid,command | sed -rn '/gnome\\-keyring\\-daemon/p' | awk" ascii
      $s3 = "MimiPenguin Results:" ascii
   condition:
      1 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-08
   Identifier: Mimipenguin
   Reference: https://github.com/huntergregal/mimipenguin
*/

/* Rule Set ----------------------------------------------------------------- */

rule mimipenguin_1 {
   meta:
      description = "Detects Mimipenguin hack tool"
      author = "Florian Roth"
      reference = "https://github.com/huntergregal/mimipenguin"
      date = "2017-07-08"
      hash1 = "9e8d13fe27c93c7571075abf84a839fd1d31d8f2e3e48b3f4c6c13f7afcf8cbd"
   strings:
      $x1 = "self._strings_dump += strings(dump_process(target_pid))" fullword ascii
      $x2 = "def _dump_target_processes(self):" fullword ascii
      $x3 = "self._target_processes = ['sshd:']" fullword ascii
      $x4 = "GnomeKeyringPasswordFinder()" ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 20KB and 1 of them )
}

rule mimipenguin_2 {
   meta:
      description = "Detects Mimipenguin hack tool"
      author = "Florian Roth"
      reference = "https://github.com/huntergregal/mimipenguin"
      date = "2017-07-08"
      hash1 = "453bffa90d99a820e4235de95ec3f7cc750539e4023f98ffc8858f9b3c15d89a"
   strings:
      $x1 = "DUMP=$(strings \"/tmp/dump.${pid}\" | grep -E" fullword ascii
      $x2 = "strings /tmp/apache* | grep -E '^Authorization: Basic.+=$'" fullword ascii
      $x3 = "grep -E '^_pammodutil_getpwnam_root_1$' -B 5 -A" fullword ascii
      $x4 = "strings \"/tmp/dump.${pid}\" | grep -E -m 1 '^\\$.\\$.+\\$')\"" fullword ascii
      $x5 = "if [[ -n $(ps -eo pid,command | grep -v 'grep' | grep gnome-keyring) ]]; then" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 20KB and 1 of them )
}
