
rule MAL_LNX_Showboat_Jun26_1 {
   meta:
      description = "Detects Showboat, a modular Linux (ELF x86-64) post-exploitation backdoor used by China-nexus actors against telecom providers - provides remote shell, SOCKS5 proxy, file transfer and process hiding"
      author = "Aryu-RU"
      reference = "https://www.lumen.com/blog/en-us/introducing-showboat-a-new-malware-family-taunts-defenses-and-targets-international-telecom-firms"
      date = "2026-06-18"
      score = 80
      id = "496c5f75-c48d-4b75-b0a6-f77b94f30fdd"
   strings:
      $x1 = "look me, AV!" ascii            /* hardcoded XOR key applied byte-wise to decrypt the agent config */

      $a1 = "_SKS_" ascii                   /* literal appended to the C2 URL by the SOCKS5 proxy function */
      $a2 = "_MAP_" ascii                   /* literal appended to the C2 URL by the portmap/scan function */

      $s1 = "SLOW_MODE_MIN_SLEEP" ascii     /* agent configuration field name */
      $s2 = "SLOW_MODE_MAX_SLEEP" ascii     /* agent configuration field name */
   condition:
      uint32(0) == 0x464c457f
      and filesize < 10MB
      and (
         all of ($a*)                       /* both C2-URL markers - the most reliable in-binary anchors */
         or ( $x1 and 1 of ($a*, $s*) )     /* or the XOR-key taunt plus one corroborating string */
      )
}
