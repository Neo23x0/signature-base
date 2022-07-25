
rule HKTL_CobaltStrike_Beacon_Strings {
   meta:
      description = "Detects strings used in Cobalt Strike Beacon DLLs"
      author = "Elastic"
      date = "2021-03-16"
      reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
      score = 80
   strings:
      $a = "%02d/%02d/%02d %02d:%02d:%02d"
      $b = "Started service %s on %s"
      $c = "%s as %s\\%s: %d"
   condition:
      2 of them
}

/* requires YARA 3.11 */
rule HKTL_CobaltStrike_Beacon_XOR_Strings {
   meta:
      author = "Elastic"
      description = "Identifies XOR'd strings used in Cobalt Strike Beacon DLL"
      reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
      date = "2021-03-16"
      modified = "2022-03-28"
      /* Used for beacon config decoding in THOR */
      xor_s1 = "%02d/%02d/%02d %02d:%02d:%02d"
      xor_s2 = "Started service %s on %s"
      xor_s3 = "%s as %s\\%s: %d"
   strings:
      $s1 = "%02d/%02d/%02d %02d:%02d:%02d" xor(0x01-0xff)
      $s2 = "Started service %s on %s" xor(0x01-0xff)
      $s3 = "%s as %s\\%s: %d" xor(0x01-0xff)

      $fp1 = "MalwareRemovalTool"
   condition:
      2 of ($s*) and not 1 of ($fp*)
}

rule HKTL_CobaltStrike_Beacon_Decrypt_v4_2 {
   meta:
      description = "Detects deobfuscation routine used in Cobalt Strike Beacon DLL version 4.2."
      author = "Elastic"
      date = "2021-03-16"
      reference = "https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures"
      score = 80
   strings:
      $a_x64 = {4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03}
      $a_x86 = {8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2}
   condition:
      1 of them
}

rule HKTL_CobaltStrike_SleepMask_Jul22 {
   meta:
      description = "Detects static bytes in Cobalt Strike 4.5 sleep mask function that are not obfuscated"
      author = "CodeX"
      date = "2022-07-04"
      reference = "https://codex-7.gitbook.io/codexs-terminal-window/blue-team/detecting-cobalt-strike/sleep-mask-kit-iocs"
      score = 80
   strings:
      $sleep_mask = { 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 45 33 DB 45 33 D2 33 FF 33 F6 48 8B E9 BB 03 00 00 00 85 D2 0F 84 81 00 00 00 0F B6 45 }
   condition:
      $sleep_mask
}


