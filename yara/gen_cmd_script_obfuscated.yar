
rule MAL_CMD_Script_Obfuscated_Feb19_1 {
   meta:
      description = "Detects obfuscated batch script using env variable sub-strings"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/DbgShell/status/1101076457189793793"
      date = "2019-03-01"
      hash1 = "deed88c554c8f9bef4078e9f0c85323c645a52052671b94de039b438a8cff382"
      id = "8cc99ff5-968c-5b12-9aac-72279c1b8a6b"
   strings:
      $h1 = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 }
      $s1 = { 2C 31 25 0D 0A 65 63 68 6F 20 25 25 }
   condition:
      uint16(0) == 0x6540 and filesize < 200KB and
      $h1 at 0 and
      uint16(filesize-3) == 0x0d25 and uint8(filesize-1) == 0x0a and
      $s1 in (filesize-200..filesize)
}
