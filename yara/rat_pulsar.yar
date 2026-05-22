/*
   Yara Rule Set
   Identifier: Pulsar RAT (server.exe variant)
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

rule Pulsar_RAT_Critical_Variant {
   meta:
      description = "Detects Pulsar RAT variant (server.exe) based on unique strings, HVNC capability, and BCrypt encryption"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/PULSAR-RAT/"
      date = "2025-11-30"
      hash1 = "2c4387ce18be279ea735ec4f0092698534921030aaa69949ae880e41a5c73766"
      family = "PulsarRAT"
      id = "bf130ee9-743d-553e-afb1-196820ed1471"
   strings:
      $pulsar = "Pulsar.Common" wide ascii
      $hvnc = "HVNC" wide ascii
      $keylog = "KeyLogger" wide ascii
      $msgpack = "MessagePackSerializer" wide ascii
      $bcrypt = "BCryptEncrypt" wide ascii
      $winre = "Recovery\\OEM\\" wide ascii nocase
      $runonce = "CurrentVersion\\RunOnce" wide ascii
      $remote_desktop = "RemoteDesktop" wide ascii
      $passwords = "Passwords" wide ascii
   condition:
      uint16(0) == 0x5A4D and
      uint32(uint32(0x3C)) == 0x00004550 and
      filesize > 1MB and filesize < 2MB and
      all of ($pulsar, $hvnc, $keylog, $msgpack, $bcrypt, $winre) and
      2 of ($remote_desktop, $passwords)
}
