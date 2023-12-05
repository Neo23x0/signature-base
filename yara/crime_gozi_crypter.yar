
rule MAL_GoziCrypter_Dec20_1 {
    meta:
      description = "Detects crypter associated with several Gozi samples"
      author = "James Quinn"
      reference = "YaraExchange"
      score = 70
      id = "d4a48612-fa6f-5f03-8d27-5f6b79b2a070"
    strings:
      $s1 = { 89 05 ?? ?? ?? ?? 81 2d ?? ?? ?? ?? 01 00 00 00 81 3D ?? ?? ?? ?? 00 00 00 00 }
    condition:
      uint16(0) == 0x5A4D and any of them and filesize < 1000KB
}
