
rule MAL_WIPER_CaddyWiper_Mar22_1 {
   meta:
      description = "Detects CaddyWiper malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/ESETresearch/status/1503436420886712321?s=20&t=xh8JK6fEmRIrnqO7Ih_PNg"
      date = "2022-03-15"
      score = 85
      hash1 = "1e87e9b5ee7597bdce796490f3ee09211df48ba1d11f6e2f5b255f05cc0ba176"
      hash2 = "a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea"
      hash3 = "ea6a416b320f32261da8dafcf2faf088924f99a3a84f7b43b964637ea87aef72"
      hash4 = "f1e8844dbfc812d39f369e7670545a29efef6764d673038b1c3edd11561d6902"
      id = "83495a0d-a295-5ec7-9761-ce79918e1034"
   strings:
      $op1 = { ff 55 94 8b 45 fc 50 ff 55 f8 8a 4d ba 88 4d ba 8a 55 ba 80 ea 01 }
      $op2 = { 89 45 f4 83 7d f4 00 74 04 eb 47 eb 45 6a 00 8d 95 1c ff ff ff 52 }
      $op3 = { 6a 20 6a 02 8d 4d b0 51 ff 95 68 ff ff ff 85 c0 75 0a e9 4e 02 00 00 }
      $op4 = { e9 67 01 00 00 83 7d f4 05 74 0a e9 5c 01 00 00 e9 57 01 00 00 8d 45 98 50 6a 20 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 50KB and 3 of them or all of them
}
