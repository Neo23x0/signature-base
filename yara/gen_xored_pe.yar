rule SUSP_Two_Byte_XOR_PE_And_MZ {
   meta:
      author = "Wesley Shields <wxs@atarininja.org>"
      description = "Look for 2 byte xor of a PE starting at offset 0"
      reference = "https://gist.github.com/wxsBSD/bf7b88b27e9f879016b5ce2c778d3e83"
      score = 60
      date = "2021-10-11"
      id = "ddb87194-bafb-597d-9184-fe4fe3c5ce8d"
   condition:
      uint16(0) != 0x5a4d and
      uint32((uint16(0x3c) ^ (uint16(0) ^ 0x5a4d)) | ((uint16(0x3e) ^ (uint16(0) ^ 0x5a4d)) << 16)) ^ ((uint16(0) ^ 0x5a4d) | ((uint16(0) ^ 0x5a4d) << 16)) == 0x00004550
}

rule SUSP_Four_Byte_XOR_PE_And_MZ {
   meta:
      author = "Wesley Shields <wxs@atarininja.org>"
      description = "Look for 4 byte xor of a PE starting at offset 0"
      reference = "https://gist.github.com/wxsBSD/bf7b88b27e9f879016b5ce2c778d3e83"
      score = 60
      date = "2021-10-11"
      id = "d7b4b462-dfde-5d1f-8039-63522436c15f"
   condition:
      uint16(0) != 0x5a4d and
      uint32(0x28) != 0x00000000 and
      uint32(0x28) == uint32(0x2c) and
      uint32(uint32(0x3c) ^ uint32(0x28)) ^ uint32(0x28) == 0x00004550
}
