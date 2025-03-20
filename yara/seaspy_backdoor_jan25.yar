rule SUSP_LNX_ByteEncoder_Jan25 {
   meta:
      description = "Detects Linux binaries that encode bytes by splitting them into upper and lower nibbles and mapping them to custom lookup tables, seen being used by SEASPY and Bluez backdoors"
      author = "MalGamy (Nextron System)"
      date = "2025-01-23"
      reference = "https://www.securityweek.com/newly-discovered-turla-malware-targets-linux-systems/"
      hash = "3e0312ce8d0c1e5c192dbb93cac4770a1205c56dc9d02a0510c7e10a15251de5"
      hash = "301d58a6a1819466e77209dbf8ca635cbee3b45516e5ee228fea50ae4a27b7d5"
      hash = "957c0c135b50d1c209840ec7ead60912a5ccefd2873bf5722cb85354cea4eb37"
      hash = "5e3c128749f7ae4616a4620e0b53c0e5381724a790bba8314acb502ce7334df2"
      hash = "b0b83e1c69aa8df6da4383230bef1ef46e09f3bf26cec877eac53a9d48dc53ca"
      hash = "d21b40645e33638bd36b63582c2c6ad5e8230c731236a54e8e5f4139bad31fdf"
      score = 75
      id = "4866348a-2129-5f6a-9498-8ab1acfa74b4"
   strings:
      $op1 = {8B 45 FC 48 63 D0 48 8B 45 A8 48 01 C2 8B 45 BC C1 F8 04 83 E0 0F 48 98 0F B6 44 05 E0 88 02} // Encode upper nibbl
      $op2 = {8B 45 FC 48 98 48 8D 50 01 48 8B 45 A8 48 01 C2 8B 45 BC 83 E0 0F 48 98 0F B6 44 05 C0 88 02} // Encode lower nibble
   condition:
      uint32be(0) == 0x7f454c46
      and filesize < 4MB
      and all of them
}

rule SUSP_LNX_StackString_Technique_Jan25 {
   meta:
      description = "Detects suspicious Linux binaries using stack-based string manipulation techniques, which are often used to generate PTY (pseudo-terminal) device names for stealth or persistence, seen being used by SEASPY and Bluez backdoors"
      author = "MalGamy (Nextron System)"
      date = "2025-01-23"
      reference = "https://www.securityweek.com/newly-discovered-turla-malware-targets-linux-systems/"
      hash = "0e65a80c6331a0e8d7df05ac217a8a7fe03b88f1d304f2ff0a26b92ed89153f3"
      hash = "3e0312ce8d0c1e5c192dbb93cac4770a1205c56dc9d02a0510c7e10a15251de5"
      hash = "301d58a6a1819466e77209dbf8ca635cbee3b45516e5ee228fea50ae4a27b7d5"
      hash = "957c0c135b50d1c209840ec7ead60912a5ccefd2873bf5722cb85354cea4eb37"
      hash = "5e3c128749f7ae4616a4620e0b53c0e5381724a790bba8314acb502ce7334df2"
      hash = "654b7c5b667e4d70ebb5fb1807dcd1ee5b453f45424eb59a287d86ad8d0598a1"
      hash = "ac6a8ec0b92935b7faab05ca21a42ed9eecdc9243fcf1449cc8f050de38e4c4f"
      score = 75
      id = "6c81d8c1-0cfa-54d9-89d3-2b025cc22f13"
   strings:
      $op1 = {C7 45 E0 70 71 72 73 C7 45 E4 74 75 76 77 C7 45 E8 78 79 7A 61 C7 45 EC 62 63 64 65 C6 45 F0 00 C7 45 C0 30 31 32 33 C7 45 C4 34 35 36 37 C7 45 C8 38 39 61 62 C7 45 CC 63 64 65 66} // tack-based string manipulation technique
   condition:
      uint32be(0) == 0x7f454c46
      and filesize < 4MB
      and $op1
}
