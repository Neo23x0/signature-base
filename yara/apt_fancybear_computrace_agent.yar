rule PUP_ComputraceAgent {
   meta:
      description = "Absolute Computrace Agent Executable"
      author = "ASERT - Arbor Networks (slightly modified by Florian Roth)"
      date = "2018-05-01"
      reference = "https://asert.arbornetworks.com/lojack-becomes-a-double-agent/"
      id = "676f8f1e-a3b4-5d05-b13b-bd6cb0aabbbd"
   strings:
      $a = { D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04 }
      $b1 = { 72 70 63 6E 65 74 70 2E 65 78 65 00 72 70 63 6E 65 74 70 00 }
      $b2 = { 54 61 67 49 64 00 }
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and ($a or ($b1 and $b2))
}
