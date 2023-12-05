/*
   Yara Rule Set
   Author: Florian Roth with the help of binar.ly
   Date: 2017-05-02
   Identifier: Enigma Protector
*/

rule EnigmaPacker_Rare {
   meta:
      description = "Detects an ENIGMA packed executable"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-04-27"
      score = 60
      hash1 = "77be6e80a4cfecaf50d94ee35ddc786ba1374f9fe50546f1a3382883cb14cec9"
      id = "748bc74c-e83f-5740-8ff7-f1371fc22802"
   strings:
      $s1 = "P.rel$oc$" fullword ascii
      $s2 = "ENIGMA" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and all of them )
}

rule Enigma_Protected_Malware_May17_RhxFiles {
   meta:
      description = "Auto-generated rule - file RhxFiles.dll"
      author = "Florian Roth (Nextron Systems) with the help of binar.ly"
      reference = "Internal Research"
      date = "2017-05-02"
      hash1 = "2187d6bd1794bf7b6199962d8a8677f19e4382a124c30933d01aba93cc1f0f15"
      id = "d701d591-4283-5645-8768-a5ab7df0f37a"
   strings:
      $op1 = { bd 9c 74 f6 7a 3a f7 94 c5 7d 7c 7c 7c 7e ae 73 }
      $op2 = { 82 62 6b 6b 6b 68 a5 ea aa 69 6b 6b 6b 3a 3b 94 }
      $op3 = { 7c 7c c5 7d 7c 7c 7c 7e ae 73 f9 79 7c 7c 7c f6 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and all of them )
}

rule Enigma_Protected_Malware {
   meta:
      description = "Detects samples packed by Enigma Protector"
      author = "Florian Roth (Nextron Systems) with the help of binar.ly"
      reference = "https://goo.gl/OEVQ9w"
      date = "2017-02-03"
      hash1 = "d4616f9706403a0d5a2f9a8726230a4693e4c95c58df5c753ccc684f1d3542e2"
      id = "d701d591-4283-5645-8768-a5ab7df0f37a"
   strings:
      $s1 = { 5d 5d 5d aa bf 5e 95 d6 dc 51 5d 5d 5d 5e 98 0d }
      $s2 = { 52 d9 47 5d 5d 5d dd a6 b4 52 d9 4c 5d 5d 5d 3b }
      $s3 = { 9f 59 14 52 d8 a9 a2 a2 a2 00 9f 51 5d d6 d1 79 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}
