
rule EXP_DriveCrypt_1 {
   meta:
      description = "Detects DriveCrypt exploit"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-08-21"
      hash1 = "0dd09bc97c768abb84d0fb6d1ae7d789f1f83bfb2ce93ff9ff3c538dc1effa33"
      id = "c192ca53-1de3-5d2d-a216-47e534ff4d01"
   strings:
      $s1 = "x64passldr.exe" fullword ascii
      $s2 = "DCR.sys" fullword ascii
      $s3 = "amd64\\x64pass.sys" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and 2 of them
}

rule EXP_DriveCrypt_x64passldr {
   meta:
      description = "Detects DriveCrypt exploit"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-08-21"
      modified = "2023-01-06"
      hash1 = "c828304c83619e2cb9dab80305e5286aba91742dc550e1469d91812af27101a1"
      id = "94594b4e-091d-5964-b2b4-5d7d44601b28"
   strings:
      $s1 = "\\x64\\x64passldr.pdb" ascii
      $s2 = "\\amd64\\x64pass.sys" wide
      $s3 = "\\\\.\\DCR" fullword ascii
      $s4 = "Open SC Mgr Error" fullword ascii
      $s5 = "thing is ok " fullword ascii
      $s6 = "x64pass" fullword wide
      $s7 = "%ws\\%ws\\Security" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 3 of them
}
