
rule CrunchRAT {
   meta:
      description = "Detects CrunchRAT - file CrunchRAT.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/t3ntman/CrunchRAT"
      date = "2017-11-03"
      hash1 = "58a07e96497745b6fd5075d569f17b0254c3e50b0234744e0487f7c5dddf7161"
      id = "da7d9b5c-6ccc-5960-9daa-4df612545751"
   strings:
      $x1 = "----CrunchRAT" fullword wide
      $x2 = "\\Debug\\CrunchRAT" ascii
      $x3 = "\\Release\\CrunchRAT" ascii

      $s1 = "runCommand" fullword ascii
      $s2 = "<action>download<action>" fullword wide
      $s3 = "Content-Disposition: form-data; name=action" fullword wide
      $s4 = "<action>upload<action>" fullword wide
      $s5 = "/update.php" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and ( 1 of ($x*) and 3 of them )
}
