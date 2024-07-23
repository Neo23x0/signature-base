
rule MAL_Go_Modbus_Jul24_1 {
   meta:
      description = "Detects characteristics reported by Dragos for FrostyGoop ICS malware"
      author = "Florian Roth"
      reference = "https://hub.dragos.com/hubfs/Reports/Dragos-FrostyGoop-ICS-Malware-Intel-Brief-0724_.pdf"
      date = "2024-07-23"
      score = 75
      hash1 = "5d2e4fd08f81e3b2eb2f3eaae16eb32ae02e760afc36fa17f4649322f6da53fb"
   strings:
      $a1 = "Go build"

      $sa1 = "github.com/rolfl/modbus"

      $sb1 = "main.TaskList.executeCommand"
      $sb2 = "main.TargetList.getTargetIpList"
   condition:
      filesize < 30MB
      and (
         $sa1
         and 1 of ($sb*)
      )
      or all of them
}
