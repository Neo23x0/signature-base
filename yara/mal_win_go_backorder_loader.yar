rule MAL_BACKORDER_LOADER_WIN_Go_Jan23 {
   meta:
      description = "Detects the BACKORDER loader compiled in GO which download and executes a second stage payload from a remote server."
      author = "Arda Buyukkaya (modified by Florian Roth)"
      date = "2025-01-23"
      reference = "EclecticIQ"
      score = 80
      tags = "loader, golang, BACKORDER, malware, windows"
      hash = "70c91ffdc866920a634b31bf4a070fb3c3f947fc9de22b783d6f47a097fec2d8"
      id = "90a82f2c-be92-5d0b-b47e-f47db2b15867"
   strings:
      $GoBuildId = "Go build" ascii
      // Debug symbols commonly seen in BACKORDER loader
      $x_DebugSymbol_1 = "C:/updatescheck/main.go"
      $x_DebugSymbol_2 = "C:/Users/IEUser/Desktop/Majestic/"
      // Function name patterns observed in BACKORDER loader
      $s_FunctionName_1 = "main.getUpdates.func"
      $s_FunctionName_2 = "main.obt_zip"
      $s_FunctionName_3 = "main.obtener_zip"
      $s_FunctionName_4 = "main.get_zip"
      $s_FunctionName_5 = "main.show_pr0gressbar"
      $s_FunctionName_6 = "main.pr0cess"
   condition:
      uint16(0) == 0x5a4d
      and filesize < 10MB
      and $GoBuildId
      and (
         1 of ($x*)
         or 3 of them
      )
}
