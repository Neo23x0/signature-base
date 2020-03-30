
rule SUSP_TINY_PE {
   meta:
      description = "Detects Tiny PE file"
      author = "Florian Roth"
      reference = "https://webserver2.tecgraf.puc-rio.br/~ismael/Cursos/YC++/apostilas/win32_xcoff_pe/tyne-example/Tiny%20PE.htm"
      date = "2019-10-23"
      score = 80
   strings:
      $header = { 4D 5A 00 00 50 45 00 00 }
   condition:
      uint16(0) == 0x5a4d and uint16(4) == 0x4550 and filesize <= 20KB and $header at 0
}
