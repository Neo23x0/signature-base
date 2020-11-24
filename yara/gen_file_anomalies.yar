
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

rule SUSP_GIF_Anomalies {
   meta:
      description = "Detects files with GIF headers and format anomalies - which means that this image could be an obfuscated file of a different type"
      author = "Florian Roth"
      score = 60
      reference = "https://en.wikipedia.org/wiki/GIF"
      date = "2020-07-02"
   condition:
      uint16(0) == 0x4947 and uint8(2) == 0x46 /* GIF */
      and uint8(11) != 0x00 /* Background Color Index != 0 */
      and uint8(12) != 0x00 /* Pixel Aspect Ratio != 0 */
      and uint8(filesize-1) != 0x3b /* Trailer (trailes are often 0x00 byte padded and cannot server as sole indicator) */
}
