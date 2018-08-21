rule SUSP_certificate_payload {
   meta:
      description = "Detects payloads that pretend to be certificates"
      date = "2018/08/02"
      author = "Didier Stevens, Florian Roth"
      reference = "https://blog.nviso.be/2018/08/02/powershell-inside-a-certificate-part-3/"
      score = 50
   strings:
      $re1 = "-----BEGIN CERTIFICATE-----"

      $fp1 = "replace it with the PEM-encoded root certificate"
   condition:
      uint32(0) == 0x2D2D2D2D
      and $re1 at 0
      /* not 'M' at position 29, which is after the BEGIN CERTIFICATE header plus line break */
      /* \r\n */
      and not uint8(29) == 0x4D
      /* \n */
      and not uint8(28) == 0x4D
      and not 1 of ($fp*)
}
