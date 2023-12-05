
rule MAL_ELF_ReverseShell_SSLShell_Jun23_1 {
   meta:
      description = "Detects reverse shell named SSLShell used in Barracuda ESG exploitation (CVE-2023-2868)"
      author = "Florian Roth"
      reference = "https://www.barracuda.com/company/legal/esg-vulnerability"
      date = "2023-06-07"
      score = 75
      hash1 = "8849a3273e0362c45b4928375d196714224ec22cb1d2df5d029bf57349860347"
      id = "91b34eb7-61d2-592e-a444-249da43994ca"
   strings:
      $sc1 = { 00 2D 63 00 2F 62 69 6E 2F 73 68 00 }
      $s1 = "SSLShell"
   condition:
      uint32be(0) == 0x7f454c46
      and uint16(0x10) == 0x0002
      and filesize < 5MB
      and all of them
}

rule MAL_ELF_SALTWATER_Jun23_1 {
   meta:
      description = "Detects SALTWATER malware used in Barracuda ESG exploitations (CVE-2023-2868)"
      author = "Florian Roth"
      reference = "https://www.barracuda.com/company/legal/esg-vulnerability"
      date = "2023-06-07"
      score = 80
      hash1 = "601f44cc102ae5a113c0b5fe5d18350db8a24d780c0ff289880cc45de28e2b80"
      id = "10a038f6-6096-5d3a-aaf5-db441685102b"
   strings:
      $x1 = "libbindshell.so"
      
      $s1 = "ShellChannel"
      $s2 = "MyWriteAll"
      $s3 = "CheckRemoteIp"
      $s4 = "run_cmd"
      $s5 = "DownloadByProxyChannel"
      $s6 = "[-] error: popen failed"
      $s7 = "/home/product/code/config/ssl_engine_cert.pem"
   condition:
      uint16(0) == 0x457f and
      filesize < 6000KB and (
         ( 1 of ($x*) and 2 of them )
         or 3 of them
      ) or all of them
}
