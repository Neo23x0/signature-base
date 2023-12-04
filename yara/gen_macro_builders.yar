
rule SUSP_MalDoc_ExcelMacro {
  meta:
    description = "Detects malicious Excel macro Artifacts"
    author = "James Quinn"
    date = "2020-11-03"
    reference = "YARA Exchange - Undisclosed Macro Builder"
  strings:
    $artifact1 = {5c 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2e 00 ?? 00 ?? 00}
    $url1 = "http://" wide
    $url2 = "https://" wide
    $import1 = "URLDownloadToFileA" wide ascii
    $macro = "xl/macrosheets/"
  condition:
    uint16(0) == 0x4b50 and
    filesize < 2000KB and
    $artifact1 and $macro and $import1 and 1 of ($url*)
}
