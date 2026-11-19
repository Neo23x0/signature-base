
rule HKTL_XiebroC2_Go_Implant_Apr26 {
   meta:
      description = "Detects the Windows Go implant of the XiebroC2 framework by Go symbol names from its own packages, including the misspelt WindosVersion function, together with its go-clr import path or the error strings of its RunPE loader"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://github.com/INotGreen/XiebroC2"
      date = "2026-04-03"
      score = 75
      hash1 = "2c1dcd403af6517ac01f3f40058b0df6b038c9a2b58ccb8cac2626204f9cf209"
      id = "90df8d57-e457-57d1-b7c5-2b318c32508e"
   strings:
      $a1 = "main/Helper/sysinfo.WindosVersion" ascii
      $a2 = "main/MessagePack.ReadStringWithFlag" ascii
      $a3 = "main/PcInfo.GetClientComputer" ascii

      $s1 = "github.com/Ne0nd0g/go-clr" ascii
      $s2 = "DOS image header magic string was not MZ" ascii
      $s3 = "PE Signature string was not PE" ascii
      $s4 = "NtQueryInformationProcess returned NTSTATUS:" ascii
   condition:
      uint16(0) == 0x5a4d
      and filesize < 25MB
      and 2 of ($a*)
      and 2 of ($s*)
}
