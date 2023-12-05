import "pe"

rule SUSP_ENV_Folder_Root_File_Jan23_1 : SCRIPT {
   meta:
      description = "Detects suspicious file path pointing to the root of a folder easily accessible via environment variables"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2023-01-11"
      score = 70
      id = "6067d822-5c1b-5b86-863c-fdcfa37da665"
   strings:
      $xr1 = /%([Aa]pp[Dd]ata|APPDATA)%\\[A-Za-z0-9_\-]{1,20}\.[a-zA-Z0-9]{1,4}[^\\]/ wide ascii
      $xr2 = /%([Pp]ublic|PUBLIC)%\\[A-Za-z0-9_\-]{1,20}\.[a-zA-Z0-9]{1,4}[^\\]/ wide ascii
      $xr4 = /%([Pp]rogram[Dd]ata|PROGRAMDATA)%\\[A-Za-z0-9_\-]{1,20}\.[a-zA-Z0-9]{1,4}[^\\]/ wide ascii

      $fp1 = "perl -MCPAN " ascii
      $fp2 = "CCleaner" ascii
   condition:
      filesize < 20MB and 1 of ($x*)
      and not 1 of ($fp*)
      and not pe.number_of_signatures > 0
}
