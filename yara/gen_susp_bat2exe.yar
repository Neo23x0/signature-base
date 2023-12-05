/* previously: APT_DarkHydrus_Jul18_4 */
rule SUSP_BAT2EXE_BDargo_Converted_BAT {
   meta:
      description = "Detects binaries created with BDARGO Advanced BAT to EXE converter"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.majorgeeks.com/files/details/advanced_bat_to_exe_converter.html"
      date = "2018-07-28"
      modified = "2022-06-23"
      score = 45
      hash1 = "d428d79f58425d831c2ee0a73f04749715e8c4dd30ccd81d92fe17485e6dfcda"
      hash1 = "a547a02eb4fcb8f446da9b50838503de0d46f9bb2fd197c9ff63021243ea6d88"
      id = "c9da4184-1530-5525-bdba-2dcc8a221bb1"
   strings:
      $s1 = "Error #bdembed1 -- Quiting" fullword ascii
      $s2 = "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s" fullword ascii
      $s3 = "\\a.txt" ascii
      $s4 = "command.com" fullword ascii /* Goodware String - occured 91 times */
      $s6 = "DFDHERGDCV" fullword ascii
      $s7 = "DFDHERGGZV" fullword ascii
      $s8 = "%s%s%s%s%s%s%s%s" fullword ascii /* Goodware String - occured 4 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and 5 of them
}
