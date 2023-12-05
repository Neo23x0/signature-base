
rule APT_SH_CodeCov_Hack_Apr21_1 {
   meta:
      description = "Detects manipulated Codecov bash uploader tool that has been manipulated by an unknown actor during March / April 2021"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://about.codecov.io/security-update/"
      date = "2021-04-16"
      id = "b5fb74c4-073e-53af-a207-1672e63c9a64"
   strings:
      $a1 = "Global report uploading tool for Codecov"

      $s1 = "curl -sm 0.5 -d"
   condition:
      uint16(0) == 0x2123 and
      filesize < 70KB and
      all of them
}
