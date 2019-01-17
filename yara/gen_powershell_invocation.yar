
rule PowerShell_Susp_Parameter_Combo {
   meta:
      description = "Detects PowerShell invocation with suspicious parameters"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/uAic1X"
      date = "2017-03-12"
      score = 60
      type = "file"
   strings:
      /* Encoded Command */
      $a1 = " -enc " ascii nocase
      $a2 = " -EncodedCommand " ascii nocase

      /* Window Hidden */
      $b1 = " -w hidden " ascii nocase
      $b2 = " -window hidden " ascii nocase
      $b3 = " -windowstyle hidden " ascii nocase

      /* Non Profile */
      $c1 = " -nop " ascii nocase
      $c2 = " -noprofile " ascii nocase

      /* Non Interactive */
      $d1 = " -noni " ascii nocase
      $d2 = " -noninteractive " ascii nocase

      /* Exec Bypass */
      $e1 = " -ep bypass " ascii nocase
      $e2 = " -exec bypass " ascii nocase
      $e3 = " -executionpolicy bypass " ascii nocase
      $e4 = " -exec bypass " ascii nocase

      /* Single Threaded - PowerShell Empire */
      $f1 = " -sta " ascii
      
      $fp1 = "Chocolatey Software"
      $fp2 = "VBOX_MSI_INSTALL_PATH"
   condition:
      filesize < 3000KB and 4 of ($s*) and not 1 of ($fp*)
}
