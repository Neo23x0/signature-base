
rule CredentialStealer_Generic_Backdoor {
   meta:
      description = "Detects credential stealer byed on many strings that indicate password store access"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-06-07"
      hash1 = "edb2d039a57181acf95bd91b2a20bd9f1d66f3ece18506d4ad870ab65e568f2c"
   strings:
      $s1 = "GetOperaLoginData" fullword ascii
      $s2 = "GetInternetExplorerCredentialsPasswords" fullword ascii
      $s3 = "%s\\Opera Software\\Opera Stable\\Login Data" fullword ascii
      $s4 = "select *  from moz_logins" fullword ascii
      $s5 = "%s\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
      $s6 = "Host.dll.Windows" fullword ascii
      $s7 = "GetInternetExplorerVaultPasswords" fullword ascii
      $s8 = "GetWindowsLiveMessengerPasswords" fullword ascii
      $s9 = "%s\\Chromium\\User Data\\Default\\Login Data" fullword ascii
      $s10 = "%s\\Opera\\Opera\\profile\\wand.dat" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and 4 of them )
}
