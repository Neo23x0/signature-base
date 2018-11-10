
rule Invoke_PSImage {
   meta:
      description = "Detects a command to execute PowerShell from String"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/peewpw/Invoke-PSImage"
      date = "2017-12-16"
   strings:
      $ = "IEX([System.Text.Encoding]::ASCII.GetString(" ascii wide
      $ = "System.Drawing.Bitmap((a Net.WebClient).OpenRead(" ascii wide

      $ = { 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52
            00 00 04 E4 00 00 03 A0 08 06 00 00 00 9D AF A9
            E8 00 00 00 09 70 48 59 73 00 00 19 D6 00 00 19
            D6 01 18 D1 CA ED 00 00 00 07 74 49 4D 45 07 E1
            0C 0F 13 1E 36 89 C4 28 BF 00 00 00 07 74 45 58
            74 41 75 74 68 6F 72 00 A9 AE CC 48 00 00 00 0C
            74 45 58 74 44 65 73 63 72 69 70 74 69 6F 6E 00
            13 09 21 23 00 00 00 0A 74 45 58 74 43 6F 70 79
            72 69 67 68 74 00 AC 0F CC 3A 00 00 00 0E 74 45
            58 74 43 72 65 61 74 69 6F 6E 20 74 69 6D 65 00
            35 F7 0F }
   condition:
      filesize < 3000KB and 1 of them
}