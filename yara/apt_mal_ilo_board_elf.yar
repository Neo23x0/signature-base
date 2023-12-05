
rule APT_MAL_HP_iLO_Firmware_Dec21_1 {
   meta:
      description = "Detects suspicios ELF files with sections as described in malicious iLO Board analysis by AmnPardaz in December 2021"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://threats.amnpardaz.com/en/2021/12/28/implant-arm-ilobleed-a/"
      date = "2021-12-28"
      score = 80
      id = "7f5fa905-07a3-55da-b644-c5ab882b4a9d"
   strings:
      $s1 = ".newelf.elf.text" ascii
      $s2 = ".newelf.elf.libc.so.data" ascii
      $s3 = ".newelf.elf.Initial.stack" ascii
      $s4 = ".newelf.elf.libevlog.so.data" ascii
   condition:
      filesize < 5MB and 2 of them or 
      all of them
}
