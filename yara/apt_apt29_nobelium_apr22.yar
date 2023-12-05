rule M_APT_Downloader_BEATDROP {
   meta:
      author = "Mandiant"
      description = "Rule looking for BEATDROP malware"
      reference = "https://www.mandiant.com/resources/tracking-apt29-phishing-campaigns"
      date = "2022-04-28"
      score = 90
      id = "5720870e-8989-59f2-998b-019084d091ce"
   strings:
      $ntdll1 = "ntdll" ascii fullword
      $ntdll2 = "C:\\Windows\\System32\\ntdll.dll" ascii fullword nocase
      $url1 = "api.trello.com" ascii
      $url2 = "/members/me/boards?key=" ascii
      $url3 = "/cards?key=" ascii
   condition:
      uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 1MB and all of them
}

rule M_APT_Downloader_BOOMMIC {
   meta:
      author = "Mandiant"
      description = "Rule looking for BOOMMIC malware"
      reference = "https://www.mandiant.com/resources/tracking-apt29-phishing-campaigns"
      date = "2022-04-28"
      score = 75
      id = "34ea08a6-5d6f-5cdd-a629-fa36313c98f7"
   strings:
      $loc_10001000 = { 55 8B EC 8D 45 0C 50 8B 4D 08 51 6A 02 FF 15 [4] 85 C0 74 09 B8 01 00 00 00 EB 04 EB 02 33 C0 5D C3 }
      $loc_100012fd = {6A 00 8D 55 EC 52 8B 45 D4 50 6A 05 8B 4D E4 51 FF 15 }
      $func1 = "GetComputerNameExA" ascii
      $func2 = "HttpQueryInfoA" ascii
   condition:
      uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 1MB and
      (
         ($loc_10001000 and $func1) or
         ($loc_100012fd and $func2)
      )
}
