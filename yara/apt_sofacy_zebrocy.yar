rule apt28_win_zebrocy_golang_loader_modified {
   meta:
      description = "Detects unpacked modified APT28/Sofacy Zebrocy Golang."
      author = "@VK_Intel"
      date = "2018-12-25"
      reference = "https://www.vkremez.com/2018/12/lets-learn-progression-of-apt28sofacy.html"
   strings:
      // Go build
      $go = { 47 6f 20 62 75 69 6c 64 20 49 44 3a 20 }
      $init = { 6d 61 69 6e 2e 69 6e 69 74 }
      $main = "main" ascii wide fullword
      $scr_git = {67 69 74 68 75 62 2e 63 6f 6d 2f 6b 62 69 6e 61}
      $s0 = "os/exec.(*Cmd).Run" fullword ascii
      $s1 = "net/http.(*http2clientConnReadLoop).processHeaders" fullword ascii
      $s2 = "os.MkdirAll" fullword ascii
      $s3 = "os.Getenv" fullword ascii
      $s4 = "os.Create" fullword ascii
      $s5 = "io/ioutil.WriteFile" fullword ascii
   condition:
      uint16(0) == 0x5a4d and $go and $init and all of ($s*) and #main > 10 and #scr_git > 5
}
