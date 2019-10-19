rule Reverse_Connect_TCP_PTY_Shell {
   meta:
      description = "Reverse Connect TCP PTY Shell"
      author = "Jeff Beley"
      date = "2019-10-19"
      hash1 = "cae9833292d3013774bdc689d4471fd38e4a80d2d407adf9fa99bc8cde3319bf"
      reference = "https://github.com/infodox/python-pty-shells/blob/master/tcp_pty_backconnect.py"
   strings:
      $s1 = "os.dup2(s.fileno(),1)" fullword ascii
      $s2 = "s.connect((lhost, lport))" fullword ascii
      $s3 = "pty.spawn(\"/bin/")" fullword ascii
      $s4 = "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)" fullword ascii
      $s5 = "import pty" fullword ascii
      $s6 = "#!/usr/bin/python2" fullword ascii
      $s7 = "lport = " fullword ascii
      $s8 = "os.putenv(\"HISTFILE\",'/dev/null')" fullword ascii
      $s9 = "os.dup2(s.fileno(),2)" fullword ascii
      $s10 = "os.dup2(s.fileno(),0)" fullword ascii
      $s11 = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)" fullword ascii
   condition:
      filesize < 1KB and 7 of them
}
