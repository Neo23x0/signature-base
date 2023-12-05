rule HKTL_Reverse_Connect_TCP_PTY_Shell {
   meta:
      description = "Detects reverse connect TCP PTY shell"
      author = "Jeff Beley"
      date = "2019-10-19"
      hash1 = "cae9833292d3013774bdc689d4471fd38e4a80d2d407adf9fa99bc8cde3319bf"
      reference = "https://github.com/infodox/python-pty-shells/blob/master/tcp_pty_backconnect.py"
      id = "a9a90d67-774b-5b32-97c0-d7e06763f2e9"
   strings:
      $s1 = "os.dup2(s.fileno(),1)" fullword ascii
      $s2 = "pty.spawn(\"/bin/\")" fullword ascii
      $s3 = "os.putenv(\"HISTFILE\",'/dev/null')" fullword ascii
      $s4 = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)" fullword ascii
   condition:
      filesize < 1KB and 2 of them
}
