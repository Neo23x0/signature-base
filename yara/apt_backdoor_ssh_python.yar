
rule custom_ssh_backdoor_server {
   meta:
      description = "Custome SSH backdoor based on python and paramiko - file server.py"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/S46L3o"
      date = "2015-05-14"
      modified = "2022-08-18"
      hash = "0953b6c2181249b94282ca5736471f85d80d41c9"
      id = "eccf705b-b2c3-5af6-ab86-70292089812b"
   strings:
      $s0 = "command= raw_input(\"Enter command: \").strip('n')" fullword ascii
      $s1 = "print '[-] (Failed to load moduli -- gex will be unsupported.)'" fullword ascii
      $s2 = "print '[-] Listen/bind/accept failed: ' + str(e)" fullword ascii
   condition:
      2 of them
}
