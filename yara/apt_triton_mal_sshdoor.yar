
// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2018, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

// MODIFIED VERSION
// Mofificaton applied by Florian Roth 05.12.2018
// Reasons for the changes:
//    - Cleaner rule structure (no inter-dependencies)
//    - Performance
//    - Limited rules to ELF files to reduce false positive rate
// Disadvantage:
//    - Lost family identification (see the original rules)
//    - Missing rule (the one with the expected & relevant performance impact)

rule MAL_LNX_SSHDOOR_Triton {
   meta:
      description = "Signature detecting "
      author = "Marc-Etienne M.Leveille, modified by Florian Roth"
      email  = "leveille@eset.com"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
      date = "2018-12-05"
      license = "BSD 2-Clause"
   strings:
      /* SSH binaries - specific strings */
      $a_usage1 = "usage: ssh ["
      $a_usage2 = "usage: %s [options] [command [arg ...]]"
      $a_old_version1 = "-L listen-port:host:port"
      $a_old_version2 = "Listen on the specified port (default: 22)"
      $a_usage = "usage: %s [-46Hv] [-f file] [-p port] [-T timeout] [-t type]"
      /* SSH binaries - combo required */
      $ac_usage = "usage: %s [options] [file ...]\n"
      $ac_log1 = "Could not open a connection to your authentication agent.\n"
      $ac_pass2 = "Enter your OpenSSH passphrase:"
      $ac_log2 = "Could not grab %s. A malicious client may be eavesdropping on you"
      $ac_pass3 = "Enter new passphrase (empty for no passphrase):"
      $ac_log3 = "revoking certificates by key ID requires specification of a CA key"

      /* Strings from malicious files */
      /* abafar */
      $s_log_c =  "%s:%s@%s"
      $s_log_d =  "%s:%s from %s"
      /* akiva */
      $s_log_aki = /(To|From):\s(%s\s\-\s)?%s:%s\n/
      /* alderaan */
      $s_log_ald = /login\s(in|at):\s(%s\s)?%s:%s\n/
      /* ando */
      $ando_s1 = "%s:%s\n"
      $ando_s2 = "HISTFILE"
      $ando_i = "fopen64"
      $ando_m1 = "cat "
      $ando_m2 = "mail -s"
      /* anoat */
      $s_log_ano = "%s at: %s | user: %s, pass: %s\n"
      /* batuu */
      $s_args_bat = "ssh: ~(av[%d]: %s\n)"
      $s_log_bat = "readpass: %s\n"
      /* banodan */
      $s_banodan1 = "g_server"
      $s_banodan2 = "mine.sock"
      $s_banodan3 = "tspeed"
      $s_banodan4 = "6106#x=%d#%s#%s#speed=%s"
      $s_banodan5 = "usmars.mynetgear.com"
      $s_banodan6 = "user=%s#os=%s#eip=%s#cpu=%s#mem=%s"
      /* borleias */
      $s_borleias_log = "%Y-%m-%d %H:%M:%S [%s]"
      /* ondaron */
      $s_daemon = "user:password --> %s:%s\n"
      $s_client = /user(,|:)(a,)?password@host \-\-> %s(,|:)(b,)?%s@%s\n/
      /* polis_massa */
      $s_polis_log = /\b\w+(:|\s-+>)\s%s(:%d)?\s\t(\w+)?:\s%s\s\t(\w+)?:\s%s/
      /* quarren */
      $s_quarren_log = "h: %s, u: %s, p: %s\n"

      /* chandrilla */
      $chandrila_log = "S%s %s:%s"
      $chandrila_magic = { 05 71 92 7D }

      /* atollon */
      // single byte offset from base pointer
      $atollon_bp = /(\xC6\x45.{2}){25}/
      // dword ss with single byte offset from base pointer
      $atollon_bp_dw = /(\xC7\x45.{5}){20}/
      // 4-bytes offset from base pointer
      $atollon_bp_off = /(\xC6\x85.{5}){25}/
      // single byte offset from stack pointer
      $atollon_sp = /(\xC6\x44\x24.{2}){25}/
      // 4-bytes offset from stack pointer
      $atollon_sp_off = /(\xC6\x84\x24.{5}){25}/
      /* other strings */
      $atollon_f1 = "PEM_read_RSA_PUBKEY"
      $atollon_f2 = "RAND_add"
      $atollon_log = "%s:%s"
      $atollon_rand = "/dev/urandom"

      /* bespin */
      $bespin_log1 = "%Y-%m-%d %H:%M:%S"
      $bespin_log2 = "%s %s%s"
      $bespin_log3 = "[%s]"

      /* coruscant */
      $coruscant_s1 = "%s:%s@%s\n"
      $coruscant_s2 = "POST"
      $coruscant_s3 = "HTTP/1.1"

      /* crait */
      $crait_i1 = "flock"
      $crait_i2 = "fchmod"
      $crait_i3 = "sendto"

      /* jakuu */
      $jakuu_dec = /GET\s\/\?(s|c)id=/
      $jakuu_enc1 = "getifaddrs"
      $jakuu_enc2 = "usleep"
      $jakuu_ns = "gethostbyname"
      $jakuu_log = "%s:%s"
      $jakuu_rc4 = { A1 71 31 17 11 1A 22 27 55 00 66 A3 10 FE C2 10 22 32 6E 95 90 84 F9 11 73 62 95 5F 4D 3B DB DC }

      /* kamino */
      $kamino_s1 = "/var/log/wtmp"
      $kamino_s2 = "/var/log/secure"
      $kamino_s3 = "/var/log/auth.log"
      $kamino_s4 = "/var/log/messages"
      $kamino_s5 = "/var/log/audit/audit.log"
      $kamino_s6 = "/var/log/httpd-access.log"
      $kamino_s7 = "/var/log/httpd-error.log"
      $kamino_s8 = "/var/log/xferlog"
      $kamino_i1 = "BIO_f_base64"
      $kamino_i2 = "PEM_read_bio_RSA_PUBKEY"
      $kamino_i3 = "srand"
      $kamino_i4 = "gethostbyname"

      /* kessel */
      $kessel_rc4 = "Xee5chu1Ohshasheed1u"
      $kessel_s1 = "ssh:%s:%s:%s:%s"
      $kessel_s2 = "sshkey:%s:%s:%s:%s:%s"
      $kessel_s3 = "sshd:%s:%s"
      $kessel_i1 = "spy_report"
      $kessel_i2 = "protoShellCMD"
      $kessel_i3 = "protoUploadFile"
      $kessel_i4 = "protoSendReport"
      $kessel_i5 = "tunRecvDNS"
      $kessel_i6 = "tunPackMSG"

      /* mimban */
      $mimban_s1 = "<|||%s|||%s|||%d|||>"
      $mimban_s2 = />\|\|\|%s\|\|\|%s\|\|\|\d\|\|\|%s\|\|\|%s\|\|\|%s\|\|\|%s\|\|\|</
      $mimban_s3 = "-----BEGIN PUBLIC KEY-----"
      $mimban_i1 = "BIO_f_base64"
      $mimban_i2 = "PEM_read_bio_RSA_PUBKEY"
      $mimban_i3 = "gethostbyname"
   condition:
      uint32be(0) == 0x7f454c46 and // ELF
      ( 1 of ($a_*) or 2 of ($ac_*) ) // SSH Binary
      and (
         ( 1 of ($s*) ) or
         ( all of ($ando_s*) and ($ando_i or all of ($ando_m*)) ) or
         ( all of ($atollon*) ) or
         ( all of ($bespin*) ) or
         ( all of ($chandrila*) ) or
         ( all of ($coruscant*) ) or
         ( 2 of ($crait*) ) or
         ( $jakuu_log and $jakuu_ns and ($jakuu_dec or all of ($jakuu_enc*) or $jakuu_rc4)) or
         ( 5 of ($kamino_s*) and 3 of ($kamino_i*) ) or
         ( 2 of ($kessel_s*) or 2 of ($kessel_i*) or $kessel_rc4 ) or
         ( 2 of ($mimban_s*) and 2 of ($mimban_i*) )
      )
}

/*
rule endor {
    meta:
        description = "Rule to detect Endor family"
        author = "Hugo Porcher"
        email  = "hugo.porcher@eset.com"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf"
        date = "2018-12-05"
        license = "BSD 2-Clause"

    strings:
        $u = "user: %s"
        $p = "password: %s"

    condition:
        ssh_binary and $u and $p in (@u..@u+20)
}
*/
