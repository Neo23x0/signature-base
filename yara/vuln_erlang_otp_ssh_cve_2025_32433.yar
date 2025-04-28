rule VULN_Erlang_OTP_SSH_CVE_2025_32433_Apr25 {
   meta:
      description = "Detects binaries vulnerable to CVE-2025-32433 in Erlang/OTP SSH"
      author = "Pierre-Henri Pezier, Florian Roth"
      reference = "https://www.upwind.io/feed/cve-2025-32433-critical-erlang-otp-ssh-vulnerability-cvss-10"
      date = "2025-04-18"
      score = 60
   strings:
      $a1 = { 46 4F 52 31 ?? ?? ?? ?? 42 45 41 4D }

      $s1 = "ssh_connection.erl"

      $fix1 = "chars_limit"
      $fix2 = "allow    macro_log"
      $fix3 = "logger"
      $fix4 = "max_log_item_len"
   condition:
      filesize < 1MB
      and $a1 at 0 // BEAM file header
      and $s1
      and not 1 of ($fix*)
}
