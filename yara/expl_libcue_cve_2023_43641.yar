
rule SUSP_EXPL_LIBCUE_CVE_2023_43641_Oct23_1 {
   meta:
      author = "Florian Roth"
      description = "Detects a suspicious .cue file that could be an exploitation attempt of libcue vulnerability CVE-2023-43641"
      reference = "https://github.com/github/securitylab/blob/main/SecurityExploits/libcue/track_set_index_CVE-2023-43641/README.md"
      date = "2023-10-27"
      score = 70
      id = "34fcf80c-adcd-55c0-9fb4-261d20f61fa6"
   strings:
      $a1 = "TRACK "
      $a2 = "FILE "

      $s1 = "INDEX 4294"
   condition:
      filesize < 100KB and all of them
}
