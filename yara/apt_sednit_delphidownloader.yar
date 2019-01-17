/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-04-24
   Identifier: Sednit Delphi Downloader
   Reference: https://www.welivesecurity.com/2018/04/24/sednit-update-analysis-zebrocy/
*/

/* Rule Set ----------------------------------------------------------------- */

rule MAL_Sednit_DelphiDownloader_Apr18_2 {
   meta:
      description = "Detects malware from Sednit Delphi Downloader report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/04/24/sednit-update-analysis-zebrocy/"
      date = "2018-04-24"
      hash1 = "53aef1e8b281a00dea41387a24664655986b58d61d39cfbde7e58d8c2ca3efda"
      hash2 = "657c83297cfcc5809e89098adf69c206df95aee77bfc1292898bbbe1c44c9dc4"
      hash3 = "5427ecf4fa37e05a4fbab8a31436f2e94283a832b4e60a3475182001b9739182"
      hash4 = "0458317893575568681c86b83e7f9c916540f0f58073b386d4419517c57dcb8f"
      hash5 = "72aa4905598c9fb5a1e3222ba8daa3efb52bbff09d89603ab0911e43e15201f3"
   strings:
      $s1 = "2D444F574E4C4F41445F53544152542D" ascii /* hex encoded string '-DOWNLOAD_START-' */
      $s2 = "55504C4F41445F414E445F455845435554455F46494C45" ascii /* hex encoded string 'UPLOAD_AND_EXECUTE_FILE' */
      $s3 = "4D6F7A696C6C612076352E31202857696E646F7773204E5420362E313B2072763A362E302E3129204765636B6F2F32303130303130312046697265666F782F36" ascii /* hex encoded string 'Mozilla v5.1 (Windows NT 6.1; rv:6.0.1) Gecko/20100101 Firefox/6.0.1' */
      $s4 = "41646F62654461696C79557064617465" ascii /* hex encoded string 'AdobeDailyUpdate' */
      $s5 = "53595354454D494E464F2026205441534B4C495354" ascii /* hex encoded string 'SYSTEMINFO & TASKLIST' */
      $s6 = "6373727376632E657865" ascii /* hex encoded string 'csrsvc.exe' */
      $s7 = "536F6674776172655C4D6963726F736F66745C57696E646F77735C43757272656E7456657273696F6E5C52756E" ascii /* hex encoded string 'Software\Microsoft\Windows\CurrentVersion\Run' */
      $s8 = "5C536F6674776172655C4D6963726F736F66745C57696E646F7773204E545C43757272656E7456657273696F6E" ascii /* hex encoded string '\Software\Microsoft\Windows NT\CurrentVersion' */
      $s9 = "5C536F6674776172655C4D6963726F736F66745C57696E646F77735C43757272656E7456657273696F6E" ascii /* hex encoded string '\Software\Microsoft\Windows\CurrentVersion' */
      $s0 = "2D444F574E4C4F41445F53544152542D" ascii /* hex encoded string '-DOWNLOAD_START-' */

      $fp1 = "<key name=\"profiles\">"
   condition:
      filesize < 4000KB and 1 of ($s*) and not 1 of ($fp*)
}

rule MAL_Sednit_DelphiDownloader_Apr18_3 {
   meta:
      description = "Detects malware from Sednit Delphi Downloader report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/04/24/sednit-update-analysis-zebrocy/"
      date = "2018-04-24"
      hash1 = "ecb835d03060db1ea3496ceca2d79d7c4c6c671c9907e0b0e73bf8d3371fa931"
      hash2 = "e355a327479dcc4e71a38f70450af02411125c5f101ba262e8df99f9f0fef7b6"
   strings:
      $ = "Processor Level: " fullword ascii
      $ = "CONNECTION ERROR" fullword ascii
      $ = "FILE_EXECUTE_AND_KILL_MYSELF" ascii
      $ = "-KILL_PROCESS-" fullword ascii
      $ = "-FILE_EXECUTE-" fullword ascii
      $ = "-DOWNLOAD_ERROR-" fullword ascii
      $ = "CMD_EXECUTE" fullword ascii
      $ = "\\Interface\\Office\\{31E12FE8-937F-1E32-871D-B1C9AOEF4D4}\\" fullword ascii
      $ = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 3 of them
}
