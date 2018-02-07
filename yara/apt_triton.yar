rule TRITON_ICS_FRAMEWORK {
      meta:
          author = "nicholas.carr @itsreallynick"
          hash = "0face841f7b2953e7c29c064d6886523"
          description = "TRITON framework recovered during Mandiant ICS incident response"
          reference = "https://www.fireeye.com/blog/threat-research/2017/12/attackers-deploy-new-ics-attack-framework-triton.html"
      strings:
          $python_compiled = ".pyc" nocase ascii wide
          $python_module_01 = "__module__" nocase ascii wide
          $python_module_02 = "<module>" nocase ascii wide
          $python_script_01 = "import Ts" nocase ascii wide
          $python_script_02 = "def ts_" nocase ascii wide

          $py_cnames_01 = "TS_cnames.py" nocase ascii wide
          $py_cnames_02 = "TRICON" nocase ascii wide
          $py_cnames_03 = "TriStation " nocase ascii wide
          $py_cnames_04 = " chassis " nocase ascii wide

          $py_tslibs_01 = "GetCpStatus" nocase ascii wide
          $py_tslibs_03 = " sequence" nocase ascii wide
          $py_tslibs_04 = /import Ts(Hi|Low|Base)[^:alpha:]/ nocase ascii wide
          $py_tslibs_05 = /module\s?version/ nocase ascii wide
          $py_tslibs_07 = "prog_cnt" nocase ascii wide

          $py_tsbase_01 = "TsBase.py" nocase ascii wide
          $py_tsbase_02 = ".TsBase(" nocase ascii wide

          $py_tshi_01 = "TsHi.py" nocase ascii wide
          $py_tshi_02 = "keystate" nocase ascii wide
          $py_tshi_03 = "GetProjectInfo" nocase ascii wide
          $py_tshi_04 = "GetProgramTable" nocase ascii wide
          $py_tshi_05 = "SafeAppendProgramMod" nocase ascii wide

          $py_tslow_01 = "TsLow.py" nocase ascii wide
          $py_tslow_02 = "print_last_error" ascii nocase wide
          $py_tslow_03 = ".TsLow(" ascii nocase wide
          $py_tslow_05 = " TCM found" nocase ascii wide  

          $py_crc_01 = "crc.pyc" nocase ascii wide
          $py_crc_02 = "CRC16_MODBUS" ascii wide
          $py_crc_03 = "Kotov Alaxander" nocase ascii wide
          $py_crc_04 = "CRC_CCITT_XMODEM" ascii wide
          $py_crc_05 = "crc16ret" ascii wide
          $py_crc_06 = "CRC16_CCITT_x1D0F" ascii wide
          $py_crc_07 = /CRC16_CCITT[^_]/ ascii wide

          $py_sh_01 = "sh.pyc" nocase ascii wide

          $py_keyword_01 = " FAILURE" ascii wide
          $py_keyword_02 = "symbol table" nocase ascii wide

          $py_TRIDENT_01 = "inject.bin" ascii nocase wide
          $py_TRIDENT_02 = "imain.bin" ascii nocase wide

      condition:
          2 of ($python_*) and 7 of ($py_*) and filesize < 3MB
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-12-14
   Identifier: Triton
   Reference: https://goo.gl/vtQoCQ
*/

/* Rule Set ----------------------------------------------------------------- */

rule Triton_trilog {
   meta:
      description = "Detects Triton APT malware - file trilog.exe"
      author = "Florian Roth"
      reference = "https://goo.gl/vtQoCQ"
      date = "2017-12-14"
      hash1 = "e8542c07b2af63ee7e72ce5d97d91036c5da56e2b091aa2afe737b224305d230"
   strings:
      $s1 = "inject.bin" ascii
      $s2 = "PYTHON27.DLL" fullword ascii
      $s3 = "payload" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and all of them
}
