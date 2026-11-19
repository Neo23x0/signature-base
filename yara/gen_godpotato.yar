
rule HKTL_GodPotato_PrivEsc {
   meta:
      description = "Detects GodPotato, a local privilege escalation tool that abuses DCOM/RPC OXID resolution to elevate a SeImpersonatePrivilege context to NT AUTHORITY\\SYSTEM"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Chris (ChrisJr404)"
      reference = "https://github.com/BeichenDream/GodPotato"
      date = "2026-08-26"
      score = 85
      id = "50640719-a634-41cc-8fd4-d21202eeefa0"
   strings:
      $guid = "2ae886c3-3272-40be-8d3c-ebaede9e61e1" ascii wide nocase
      $name = "GodPotato" ascii wide

      $x1 = "[*] UseProtseqFunctionParamCount:" ascii wide
      $x2 = "[*] UseProtseqFunction: 0x" ascii wide
      $x3 = "[*] UnmarshalObject: 0x" ascii wide
      $x4 = "[*] DispatchTable: 0x" ascii wide
      $x5 = "[*] CombaseModule: 0x" ascii wide
      $x6 = "[*] Trigger RPCSS" ascii wide
      $x7 = "[!] Failed to impersonate security context token" ascii wide
   condition:
      uint16(0) == 0x5A4D and filesize < 500KB
      and (
         $guid
         or 2 of ($x*)
         or ( $name and 1 of ($x*) )
      )
}
