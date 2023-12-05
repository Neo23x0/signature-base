import "pe"

rule gen_Excel_xll_addin_suspicious
{
    meta:
        description = "Detects suspicious XLL add-ins to Excel"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "@JohnLaTwC"
        date = "2020-10-16"
        reference1="https://twitter.com/JohnLaTwC/status/1315287078855352326"
        reference2="https://labs.f-secure.com/archive/add-in-opportunities-for-office-persistence/"
        reference3="https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52"

        hash1="0bad4e4bc5093dcfc2737c4d8be89d6f093509a7b91a1e022050cb890d90e4e0"
        hash2="133e47eedfede46d1a4529ce7f047e09521ed8c7cad2e49d3522064695bd6c43"
        hash3="1994a39d5639b4eea5c3cdf084a8eacf8610a96702e580d88a6ec18887d0ec6b"
        hash4="28f45d01e397841fcba48da1e61e4927f42ff6fe6f32595c23cf9a953cd2658a"
        hash5="54c3598cf22ad64faeb4e0f9f70e026a1ae834a8c06e5187bf289bb3ee43a8ec"
        hash6="5644a04513744edfb247d0ea83e3e2f7d616d6752cfd1af50e866bb0270131ee"
        hash7="836c0d21fc3ea3a8ce1a493097a5034d110e5c50bfd7e6c3dcb674dc7a6a19ec"
        hash8="b926f7db36bc5bae73091c783b0715d2af051de22a579548adf2498cb1a1d075"
        hash9="6ba100a5da5efea14a5ca929628b732a6e6b8ab8f78167db35343e895997ce52"
        hasha="ee603cbd6187850334ae5d8adcf029d5cde710fc966b2b7a2c95249d3b23d693"
        hashb="99195679e998407fd4d606a0d956bda99f79625b638c63f90d9d399c6f2a143e"
        hashc="99534c7086128998ae39967fe5fc6bf526cb2ba5d3b2e99dc7bd03833e4a94ae"
        id = "013db759-ab9d-5505-933b-bda702a0941e"
    strings:
        $s1 = "CryptStringToBinaryA"
        $s2 = "NtQueueApcThread"
        
        $cs1 = "dsrole.dll"
        $cs2 = "user32.dll"

        $debug = "SeDebugPrivilege"
    condition:
        filesize < 1MB
        and uint16(0) == 0x5a4d 
        and pe.characteristics & pe.DLL
        and pe.exports("xlAutoOpen")
        and (
              ((pe.imports("KERNEL32.dll", "LookupPrivilegeValueW") or pe.imports("KERNEL32.dll", "LookupPrivilegeValueA"))
                and pe.imports("KERNEL32.dll", "AdjustTokenPrivileges")
                and pe.imports("KERNEL32.dll", "OpenProcess")
                and $debug)
             or (pe.imports("ADVAPI32.dll", "CryptDecrypt")
                 and pe.imports("ADVAPI32.dll", "CryptImportKey"))
             or (pe.imports("DNSAPI.dll", "DnsQuery_A") or pe.imports("DNSAPI.dll", "DnsQuery_W"))
             or ((pe.imports("KERNEL32.dll", "FindResourceA") or pe.imports("KERNEL32.dll", "FindResourceW"))
                  and pe.imports("KERNEL32.dll", "LoadResource")
                  and pe.imports("KERNEL32.dll", "LockResource")
                  and (pe.imports("KERNEL32.dll", "VirtualAlloc") or pe.imports("KERNEL32.dll", "VirtualAllocEx"))
                  and pe.imports("KERNEL32.dll", "WriteProcessMemory")
                  and pe.imports("KERNEL32.dll", "SetThreadContext"))
             or (pe.imports("KERNEL32.dll", "GetThreadContext")
                  and pe.imports("KERNEL32.dll", "VirtualAllocEx")
                  and pe.imports("KERNEL32.dll", "ResumeThread")
                  and pe.imports("KERNEL32.dll", "SetThreadContext"))
             or (pe.imports("KERNEL32.dll", "WinExec"))
             or (all of ($s*))
             or (all of ($cs*) and pe.imports("KERNEL32.dll", "VirtualAllocEx")
                  and pe.imports("KERNEL32.dll", "TerminateProcess")
                  and pe.imports("KERNEL32.dll", "Sleep"))
            )
}
