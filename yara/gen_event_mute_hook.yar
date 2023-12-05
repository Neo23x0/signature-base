rule SUSP_Hunt_EvtMuteHook_Memory {
    meta:
        description = "Memory hunt for default wevtsv EtwEventCallback hook pattern to apply to eventlog svchost memory dump"
        reference = "https://blog.dylan.codes/pwning-windows-event-logging/"
        author = "SBousseaden"
        date = "2020-09-05"
        score = 70
        id = "5326581e-90d9-59b9-8dc5-74df97571600"
    strings:
        $a = {49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3 54 24 20 4C 8B 05 61 CB 1A 00 0F 57 C0 66 0F 7F 44 24 20 E8 5B 0A 00 00 48 83 C4 38 C3}
        $b = {48 83 EC 38 4C 8B 0D 65 CB 1A 00 48 8D 54 24 20 4C 8B 05 61 CB 1A 00 0F 57 C0 66 0F 7F 44 24 20 E8 5B 0A 00 00 48 83 C4 38 C3}
    condition: 
        $a and not $b
}