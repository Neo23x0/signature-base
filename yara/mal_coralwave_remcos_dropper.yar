rule MAL_CoralWave_LenovoSPKVOL_RemcosMicDrop {
    meta:
        description = "CoralWave loader masquerading as Lenovo audio DLL. Drops Remcos RAT."
        author = "xstp"
        date = "2026-01-01"
        reference = "https://bazaar.abuse.ch/sample/050edadedd7947bc6418f7856a29df5b7b5550bf5eec7f5f37e9a7e1713036f6/"
        hash = "65302b435a5bc30e8f0215455679635ec50b5b1caba9e55f9258d17c7238be54"
        score = 85

    strings:
        $stub_1 = "BAyXuHpAGwdG8ebXF3GvZ32vO3ORY" ascii
        $stub_2 = "IK5HT1XPlj3LoFkKi3YC4QwYQs7s" ascii
        $stub_3 = "Xmk61GHDjDfjUjJhNjwDPXxM1Cdg" ascii

        $fake_1 = "GetVolumeLevel" ascii
        $fake_2 = "OpenSpeakerVolumeInterface" ascii
        $fake_3 = "SetMuteState" ascii

        $mutex = "Rmc-245S33" wide ascii
        $log_file = "logs.dat" wide ascii
        $audio_folder = "MicRecords" wide ascii

    condition:
        filesize < 5MB and uint16(0) == 0x5A4D and
        (
            2 of ($stub_*) or
            (2 of ($fake_*) and 1 of ($mutex, $log_file, $audio_folder))
        )
}
