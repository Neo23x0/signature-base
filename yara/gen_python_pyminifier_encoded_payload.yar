rule gen_python_pyminifier_encoded_payload
{
    meta:
        description = "Detects python code encoded by pyminifier. Used by the Machete malware as researched by ESET"
        author = "John Lambert @JohnLaTwC"
        date = "2019-12-16"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2019/08/ESET_Machete.pdf"
        reference2 = "https://github.com/liftoff/pyminifier"
        hash = "01df8765ea35db382d1dd67a502bf1d9647d8fe818ec31abff41c7e41c2816c0"
        hash = "15d201152a9465497a0f9dd6939e48315b358702c5e2a3c506ad436bb8816da7"
        hash = "ab91f76394ddf866cc0b315d862a19b57ded93be5dfc2dd0a81e6a43d0c5f301"
        hash = "b67256906d976aafb6071d23d1b3f59a1696f26b25ff4713b9342d41e656dfba"
        hash = "d5664c70f3543f306f765ea35e22829dbea66aec729e8e11edea9806d0255b7e"
        hash = "dd2b0e2c2cb8a83574248bda54ce472899b22eb602e8ebecafcce2c4355177fe"
        hash = "ed76bd136f40a23aeffe0aba02f13b9fea3428c19b715aafa6ea9be91e4006ca"

        hash = "b454179c13cb4727ae06cc9cd126c3379e2aded5c293af0234ac3312bf9bdad2"

        id = "d7297e6a-e1c7-57dd-a57f-a3b67face2f3"
    strings:
        $s1 = "exec(zlib.decompress(base64.b64decode('eJ"
        $s2 = "base64" fullword
        $s3 = "zlib" fullword

    condition:
    	filesize < 20KB
        and uint32be(0) == 0x696d706f // import
        and all of them
}
