rule SUSP_Doc_WindowsInstaller_Call_Feb22_1 {
    meta:
        author = "Nils Kuhnert"
        date = "2022-02-26"
        description = "Triggers on docfiles executing windows installer. Used for deploying ThinBasic scripts."
        tlp = "white"
        reference = "https://inquest.net/blog/2022/02/24/dangerously-thinbasic"
        reference2 = "https://twitter.com/threatinsight/status/1497355737844133895"
        id = "8f2e8f91-74e0-5574-9c0a-1479d6114212"
    strings:
        $ = "WindowsInstaller.Installer$"
        $ = "CreateObject"
        $ = "InstallProduct"
    condition:
        uint32be(0) == 0xd0cf11e0 and all of them
}
