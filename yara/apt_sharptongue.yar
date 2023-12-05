rule APT_SharpTongue_JS_SharpExt_Chrome_Extension : SharpTongue {
    meta:
        author = "threatintel@volexity.com"
        date = "2021-09-14"
        description = "A malicious Chrome browser extention used by the SharpTongue threat actor to steal mail data from a victim"
        reference = "https://www.volexity.com/blog/2022/07/28/sharptongue-deploys-clever-mail-stealing-browser-extension-sharpext/"
        hash1 = "1c9664513fe226beb53268b58b11dacc35b80a12c50c22b76382304badf4eb00"
        hash2 = "6025c66c2eaae30c0349731beb8a95f8a5ba1180c5481e9a49d474f4e1bb76a4"
        hash3 = "6594b75939bcdab4253172f0fa9066c8aee2fa4911bd5a03421aeb7edcd9c90c"
        memory_suitable = 1
        score = 85
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        id = "61b5176a-ff73-5fce-bc70-c9e09bb5afed"
    strings:
        $s1 = "\"mode=attach&name=\"" ascii
        $s2 = "\"mode=new&mid=\"" ascii
        $s3 = "\"mode=attlist\"" ascii
        $s4 = "\"mode=list\"" ascii
        $s5 = "\"mode=domain\"" ascii
        $s6 = "\"mode=black\"" ascii
        $s7 = "\"mode=newD&d=\"" ascii

        $mark1 = "chrome.runtime.onMessage.addListener" ascii
        $mark2 = "chrome.webNavigation.onCompleted.addListener" ascii

        $enc1 = "function BSue(string){" ascii
        $enc2 = "function BSE(input){" ascii
        $enc3 = "function bin2hex(byteArray)" ascii

        $xhr1 = ".send(\"mode=cd1" ascii
        $xhr2 = ".send(\"mode=black" ascii
        $xhr3 = ".send(\"mode=domain" ascii
        $xhr4 = ".send(\"mode=list" ascii

        $manifest1 = "\"description\":\"advanced font\"," ascii
        $manifest2 = "\"scripts\":[\"bg.js\"]" ascii
        $manifest3 = "\"devtools_page\":\"dev.html\"" ascii
    condition:
        (
            5 of ($s*) and
            all of ($mark*)
        ) or
        all of ($enc*) or
        3 of ($xhr*) or
        2 of ($manifest*)
}