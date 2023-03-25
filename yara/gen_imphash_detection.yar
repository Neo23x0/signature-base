import "pe"
//import "hash"

rule MAL_Malware_Imphash_Mar23_1 {
    meta:
        description = "Detects malware by known bad imphash or rich_pe_header_hash"
        reference = "https://yaraify.abuse.ch/statistics/"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp"
        date = "2023-03-20"
        modified = "2023-03-22"
        score = 75
        hash = "167dde6bd578cbfcc587d5853e7fc2904cda10e737ca74b31df52ba24db6e7bc"
        hash = "0a25a78c6b9df52e55455f5d52bcb3816460001cae3307b05e76ac70193b0636"
        hash = "d87a35decd0b81382e0c98f83c7f4bf25a2b25baac90c9dcff5b5a147e33bcc8"
        hash = "5783bf969c36f13f4365f4cae3ec4ee5d95694ff181aba74a33f4959f1f19e8b"
        hash = "4ca925b0feec851d787e7ee42d263f4c08b0f73f496049bdb5d967728ff91073"
        hash = "9c2d2fa9c32fdff1828854e8cc39160dae73a4f90fb89b82ef6d853b63035663"
        hash = "2c53d58f30b2ee1a2a7746e20f136c34d25d0214261783fc67e119329d457c2a"
        hash = "5e83747015b0589b4f04b0db981794adf53274076c1b4acf717e3ff45eca0249"
        hash = "ceaa0af90222ff3a899b9a360f6328cbda9ec0f5fbd18eb44bdc440470bb0247"
        hash = "82fb1ba998dfee806a513f125bb64c316989c36c805575914186a6b45da3b132"
        hash = "cb41d2520995abd9ba8ccd42e53d496a66da392007ea6aebd4cbc43f71ad461a"
        hash = "c7bd758506b72ee6db1cc2557baf745bf9e402127d8e49266cc91c90f3cf3ed5"
        hash = "e6e0d60f65a4ea6895ff97df340f6d90942bbfa402c01bf443ff5b4641ff849f"
        hash = "e8ddef9fa689e98ba2d48260aea3eb8fa41922ed718b7b9135df6426b3ddf126"
        hash = "ad57d77aba6f1bf82e0affe4c0ae95964be45fb3b7c2d6a0e08728e425ecd301"
        hash = "483df98eb489899bc89c6a0662ca8166c9b77af2f6bedebd17e61a69211843d9"
        hash = "a65ed85851d8751e6fe6a27ece7b3879b90866a10f272d8af46fb394b46b90a9"
        hash = "09081e04f3228d6ef2efc1108850958ed86026e4dfda199852046481f4711565"
        hash = "1b2c9054f44f7d08cffe7e2d9127dbd96206ab2c15b63ebf6120184950336ae1"
        hash = "257887d1c84eb15abb2c3c0d7eb9b753ca961d905f4979a10a094d0737d97138"
        hash = "1cbad8b58dbd1176e492e11f16954c3c254b5169dde52b5ad6d0d3c51930abf8"
        hash = "a9897fd2d5401071a8219b05a3e9b74b64ad67ab75044b3e41818e6305a8d7b9"
        hash = "aeac45fbc5d2a59c9669b9664400aeaf6699d76a57126d2f437833a3437a693e"
        hash = "7b4c4d4676fab6c009a40d370e6cb53ea4fd73b09c23426fbaccc66d652f2a00"
        hash = "b07f6873726276842686a6a6845b361068c3f5ce086811db05c1dc2250009cd0"
        hash = "d1b3afebcacf9dd87034f83d209b42b0d79e66e08c0a897942fbe5fbd6704a0e"
        hash = "074d52be060751cf213f6d0ead8e9ab1e63f055ae79b5fcbe4dd18469deea12b"
        hash = "84d1fdef484fa9f637ae3d6820c996f6c5cf455470e8717ad348a3d80d2fb8e0"
        hash = "437da123e80cfd10be5f08123cd63cfc0dc561e17b0bef861634d60c8a134eda"
        hash = "f76c36eb22777473b88c6a5fc150fd9d6b5fac5b2db093f0ccd101614c46c7e7"
        hash = "5498b7995669877a410e1c2b68575ca94e79014075ef5f89f0f1840c70ebf942"
        hash = "af4e633acfba903e7c92342b114c4af4e694c5cfaea3d9ea468a4d322b60aa85"
        hash = "d7d870f5afab8d4afa083ea7d7ce6407f88b0f08ca166df1a1d9bdc1a46a41b3"
        hash = "974209d88747fbba77069bb9afa9e8c09ee37ae233d94c82999d88dfcd297117"
        hash = "f2d99e7d3c59adf52afe0302b298c7d8ea023e9338c2870f74f11eaa0a332fc4"
        hash = "b32c93be9320146fc614fafd5e6f1bb8468be83628118a67eb01c878f941ee5d"
        hash = "bbd99acc750e6457e89acbc5da8b2a63b4ef01d4597d160e9cde5dc8bd04cf74"
        hash = "dbff5ca3d1e18902317ab9c50be4e172640a8141e09ec13dcca986f2ec1dc395"
        hash = "3ee1741a649f0b97bbeb05b6f9df97afda22c82e1e870177d8bdd34141ef163c"
        hash = "222096fc800c8ea2b0e530302306898b691858324dbe5b8357f90407e9665b85"
        hash = "b9995d1987c4e8b6fb30d255948322cfad9cc212c7f8f4c5db3ac80e23071533"
        hash = "a6a92ea0f27da1e678c15beb263647de43f68608afe82d6847450f16a11fe6c0"
        hash = "866e3ea86671a62b677214f07890ddf7e8153bec56455ad083c800e6ab51be37"
    strings:
        $fp1 = "Win32 Cabinet Self-Extractor" wide
        $fp2 = "EXTRACTOPT" ascii fullword
    condition:
        uint16(0) == 0x5A4D and (
            // no size limit as some samples are 20MB+ (ceaa0af90222ff3a899b9a360f6328cbda9ec0f5fbd18eb44bdc440470bb0247) and the hash is calculated only on the header
            pe.imphash() == "9ee34731129f4801db97fd66adbfeaa0" or
            pe.imphash() == "f9e8597c55008e10a8cdc8a0764d5341" or
            pe.imphash() == "0a76016a514d8ed3124268734a31e2d2" or
            pe.imphash() == "d3cbd6e8f81da85f6bf0529e69de9251" or
            pe.imphash() == "d8b32e731e5438c6329455786e51ab4b" or
            pe.imphash() == "cdf5bbb8693f29ef22aef04d2a161dd7" or
            pe.imphash() == "890e522b31701e079a367b89393329e6" or
            pe.imphash() == "bf5a4aa99e5b160f8521cadd6bfe73b8" or
            pe.imphash() == "646167cce332c1c252cdcb1839e0cf48" or
            pe.imphash() == "9f4693fc0c511135129493f2161d1e86" or
            pe.imphash() == "b4c6fff030479aa3b12625be67bf4914" // or

            // these have lots of hits on abuse.ch but none on VT? (except for my one test upload) honeypot collected samples?
            //pe.imphash() == "2c2ad1dd2c57d1bd5795167a7236b045" or
            //pe.imphash() == "46f03ef2495b21d7ad3e8d36dc03315d" or
            //pe.imphash() == "6db997463de98ce64bf5b6b8b0f77a45" or
            //pe.imphash() == "c9246f292a6fdc22d70e6e581898a026" or
            //pe.imphash() == "c024c5b95884d2fe702af4f8984b369e" or
            //pe.imphash() == "4dcbc0931c6f88874a69f966c86889d9" or
            //pe.imphash() == "48521d8a9924bcb13fd7132e057b48e1" or

            // rich_pe_header_hash:b6321cd8142ea3954c1a27b162787f7d p:2+ has 238k hits on VT including many files without imphash (e.g. e193dadf0405a826b3455185bdd9293657f910e5976c59e960a0809b589ff9dc) due to being corrupted?
            // zero hits with p:0
            // disable bc it's killing performance
            //hash.md5(pe.rich_signature.clear_data) == "b6321cd8142ea3954c1a27b162787f7d"
        )
        and not 1 of ($fp*)
}


rule HKTL_Imphashes_Aug22_1 {
   meta:
      description = "Detects different hacktools based on their imphash"
      author = "Florian Roth"
      reference = "Internal Research"
      score = 80
      date = "2022-08-17"
      modified = "2023-03-21"
   condition:
      uint16(0) == 0x5a4d and (
            pe.imphash() == "bcca3c247b619dcd13c8cdff5f123932" or // PetitPotam
            pe.imphash() == "3a19059bd7688cb88e70005f18efc439" or // PetitPotam
            pe.imphash() == "bf6223a49e45d99094406777eb6004ba" or // PetitPotam
            pe.imphash() == "0c106686a31bfe2ba931ae1cf6e9dbc6" or // Mimikatz
            pe.imphash() == "0d1447d4b3259b3c2a1d4cfb7ece13c3" or // Mimikatz
            pe.imphash() == "1b0369a1e06271833f78ffa70ffb4eaf" or // Mimikatz
            pe.imphash() == "4c1b52a19748428e51b14c278d0f58e3" or // Mimikatz
            pe.imphash() == "4d927a711f77d62cebd4f322cb57ec6f" or // Mimikatz
            pe.imphash() == "66ee036df5fc1004d9ed5e9a94a1086a" or // Mimikatz
            pe.imphash() == "672b13f4a0b6f27d29065123fe882dfc" or // Mimikatz
            pe.imphash() == "6bbd59cea665c4afcc2814c1327ec91f" or // Mimikatz
            pe.imphash() == "725bb81dc24214f6ecacc0cfb36ad30d" or // Mimikatz
            pe.imphash() == "9528a0e91e28fbb88ad433feabca2456" or // Mimikatz
            pe.imphash() == "9da6d5d77be11712527dcab86df449a3" or // Mimikatz
            pe.imphash() == "a6e01bc1ab89f8d91d9eab72032aae88" or // Mimikatz
            pe.imphash() == "b24c5eddaea4fe50c6a96a2a133521e4" or // Mimikatz
            pe.imphash() == "d21bbc50dcc169d7b4d0f01962793154" or // Mimikatz
            pe.imphash() == "fcc251cceae90d22c392215cc9a2d5d6" or // Mimikatz
            pe.imphash() == "23867a89c2b8fc733be6cf5ef902f2d1" or // JuicyPotato
            pe.imphash() == "a37ff327f8d48e8a4d2f757e1b6e70bc" or // JuicyPotato
            pe.imphash() == "f9a28c458284584a93b14216308d31bd" or // JuicyPotatoNG
            pe.imphash() == "6118619783fc175bc7ebecff0769b46e" or // RoguePotato
            pe.imphash() == "959a83047e80ab68b368fdb3f4c6e4ea" or // RoguePotato
            pe.imphash() == "563233bfa169acc7892451f71ad5850a" or // RoguePotato
            pe.imphash() == "87575cb7a0e0700eb37f2e3668671a08" or // RoguePotato
            pe.imphash() == "13f08707f759af6003837a150a371ba1" or // Pwdump
            pe.imphash() == "1781f06048a7e58b323f0b9259be798b" or // Pwdump
            pe.imphash() == "233f85f2d4bc9d6521a6caae11a1e7f5" or // Pwdump
            pe.imphash() == "24af2584cbf4d60bbe5c6d1b31b3be6d" or // Pwdump
            pe.imphash() == "632969ddf6dbf4e0f53424b75e4b91f2" or // Pwdump
            pe.imphash() == "713c29b396b907ed71a72482759ed757" or // Pwdump
            pe.imphash() == "749a7bb1f0b4c4455949c0b2bf7f9e9f" or // Pwdump
            pe.imphash() == "8628b2608957a6b0c6330ac3de28ce2e" or // Pwdump
            pe.imphash() == "8b114550386e31895dfab371e741123d" or // Pwdump
            pe.imphash() == "94cb940a1a6b65bed4d5a8f849ce9793" or // PwDumpX
            pe.imphash() == "9d68781980370e00e0bd939ee5e6c141" or // Pwdump
            pe.imphash() == "b18a1401ff8f444056d29450fbc0a6ce" or // Pwdump
            pe.imphash() == "cb567f9498452721d77a451374955f5f" or // Pwdump
            pe.imphash() == "730073214094cd328547bf1f72289752" or // Htran
            pe.imphash() == "17b461a082950fc6332228572138b80c" or // Cobalt Strike beacons
            pe.imphash() == "dc25ee78e2ef4d36faa0badf1e7461c9" or // Cobalt Strike beacons
            pe.imphash() == "819b19d53ca6736448f9325a85736792" or // Cobalt Strike beacons
            pe.imphash() == "829da329ce140d873b4a8bde2cbfaa7e" or // Cobalt Strike beacons
            pe.imphash() == "c547f2e66061a8dffb6f5a3ff63c0a74" or // PPLDump
            pe.imphash() == "0588081ab0e63ba785938467e1b10cca" or // PPLDump
            pe.imphash() == "0d9ec08bac6c07d9987dfd0f1506587c" or // NanoDump
            pe.imphash() == "bc129092b71c89b4d4c8cdf8ea590b29" or // NanoDump
            pe.imphash() == "4da924cf622d039d58bce71cdf05d242" or // NanoDump
            pe.imphash() == "e7a3a5c377e2d29324093377d7db1c66" or // NanoDump
            pe.imphash() == "9a9dbec5c62f0380b4fa5fd31deffedf" or // NanoDump
            pe.imphash() == "af8a3976ad71e5d5fdfb67ddb8dadfce" or // NanoDump
            pe.imphash() == "0c477898bbf137bbd6f2a54e3b805ff4" or // NanoDump
            pe.imphash() == "0ca9f02b537bcea20d4ea5eb1a9fe338" or // NanoDump
            pe.imphash() == "3ab3655e5a14d4eefc547f4781bf7f9e" or // NanoDump
            pe.imphash() == "e6f9d5152da699934b30daab206471f6" or // NanoDump
            pe.imphash() == "3ad59991ccf1d67339b319b15a41b35d" or // NanoDump
            pe.imphash() == "ffdd59e0318b85a3e480874d9796d872" or // NanoDump
            pe.imphash() == "0cf479628d7cc1ea25ec7998a92f5051" or // NanoDump
            pe.imphash() == "07a2d4dcbd6cb2c6a45e6b101f0b6d51" or // NanoDump
            pe.imphash() == "d6d0f80386e1380d05cb78e871bc72b1" or // NanoDump
            pe.imphash() == "38d9e015591bbfd4929e0d0f47fa0055" or // HandleKatz
            pe.imphash() == "0e2216679ca6e1094d63322e3412d650" or // HandleKatz
            pe.imphash() == "ada161bf41b8e5e9132858cb54cab5fb" or // DripLoader
            pe.imphash() == "2a1bc4913cd5ecb0434df07cb675b798" or // DripLoader
            pe.imphash() == "11083e75553baae21dc89ce8f9a195e4" or // DripLoader
            pe.imphash() == "a23d29c9e566f2fa8ffbb79267f5df80" or // DripLoader
            pe.imphash() == "4a07f944a83e8a7c2525efa35dd30e2f" or // CreateMiniDump
            pe.imphash() == "767637c23bb42cd5d7397cf58b0be688" or // UACMe Akagi
            pe.imphash() == "14c4e4c72ba075e9069ee67f39188ad8" or // UACMe Akagi
            pe.imphash() == "3c782813d4afce07bbfc5a9772acdbdc" or // UACMe Akagi
            pe.imphash() == "7d010c6bb6a3726f327f7e239166d127" or // UACMe Akagi
            pe.imphash() == "89159ba4dd04e4ce5559f132a9964eb3" or // UACMe Akagi
            pe.imphash() == "6f33f4a5fc42b8cec7314947bd13f30f" or // UACMe Akagi
            pe.imphash() == "5834ed4291bdeb928270428ebbaf7604" or // UACMe Akagi
            pe.imphash() == "5a8a8a43f25485e7ee1b201edcbc7a38" or // UACMe Akagi
            pe.imphash() == "dc7d30b90b2d8abf664fbed2b1b59894" or // UACMe Akagi
            pe.imphash() == "41923ea1f824fe63ea5beb84db7a3e74" or // UACMe Akagi
            pe.imphash() == "3de09703c8e79ed2ca3f01074719906b" or // UACMe Akagi
            pe.imphash() == "a53a02b997935fd8eedcb5f7abab9b9f" or // WCE
            pe.imphash() == "e96a73c7bf33a464c510ede582318bf2" or // WCE
            pe.imphash() == "32089b8851bbf8bc2d014e9f37288c83" or // Sliver Stagers
            pe.imphash() == "09D278F9DE118EF09163C6140255C690" or // Dumpert
            pe.imphash() == "03866661686829d806989e2fc5a72606" or // Dumpert
            pe.imphash() == "e57401fbdadcd4571ff385ab82bd5d6d" or // Dumpert
            pe.imphash() == "84B763C45C0E4A3E7CA5548C710DB4EE" or // SysmonEnte
            pe.imphash() == "19584675d94829987952432e018d5056" or // SysmonQuiet
            pe.imphash() == "330768a4f172e10acb6287b87289d83b" // ShaprEvtMute Hook
      )
}

