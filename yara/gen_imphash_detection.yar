import "pe"
//import "hash"

rule MAL_Malware_Imphash_Mar23_1 : HIGHVOL {
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
        id = "fb398c26-e9ac-55f9-b605-6b763021e96a"
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
      id = "e1d4dde6-16ad-5495-b3a7-01a86c830761"
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

rule SUSP_Imphash_Mar23_2 : HIGHVOL {
    meta:
        description = "Detects imphash often found in malware samples (Zero hits with with search for 'imphash:x p:0' on Virustotal)"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2023-03-23"
        modified = "2023-11-25"
        score = 65
        hash = "12bf2795f4a140adbaa0af6ad4b2508d398d8ba69e9dadb155f800b10f7458c4"
        hash = "14ec56489fbcc3c7f1ef9a4d4a80ff302a5e233cdc4429a29c635a88fb1278d6"
        hash = "13731912823d6ce01c28a8d7d7f961505f461620bb35adbb409d4954ba1f4b8e"
        hash = "15e59cc5d7b83e63d40dbfd8406701cb4decd31353f68fda47238d073c87e4ea"
        hash = "13e5bb40be20b1a0bc28081ce7798f339c28c9652cb37b538c29872dfd0cd51d"
        hash = "16f963afdb30b38ba4b8b98ce56a37626e9fd87de9eba5f9903d2ba7f8a77788"
        hash = "168f22d02304ce66be88d2370c8fa7c7d9aa2ccf80f8e376edfeabfc9b96c73d"
        hash = "9e7701450dbcbd35083e34df935bd77a95735c4b441e0fc8eacd543a621f2fa5"
        hash = "51205c100702b21cce600692d69f3b108f49228e53f36678dd8b39434406526b"
        hash = "c9b48e8b0e7c6fa75886554659bc0529e454d84b29daa07bd4323aca9a33f607"
        hash = "ba5c06703bd3c093afa89e45d86aaf6c151fbaef44ebf3b65c97f3b376a88c72"
        hash = "7281afc138e8e898aee16d415cd02a29dc5dedda5b11c23934aac0ebd208373b"
        hash = "10a091b2468a8286f7b1a580d8923aef48856b43014e849035f05c4dbdc0a413"
        hash = "56c04e76427bd982be83799d0a435732193d7bf5a70cdeba5eb63eaf0d4ebb77"
        hash = "0aa8b7eddc4792a82f247702442c04e50173bd7712a4b596545916480942853b"
        hash = "627f043ad875c182682149653363b7f856dd618d169821b18df7bc9cdf6269d8"
        hash = "e1df460fd99c4f901859f3a8ec23b041ba9f4b79897dec349a96d6a27fb3e335"
        hash = "f10ecbd8031ce85b782c59682ff32301a65e0975687977688771f1057fb063d1"
        hash = "1bc7b8932b5b077b359c79e7ca664938b7a487a4e7e6b99d6647d6803bc677c5"
        hash = "01f81029a5e93cbfecfbc81cbd4a2ffd1bb1b6159e2a144a21e58caf8dab9661"
        hash = "cd33a71f71e2971667bacb0da71f2d36073777993b9581ec90bbf042162c3530"
        hash = "4aab991149cb2dc8c0c0a323af3acbbd73d6a22177910ef3af92b05ae7c9ae7b"
        hash = "df05fa3983c9e623388231d366dba4e435575ca53421d3f0bcb0fb346dd971d4"
        hash = "14de3584fe7108386f7637c2bd343f30341c0fa2102d52bb35ee772b5b7672f0"
        hash = "c4d9ad5cffd9aa13dfe3acbf0905810e28ff96d231541d7e209327ca5b0b24fe"
        hash = "5e0bed2269dc34c6cc2db30b0a53282e6debb85b3c90a857d1be4cfd06312211"
        hash = "3aa13e72382a2d7da592273b8c18a42106b65db528e16b6066646812e81555c4"
        hash = "244c4a930e3644ffb96bf3ab33e8c8c0f94ed9fe6a8b2fc45fc8e9b6471ef3a8"
        hash = "f00848b8edeeb5a668bf7e89e3f33f438b2f5d5cf130596a8ed2531e21be6d81"
        hash = "5b9348c24ff604e78d70464654e645b90dc695c7e0415959c443fe29cebc3c4e"
        id = "b739d540-5d9f-53b3-9e42-a514dc972e8d"
    condition:
        uint16(0) == 0x5A4D and (
            // no size limit as some samples are 20MB+ and the hash is calculated only on the header
            pe.imphash() == "e4290fa6afc89d56616f34ebbd0b1f2c" or
            pe.imphash() == "8abecba2211e61763c4c9ffcaa13369e" or
            pe.imphash() == "a64e048b98d051ae6e6b6334f77c95d3" or
            pe.imphash() == "359d89624a26d1e756c3e9d6782d6eb0" or
            pe.imphash() == "c2a87fabf96470db507b2e6b43bd92eb" or
            pe.imphash() == "62ec3dce1eba1b68f6a4511bb09f8c2c" or
            pe.imphash() == "5662cfcdfd9da29cb429e7528d5af81e" or
            pe.imphash() == "406c785a6e2c6970c1e8ed62877e197b" or
            pe.imphash() == "dbf687d6aa2a6cafe4349f7b0821a792" or
            pe.imphash() == "6dca3e9fb3928bbdb54dbce669943ec8" or
            pe.imphash() == "f1a539a5b71ad53ac586f053145f08ec" or
            pe.imphash() == "3a2003ea545fe942681da9e7683ebb58" or
            pe.imphash() == "a8286b574ff850cd002ea6282d15aa40" or
            pe.imphash() == "3c8577ca4bab2f95cc6fc73ef1895288" or
            pe.imphash() == "84706849fa809feaa385711a628be029" or
            pe.imphash() == "ba23a556ac1d6444f7f76feafd6c8867" or
            pe.imphash() == "95e6f8741083e0c7d9a63d45e2472360" or
            pe.imphash() == "774d797db707398fd2ef1979d02634d5" or
            pe.imphash() == "8c16c795b57934183422be5f6df7d891" or
            pe.imphash() == "98f67c550a7da65513e63ffd998f6b2e" or
            pe.imphash() == "e836076a09dba03e4d6faa46dda0fefc" or
            pe.imphash() == "ff63dc9c65eb25911a9bc535c8f06ad0" or
            pe.imphash() == "08b67a9663d3a8c9505f3b2561bbdd1c" or
            pe.imphash() == "135e92fc9902f3140f2e5a51458efdf0" or
            pe.imphash() == "4753904c40d638a1bc745c65b88291d5" or
            pe.imphash() == "0f44bf2b3b0b8d5ecae5689ff1d0e90d" or
            pe.imphash() == "c4c9ecfc26ca516a80b8f6f5b2bdb7e6" or
            pe.imphash() == "46ad3d954e527f769e37017b3e128039" or
            pe.imphash() == "802dcac7aab948c19738ba3df9f356d9" or
            pe.imphash() == "b36a21279375c40e6f4c1ea347f906de" or
            pe.imphash() == "77a185e903c5527243ef219b003bfd38" or
            pe.imphash() == "12a30b523ac71a3cbe9145c89400dd7f" or
            pe.imphash() == "cc40fefa3af5cd00cc28dbd874038a4d" or
            pe.imphash() == "3d8c26f4cb1782a87c3bb42796fb6b85" or
            pe.imphash() == "2f4ddcfebbcad3bacadc879747151f6f" or
            pe.imphash() == "76812f441b0ed9d3cc0748af25d689a3" or
            pe.imphash() == "9a06f0024c1694774ae97311608bab5b" or
            pe.imphash() == "481f47bbb2c9c21e108d65f52b04c448" or
            pe.imphash() == "286870a926664a5129b8b68ed0d4a8eb" or
            pe.imphash() == "a0db151d55761167d93eba72d3d94b32" or
            pe.imphash() == "663243fe4d94e1304b265ce4011cd01b" or
            pe.imphash() == "f24e64014af9015dc25262e5076fe61f" or
            pe.imphash() == "b7d08302c927428e16a2ad8d18b9d2b7" or
            pe.imphash() == "352063077f27a851dc2b08e15f08105e" or
            pe.imphash() == "b0b97d1a91a2730b3daa8bbb2e86b402" or
            pe.imphash() == "bc96f1c981700752dc2cf9553da99eb6" or
            pe.imphash() == "f68ddef5f29b66bbd543e947c8743bb0" or
            pe.imphash() == "6dfbc160505aa2f7205766eaa6fe72a1" or
            pe.imphash() == "a202429ffe8d8c8b722572cffd5681a7" or
            pe.imphash() == "342a3708d93b6b819b7b1a768201a747" or
            pe.imphash() == "cdc00badc7162acde9bb032e793ac137" or
            pe.imphash() == "be19e18d6a8b41631d40059031a928bb" or
            pe.imphash() == "0c54f96a844b02689687407de9b6663e" or
            pe.imphash() == "fa5f28e70130a452b7c0a51db5544ef9" or
            pe.imphash() == "2e5708ae5fed0403e8117c645fb23e5b" or
            pe.imphash() == "8d92fa1956a6a631c642190121740197" or
            pe.imphash() == "dc73a9bd8de0fd640549c85ac4089b87"
        )
}

rule SUSP_Imphash_Mar23_3 {
    meta:
        description = "Detects imphash often found in malware samples (Maximum 0,25% hits with search for 'imphash:x p:0' on Virustotal) = 99,75% hits"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2023-03-23"
        modified = "2025-08-15"
        reference = "Internal Research"
        score = 45
        hash = "b5296cf0eb22fba6e2f68d0c9de9ef7845f330f7c611a0d60007aa87e270c62a"
        hash = "5a5a5f71c2270cea036cd408cde99f4ebf5e04a751c558650f5cb23279babe6d"
        hash = "481b0d9759bfd209251eccb1848048ebbe7bd2c87c5914a894a5bffc0d1d67ff"
        hash = "716ba6ea691d6a391daedf09ae1262f1dc1591df85292bff52ad76611666092d"
        hash = "800d160736335aafab10503f7263f9af37a15db3e88e41082d50f68d0ad2dabd"
        hash = "416155124784b3c374137befec9330cd56908e0e32c70312afa16f8220627a52"
        hash = "21899e226502fe63b066c51d76869c4ec5dbd03570551cea657d1dd5c97e7070"
        hash = "0461830e811d3831818dac5a67d4df736b4dc2e8fb185da439f9338bdb9f69c3"
        hash = "773edc71d52361454156dfd802ebaba2bb97421ce9024a7798dcdee3da747112"
        hash = "fe53b9d820adf3bcddf42976b8af1411e87d9dfd9aa479f12b2db50a5600f348"
        id = "eb91e700-6478-5085-a393-a7b342c0eb4f"
    condition:
        uint16(0) == 0x5A4D and (
            // no size limit as some samples are 20MB+ and the hash is calculated only on the header
            //pe.imphash() == "87bed5a7cba00c7e1f4015f1bdae2183" or // UPX imphash
            //pe.imphash() == "09d0478591d4f788cb3e5ea416c25237" or // PECompact imphash
            // pe.imphash() == "6ed4f5f04d62b18d96b26d6db7c18840" or // too many fp by now
            pe.imphash() == "afcdf79be1557326c854b6e20cb900a7" or
            pe.imphash() == "fc6683d30d9f25244a50fd5357825e79" or
            pe.imphash() == "2c5f2513605e48f2d8ea5440a870cb9e" or
            pe.imphash() == "0b5552dccd9d0a834cea55c0c8fc05be"
        )
        and pe.number_of_signatures == 0
}
