
import "pe"

rule SUSP_Unsigned_OSPPSVC {
   meta:
      description = "Detects a suspicious unsigned office software protection platform service binary"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.welivesecurity.com/2019/09/24/no-summer-vacations-zebrocy/"
      date = "2019-09-26"
      hash1 = "5294a730f1f0a176583b9ca2b988b3f5ec65dad8c6ebe556b5135566f2c16a56"
      id = "0e312237-0c82-59da-b62d-56065c6075f0"
   strings:
      /* FileDescription Microsoft Office Software Protection Platform Service */
      $sc1 = { 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63
               00 72 00 69 00 70 00 74 00 69 00 6F 00 6E 00 00
               00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F
               00 66 00 74 00 20 00 4F 00 66 00 66 00 69 00 63
               00 65 00 20 00 53 00 6F 00 66 00 74 00 77 00 61
               00 72 00 65 00 20 00 50 00 72 00 6F 00 74 00 65
               00 63 00 74 00 69 00 6F 00 6E 00 20 00 50 00 6C
               00 61 00 74 00 66 00 6F 00 72 00 6D 00 20 00 53
               00 65 00 72 00 76 00 69 00 63 00 65 }
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and $sc1 and pe.number_of_signatures < 1
}


rule SUSP_PE_Signed_by_Suspicious_Entitiy_Mar23
{
    meta:
        author = "Arnim Rupp (https://github.com/ruppde)"
        date_created = "2023-03-06"
        description = "Find driver signed by suspicious company (see references)"
        score = 60
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        reference = "https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware"
        reference = "https://news.sophos.com/en-us/2022/12/13/signed-driver-malware-moves-up-the-software-trust-chain/"
        reference = "https://www.sentinelone.com/labs/driving-through-defenses-targeted-attacks-leverage-signed-malicious-microsoft-drivers/"
        hash = "2fb7a38e69a88e3da8fece4c6a1a81842c1be6ae9d6ac299afa4aef4eb55fd4b"
        hash = "9a24befcc0c0926abb49d43174fe25c2469cca06d6ab3b5000d7c9d434c42fe9"
        hash = "9ad716f0173489e74fefe086000dfbea9dc093b1c3460bed9cdb82f923073806"
        hash = "a007c8c6c1aecfff1065429fef691e7ae1c0ce20012a113f01ac57c61564a627"
        hash = "fbe82a21939d04735aa3bbf23fbabd45ac491a143396e8e62ee20509c1257918"
        hash = "d12c6ea0a86c58ea2d80d1dc9b793ba28a0db92c72bb5b6f4ee2b800fe42091b"
        hash = "4cf31d000f1542690cbc0ace41e4166651a71747978dc408e3cce32e82713917"
        hash = "e1adaea335b20d4d2e351f7bea496cd40cb379376900434866db342f851d9ddf"
        hash = "031408cf2f2c282bcc05066356fcc2bb862b7e3c504ab7ffb0220bea341404a5"
        hash = "2f13d4e1bd35f6c0ad0978af19006c17193cf3d42b71cba763cca68f7e9d7fca"
        hash = "cb40a5dc4f6a27b1dc50176770026b827f8baa05fa95a98a4e880652f6729d96"
        hash = "a7591b7384bd10eb934f0dac8dcbfdff8c352eba2309f4d75553567fa2376efa"
        hash = "d517ce5f132b3274f0b9783a5b0c37d1d648e6079874960af24ca764b011c042"
        hash = "aeec903013d5b66f0ae1c6fa50bb892759149c1cec86db8089a4e60482e02250"
        hash = "0d22828724cb7fbc6cef7f98665d020867d2eb801cff2c21f2e97e481040499b"
        hash = "4b2e874d51d332fd840dadd463a393f9f019de46e49de73be910b9b1365e4e4e"
        hash = "3839c0925acf836238ba9a0c5798b84b1c089a8353cc27ae7e6b75d273b539e3"
        hash = "c470f519fb0d4a2862035e0d9e105a0a6918adc51842b12ad14b5b5f34879963"
        hash = "cc6d174bc86f84f5a4c516e9c04947e2fecc0509a84748ea80576aeee5950aed"
        hash = "6fe8df70254f9b5f53452815f0163cb2ffb2d7f0f5aefbb9b149ad1be9284e31"
        hash = "4cde473fb68fa9b2709ea8a23349cd2fce8b8b3991b9fea12f95d12292b8aa7a"
        hash = "e2c40c8dd60bb395807c39c76bfdf5cd158ebefd2a47ad3306a96662c50057c0"
        hash = "9c12b09b529fa517eaeb49df22527d7563b5432d62776166048d97f83b2dce5c"
        hash = "5a4e17287f3dceb5bf1ed411e5fdd7e8692aebf2a19b334327733fc1c158b0ba"
        hash = "c42964aa7fa354b1a285bdbcbd9e84b6bdd8813ff9361955e0e455d032803cce"
        hash = "ffd6955bf40957a35901d82fd5b96d0cb191b651d3eca7afa779eebfed0d9f7e"
        hash = "f6874335eb0d611d47b2ec99a6b70f7b373a50d8d1f62d290b06174f42279f36"
        hash = "4e6d7fd70a143f19429fead2c14779aea9d9140e270bb9e91e47fa601643e40e"
        hash = "7b0e4aae37660b1099de69f4c14f5d976f260c64a4af8495ff1415512a6268ba"
        hash = "db45cbfb094f3e1ebf1cb3880087a24d4e771cc43ba48ad373e6283cbe7391da"
        hash = "813edc804f59a97ec9391ea0db4b779443bd8daf1e64c622b5e3c9a22ee9c2e0"
        hash = "8d66a4b7c2ae468390d32e5e70b3f9b7cb796b54b7c404cde038de9786be8d1d"
        hash = "85936141f0f32cf8f3173655e7200236d1fce6ef9c2616fd2b19ae7951c644c5"
        hash = "b5fc0cc9980fc594a18682d2b0d5b0d0f19ba7a35d35106693a78f4aaba346ac"
        hash = "7aae36c5ffa8baaab19724dae051673ddafd36107cb61c505926bfceaadcd516"
        hash = "5d0228a0d321e2ddac5502da04ca7a2b2744f3dc1382daa5f02faa9da5aface1"
        hash = "2af1ac8bc8ae8d7cad703d2695f2f6c6d79b82eebba01253a8ec527e11e83fcd"
        hash = "c8f9e1ad7b8cce62fba349a00bc168c849d42cfb2ca5b2c6cc4b51d054e0c497"
        hash = "0e339c9c8a6702b32ee9f2915512cbeb3391ced74b16c7e0aed9b1a80c9e58c8"
        hash = "80bdeaa4f162c65722b700e4ffba31701d0d634f5533e59bf3885dc67ee92f3f"
        hash = "4570f64f2000bdaf53aec0fc2214c8bd54e0f5cb75987cdf1f8bda6ea5fc4c43"
        hash = "a9c906bde6c8a693d5d46c9922dafa2dfd2dec0fff554f3f6a953c2e36d3f7b7"
        hash = "520df3ddd7c9ecdeecac8e443d75ac258c26b45d37ecec22501afdda797f6a0a"
        hash = "4d3e0f27a7bcfd4b442b489c63641af22285ca41c6d56ac1db734196ab10b315"
        hash = "5000b3b1d593ba40cc10098644af1551259590ac67d3726fab2be87aad460877"
        hash = "7c27bd6104fc67dd16e655f3bf67c2abd8b5bf2a693ba714ac86904c5765b316"
        hash = "34b1234eab7ff10edde9e09ecf73c5e4bfe9ee047ccfdb43de1e1f6155afad0c"
        hash = "f6fe2cc9ea31f85273c26e84422137df21cfce4b9e972b0db94fe3a67b54f6ca"
        hash = "ec4d0828196926bd36325f4b021895d37cfaaa024f754b36618c78b2574f0122"
        hash = "2a89f263d85da8fb0c934d287b5b524744479741491c740aaa46ac9f694f6d1b"
        hash = "c8d0122974fc10a7d82c62f3e6573a94379c026dd741fd73497afdf36d3929be"
        hash = "0345f71876bc4c888deadba7284565a8da112901f343e54b8522279968abd1b2"
        hash = "6c0e10650be9e795dc6adfbe8aad8c1c3a8657e4c45cb82a7d5188ee24021ca0"
        hash = "90b8d9c4ff3e4e0a0342e0d91da3a25be2fead29f3b32888bb35f8575845259d"
        hash = "0310400c9e62c3fe08dc6506313e26f7c5c89035c81b0141ce57543910c1c42e"
        hash = "b0da0316443f878aad0b3d9764b631d5df60e119ab59324c37640da1b431893a"
        hash = "cc4bd06f27a5f266bc8825a08e5f45dcaa4352eb6d69214b5037d28cc8de6908"
        hash = "2d4b7c6931203923db9a07e1ac92124e799f3747ab20e95e191e99c7b98f3fbd"
        hash = "b5965de0d883fd0602037f3dc26fd4461e6328612f1a34798cff0066142e13c4"
        hash = "86ce17183ddf32379db53ecaedefe0811252165b05cd326025bb8eca2e6a25d7"
        hash = "6edca16d5aa751aa4c212e6477121d51e4d9b9432896d25b41938a27a554bbe7"
        hash = "cdd8966e0cf08a6578e34de7498a44413a6adabae04d81ef3129f26305966db2"
        hash = "df890974589ed2435f53b8c8f147a06752f1b37404afd4431362c1938fcb451e"
        hash = "3e05d8abaaa95af359e5b09efb30546d0aa693859ebc8a0970a2641556ea644c"
        hash = "1c8ddf4b9c99c8f1945abf1527c7fa93141430680ac156a405d9a927d32f3b5e"
        hash = "5d2ed5930ab1a650f9fb9293f49a9f35737139fdfa9f14e46a07e5d4d721ae3e"
        hash = "18834de3e4844a418970c2184cc78c2d7cb61d18e9f7c7c0e88e994b4212edc5"
        hash = "a6b6fc94d8e582059af0fe30c2c93c687fccd5a0073a6a26a2cd097ea96adc7c"
        hash = "28b40fa160c915f13f046d36725c055d6c827a4d28674ea33c75a9b410321290"
        hash = "efab0fbf77dc67a792efd1fe2b3f46bbdfdee30a9321acc189c53a6c5e90f05c"
        hash = "348781221d1a2886923de089d1b7b12c32cfdd38628b71203da925b5736561e9"
        hash = "a1a5f410e6eab2445d64bfcd742fe1a802a0a2d9af45c7ab398f84894dd5dc3d"
        hash = "9de05ce0d9e9de05ebdc2859a5156f044f98bb180723f427a779d36b1913e5d3"
        hash = "eeff7e85c50a7f11fc8a99f7048953719fb1d2a6451161a0796eac43119ece21"
        hash = "383cc025800a3b3d089f7697e78fe4d5695a8d1ee26dcad0b0956ad6800ccae4"
        hash = "41be6f393cea4d8d5869fff526c4d75ec66c855f7e9c176042c39b9682ea9c14"
        hash = "71552e65433c8bbf14e5bcbc35a708bc10d6fded740c5f4783edce84aea4aabf"
        hash = "3c1b3e8666b58a78c70f36ed557c7ecc52e84457e87e5884b42e5cd9e8c1a303"
        hash = "4288d7113031151a2636a164c0dc6fce78c86f322271afec9ef2d4b54494c334"
        hash = "f73a39332be393a9bc23ec27ff6d025bc90d7320dde97f37cc585ecf6c0436a2"
        hash = "018f5103635992aa9ddc1c46cafe2b7ba659fcfbc8f8ab29dcea28e155b033ee"
        hash = "fe650fc138dcfbbd4ab6aa5718bf3cd36f50898ae19d3aceaa12f7d4f39d0b43"
        hash = "fa21b39cd5a24ba35433e90cae486454b7400b50e7f7f5c190fdbec6704b4352"
        hash = "3dd36c798cc89bfad7cdbf58d7da90ba113fe043ca46bdbcab7ae7fb9dc2f42b"
        hash = "674f4444f0de5c81c766c376a65fbdf1f7116228a61c71ffb504995c9e160183"
        hash = "cd3d25b2842bb2d6a5580f72e819acd344ce7f3a2478fb6d53ff668ad6531228"
        hash = "1668f4eb8a85914db46ff308b9f8a5040a024acc93259dfc004ea2b80ab6bcf1"
        hash = "4f31cab6c011b79bf862bb6acea3086308b0576afe33affdb09039c97e723beb"
        hash = "6b0ff48b8113076d2875edb7bea7f120b7b9d9a990ae296a5b5a95660ae7edfc"
        hash = "956a00dd6382e83d3f7490378ae98e4fc8d9b8ec2cd549519f007091e3ccce1f"
        hash = "8c7f938cf55728d8d41a7fa6b9953c4f81cf05ed3d7b7435ec8999e130257f7f"
        hash = "427ee4d4d18fc0c1196326215e94947f7d8c03794de36d0127231690bf5bf3c0"
        hash = "b6f3ece5bf7b9f6ecf99104d3c76b9007106fad98d20500956dd1e42d4ec5e8d"
        hash = "47a0ad6150c5a1de4c788827662a9cafbd2816a7d32be2028721e49a464acbed"
        hash = "8743ac81384fd10c0459f3574489d626e13c95dd73274dcf1d872bcd3630b9e8"
        hash = "a1755415a12f85bea3f65807860f902cf41e56b0ab2c155ac742af3166ef1dfd"
        hash = "3f5a91500bfade2d9708e1fbe76ae81dacdb7b0f65f335fee598546ccfc267e3"
        hash = "5be43b773dbde6542d6a0d53cd6616ea95a49dd38659edc6ba0d580a0d9777ab"
        hash = "90e080a63916c768b0b65787fe5695fd903d44e1b0b688d06c14988ba30b5ea7"
        hash = "d1184ee3f26919b8f5a4b1a6d089f14e79e0c89260590156111f72a979c8e446"
        hash = "c13ddd2bafcfdfc00fb5cb87d8eb533ae094b0dd5784df77c98bddeac9d72725"
        hash = "9bb3035610bd09ba769c0335f23f98dd85c2f32351cdd907d4761b41ab5d099c"
        hash = "1703025c4aed71d0ca29a3cd0e15047c24cc9adbb5239765f63e205ef7d65753"
        hash = "948d47b9386b2b3247b7e9796ab2f2078889264559ad04ccd9362b03dbbf8534"
        hash = "edd527d978b591d146d24d075bb4c24177e0eca6a27b5d92f35be68635cc3767"
        hash = "c642dc125fbd83e004d2c527933996589e0fcad06313a5a56679a265b8966529"
        hash = "cfa3a48bf0c683834d1d198a653ebced8a8faae9d0cbb38f3e859b45da81d554"
        hash = "bb8f5d123aebdde5542724db5be8430d62a80f86f590a272aac9087d097f395c"
        hash = "e41e10673db41b13ba17c828beb94fc39e8d3aa43b01f9fe437a2f6e0b8ae443"
        hash = "a132e31db9f9761d6bd2c375415e615bb0a548fb02c4fd6373e9f7d1568de1dc"
        hash = "5084c6e20b88adeea6a28508cf172048d7cf20adeaa52abdd361fc2207411055"
        hash = "525320e3631a23a3286481710533ba15cd6268ee10be98962a55e2afead1ffbf"
        hash = "16c74f288f4f929e74cd8e16443303aec3a64cfef64aabc14553f4c1e58c9ede"
        hash = "4b482ebf88bcb55e7b0769690ccca4d08856c879af82ad7165436b82a315d742"
        hash = "79c9acadd99ab1251dbba3bff7d0b67de4252f913f485465d63f4f0c4d9a6419"
        hash = "9bcc3f36c32e3efbf8bdcba7670658042db65dd617dad0709d92c554ba841b57"
        hash = "5654ed1205de6860e66383a27231e4ac2bb7639b07504121d313a8503ece3305"
        hash = "5d1e3c495d08982459b4bd4fd2ab073ed2078fce9347627718a7c25adee152e9"
        hash = "458702ae1b2ef8a113344be76af185ee137b7aac3646ece626d2eeeadcc9e003"
        hash = "2c703e562a6266175379fa48f06f58aab109dbe56e0cde24b4b0db5f22f810a3"
        hash = "49faf70c0978c21a68bc8395cf326f50c491e379f55b5df7d17f0af953861ece"
        hash = "a2b16bbef0a7cb545597828466cd13225efaba6e7006bfbf59040bbff54c463c"
        hash = "b08449d42f140c7e4d070c5f81ce7509f48282a5bb0e06948b7ed65053696a37"
        hash = "c1633ad8c9e6c2b4cc23578655fc6cf5cd0122cfd24395d1551af1d092f89db2"
        hash = "01f42f949a37d9d479b8021f27dcf0d0e6f0b0b6cd2e0883c6b4b494f0a1d32a"
        hash = "4943d53a38ac123ed7c04ad44742a67ea06bb54ea02fa241d9c4ebadab4cb99a"
        hash = "597ce12c9fbecc71299ba6fc3e4df36cc49222878d0e080c4c35bbfdffd30083"
        hash = "0265fbd9cfc27c26c42374fce7cf0ef11f38e086308d51648b45f040d767c51d"
        hash = "0dc92a1a6fd27144b3e35a9900038653892d25c2db8ede8b9e0aee04839f165a"
        hash = "682582c324cb1eafacf80090f6108c1580fee12dbfdfe8b51771d429fdcce718"
        hash = "e9e6f6e22b5924f80164fbad45be28299e9ec0bd2f404551b6ca772509a7135a"
        hash = "a8db750f82906fb9cf9fb371ec65be76275d9b81b95e351fcb3db4ef345884ab"
        hash = "e900b4016177259d07011139a55c0571c1e824fb7e9dddc11df493b3c8209173"
        hash = "f8a7a26d51a5e938325deee86cbf5aa8263d3a50818c15d5a395b98658630c18"
        hash = "861b87fc6c4758cfe1e26c7a038cffb64054ad633b7ea81319c9a98b7b49df0d"
        hash = "848fdb491307ed7b002dbdf99796df2b286d53b2e0066d78f3554f2f38a2c438"
        hash = "4b0c05bc33c9e7d0ed2d97dbefb6292469b9d74d650d5cfb2691345a11c0f54a"
        hash = "948d47b9386b2b3247b7e9796ab2f2078889264559ad04ccd9362b03dbbf8534"
        hash = "edd527d978b591d146d24d075bb4c24177e0eca6a27b5d92f35be68635cc3767"
        hash = "c642dc125fbd83e004d2c527933996589e0fcad06313a5a56679a265b8966529"
        hash = "cfa3a48bf0c683834d1d198a653ebced8a8faae9d0cbb38f3e859b45da81d554"
        hash = "bb8f5d123aebdde5542724db5be8430d62a80f86f590a272aac9087d097f395c"
        hash = "e41e10673db41b13ba17c828beb94fc39e8d3aa43b01f9fe437a2f6e0b8ae443"
        hash = "a132e31db9f9761d6bd2c375415e615bb0a548fb02c4fd6373e9f7d1568de1dc"
        hash = "5084c6e20b88adeea6a28508cf172048d7cf20adeaa52abdd361fc2207411055"
        hash = "525320e3631a23a3286481710533ba15cd6268ee10be98962a55e2afead1ffbf"
        hash = "16c74f288f4f929e74cd8e16443303aec3a64cfef64aabc14553f4c1e58c9ede"
        hash = "4b482ebf88bcb55e7b0769690ccca4d08856c879af82ad7165436b82a315d742"
        hash = "79c9acadd99ab1251dbba3bff7d0b67de4252f913f485465d63f4f0c4d9a6419"
        hash = "9bcc3f36c32e3efbf8bdcba7670658042db65dd617dad0709d92c554ba841b57"

        id = "13151f9b-22cb-551f-81b4-a60a301f0bfc"
    strings:
        // works well enough with string search so no need to use the pe module
        $cert1 = "91210242MA0YGH36" wide ascii ///serialNumber=91210242MA0YGH36XJ/jurisdictionC=CN/businessCategory=Private Organization/C=CN/ST=\xE8\xBE\xBD\xE5\xAE\x81\xE7\x9C\x81
        $cert2 = "Copyright (C) 2013-2021 QuickZip. All rights reserved." wide ascii 
        $cert3 = "Qi Lijun" wide ascii // short but no fp
        $cert4 = {51 00 69 00 20 00 4c 00 69 00 6a 00 75 00 6e} // string above in hex(utf16-be minus first 00) because of https://github.com/VirusTotal/yara/issues/1891
        $cert5 = "Luck Bigger Technology Co., Ltd" wide ascii
        $cert6 = {4c 00 75 00 63 00 6b 00 20 00 42 00 69 00 67 00 67 00 65 00 72 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 79 00 20 00 43 00 6f 00 2e 00 2c 00 20 00 4c 00 74 00 64 } // above in hex
        $cert7 = "XinSing Network Service Co., Ltd" wide ascii
        $cert8 = "Hangzhou Shunwang Technology Co.,Ltd" wide ascii
        $cert9 = "Zhuhai liancheng Technology Co., Ltd." wide ascii
        $cert10 = { e5 a4 a7 e8 bf 9e e7 ba b5 e6 a2 a6 e7 bd 91 e7 bb 9c e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }
        $cert11 = { e5 8c 97 e4 ba ac e5 bc 98 e9 81 93 e9 95 bf e5 85 b4 e5 9b bd e9 99 85 e8 b4 b8 e6 98 93 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }
        $cert12 = { e7 a6 8f e5 bb ba e5 a5 a5 e5 88 9b e4 ba 92 e5 a8 b1 e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }
        $cert13 = { e5 8e a6 e9 97 a8 e6 81 92 e4 bf a1 e5 8d 93 e8 b6 8a e7 bd 91 e7 bb 9c e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 0a }
        $cert14 = { e5 a4 a7 e8 bf 9e e7 ba b5 e6 a2 a6 e7 bd 91 e7 bb 9c e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        filesize < 20MB and
        any of ( $cert* )

}
