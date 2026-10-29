rule SUSP_LNX_ARCH_PKGBUILD_NPM_Dependency_Jun26 {
   meta:
      description = "Detects suspicious PKGBUILD with NPM dependency and install script"
      author = "Marius Benthin"
      date = "2026-06-15"
      reference = "https://aur.archlinux.org/cgit/aur.git/commit/?h=hearthstone-linux-gui-bin&id=ecf810ac853e7149abd4e0c793b2517e9737edb8"
      reference2 = "https://aur.archlinux.org/cgit/aur.git/commit/?h=python-django-js-asset&id=af09b1cf1b59"
      hash = "56bed7736d44219215fd912b229c7f765b737db4f6cde256ce264e795310c648"
      hash = "1359814fda7f5ef63f04348439bfb011d7abc0381be6fbb404b04b359d63b61b"
      hash = "3e1f297ab4d261fcad14a865a54d049d75d897d549d03371a5c4bbbc6e10e5cd"
      score = 60
      id = "e98bbded-9f21-4f11-9856-35981d62ad06"
   strings:
      // depends=('npm' or 'bun'
      $sa1 = { (0A | 20) 64 65 70 65 6E 64 73 3D 28 [0-15] (6E 70 6D | 62 75 6E) }

      // install -Dm644 "../*.hook"
      $sb1 = { 69 6E 73 74 61 6C 6C 20 2D 44 6D 36 34 34 20 (22 | 27) [0-100] 2E 68 6F 6F 6B (22 | 27) 0A }
      // install=oracle-bin-deps.install
      $sb2 = { 69 6E 73 74 61 6C 6C 3D [1-50] 2E 69 6E 73 74 61 6C 6C }
   condition:
      filesize < 100KB
      and $sa1
      and 1 of ($sb*)
}

rule SUSP_LNX_ARCH_SRCINFO_NPM_Dependency_Jun26 {
   meta:
      description = "Detects suspicious .SRCINFO with NPM dependency and install script"
      author = "Marius Benthin"
      date = "2026-06-15"
      reference = "https://aur.archlinux.org/cgit/aur.git/commit/?h=hearthstone-linux-gui-bin&id=ecf810ac853e7149abd4e0c793b2517e9737edb8"
      hash = "2ee28d5866fdb46e439678ad92729b1cd71d2d871135d8d56a27cf6a6b49e649"
      score = 60
      id = "410d64ed-4e89-4e35-95ec-7681982c7064"
   strings:
      $s1 = "depends = npm\n"
      // install = python-pymilvus-deps.install
      $s2 = { 69 6E 73 74 61 6C 6C 20 3D 20 [1-50] 2E 69 6E 73 74 61 6C 6C }
   condition:
      filesize < 5KB
      and all of them
}

rule SUSP_LNX_ARCH_Install_Hook_Jun26 {
   meta:
      description = "Detects suspicious pre and post hooks in Arch install files"
      author = "Marius Benthin"
      date = "2026-06-15"
      reference = "https://aur.archlinux.org/cgit/aur.git/commit/?h=hearthstone-linux-gui-bin&id=ecf810ac853e7149abd4e0c793b2517e9737edb8"
      reference2 = "https://aur.archlinux.org/cgit/aur.git/commit/?h=python-django-js-asset&id=af09b1cf1b59"
      hash = "47c076099e6715ffb0bd357b6832175741e77b88972033cd1f9b55b6ff7e5519"
      hash = "ef735bca8cb2acafe70831e33ed468a3046a61147af694000761970415c7eef1"
      score = 70
      id = "fbe3599b-525b-432e-af8f-53779b02a171"
   strings:
      $sa1 = "pre_install() {"
      $sa2 = "post_install() {"
      $sa3 = "pre_upgrade() {"
      $sa4 = "post_upgrade() {"
      $sa5 = "pre_remove() {"
      $sa6 = "post_remove() {"

      $sb1 = "npm install "
      $sb2 = "&& 'b''u''n'"

      $fp1 = "#!/bin/sh"
   condition:
      filesize < 5KB
      and 1 of ($sa*)
      and 1 of ($sb*)
      and not 1 of ($fp*)
}

rule SUSP_LNX_ARCH_ALPM_Hook_Jun26 {
   meta:
      description = "Detects suspicious execution commands in Arch ALPM hooks"
      author = "Marius Benthin"
      date = "2026-06-15"
      reference = "https://aur.archlinux.org/cgit/aur.git/commit/?h=hearthstone-linux-gui-bin&id=ecf810ac853e7149abd4e0c793b2517e9737edb8"
      hash = "ba332432f87e68d7fa8c784c60c39ba0d3e2ac06fd8855e82ea49329e2684529"
      score = 70
      id = "6598c5ca-8f2c-44f8-bf1f-54e82b06f59c"
   strings:
      $s1 = "[Action]"
      $s2 = "Exec = "
      $s3 = "npm install "
      $s4 = "2>/dev/null"
   condition:
      filesize < 5KB
      and all of them
}
