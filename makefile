YARA=3.5.0
CUR_DIR=${PWD}
YARA_DIR=$(CUR_DIR)/yara
BUILD_DIR=$(CUR_DIR)/build
3RD_PARTY=$(CUR_DIR)/3rdparty

YAR_COMP_VARS=-d filename="XXX" -d filepath="XXX" -d extension="XXX" -d filetype="XXX" -d md5="XXX" -d id="1"
YAR_SIGS=$(wildcard ./yara/*.yar)

all: clean prereq build
sigs: cleanbuild build

clean: cleanbuild
	rm -rf $(3RD_PARTY)

cleanbuild:
	rm -rf $(BUILD_DIR)

prereq:
	mkdir -p $(3RD_PARTY)/src
	wget -P $(3RD_PARTY)/src https://github.com/VirusTotal/yara/archive/v$(YARA).tar.gz
	tar -xvzf $(3RD_PARTY)/src/*.tar.gz -C $(3RD_PARTY)/src
	cd $(3RD_PARTY)/src/yara-$(YARA) ; \
	./bootstrap.sh ; \
	./configure --disable-shared --disable-magic --disable-cuckoo --prefix=$(3RD_PARTY)/yara ; \
	make ; \
	make install

build:
	mkdir -p $(BUILD_DIR)/yara
	for yarsig in $(YAR_SIGS) ; do \
		echo "Compiling $(BUILD_DIR)/$(notdir $$yarsig) ..." ; \
		$(3RD_PARTY)/yara/bin/yarac $(YAR_COMP_VARS) $(notdir $$yarsig) $(BUILD_DIR)/$(notdir $$yarsig).compiled ; \
	done
