# -*- coding: utf-8 -*-

import sys
import os
import yara         # install 'yara-python' module not the outdated 'yara' module
import logging
import traceback
import codecs
import re

YARA_RULE_DIRECTORIES = [r'./yara']
FILENAME_IOC_DIRECTORY = r'./iocs'


def walk_error(err):
    try:
        if "Error 3" in str(err):
            logging.error(removeNonAsciiDrop(str(err)))
            print("Directory walk error")
            sys.exit(1)
    except UnicodeError as e:
        print("Unicode decode error in walk error message")
        sys.exit(1)


def removeNonAsciiDrop(string):
    nonascii = "error"
    try:
        # Generate a new string without disturbing characters
        nonascii = "".join(i for i in string if ord(i)<127 and ord(i)>31)

    except Exception as e:
        traceback.print_exc()
        pass
    return nonascii


def transformOS(regex, platform):
    # Replace '\' with '/' on Linux/Unix/OSX
    if platform != "windows":
        regex = regex.replace(r'\\', r'/')
        regex = regex.replace(r'C:', '')
    return regex


def replaceEnvVars(path):

    # Setting new path to old path for default
    new_path = path

    # ENV VARS ----------------------------------------------------------------
    # Now check if an environment env is included in the path string
    res = re.search(r"([@]?%[A-Za-z_]+%)", path)
    if res:
        env_var_full = res.group(1)
        env_var = env_var_full.replace("%", "").replace("@", "")

        # Check environment varibales if there is a matching var
        if env_var in os.environ:
            if os.environ[env_var]:
                new_path = path.replace(env_var_full, re.escape(os.environ[env_var]))

    # TYPICAL REPLACEMENTS ----------------------------------------------------
    if path[:11].lower() == "\\systemroot":
        new_path = path.replace("\\SystemRoot", os.environ["SystemRoot"])

    if path[:8].lower() == "system32":
        new_path = path.replace("system32", "%s\\System32" % os.environ["SystemRoot"])

    #if path != new_path:
    #    print "OLD: %s NEW: %s" % (path, new_path)
    return new_path


def initialize_filename_iocs():

    try:
        for ioc_filename in os.listdir(FILENAME_IOC_DIRECTORY):
            if 'filename' in ioc_filename:
                logging.info("Compiling Filename IOCs from %s" % ioc_filename)
                with codecs.open(os.path.join(FILENAME_IOC_DIRECTORY, ioc_filename), 'r', encoding='utf-8') as file:
                    lines = file.readlines()

                    # Last Comment Line
                    last_comment = ""

                    for line in lines:
                        try:
                            # Empty
                            if re.search(r'^[\s]*$', line):
                                continue

                            # Comments
                            if re.search(r'^#', line):
                                last_comment = line.lstrip("#").lstrip(" ").rstrip("\n")
                                continue

                            # Elements with description
                            if ";" in line:
                                line = line.rstrip(" ").rstrip("\n\r")
                                row = line.split(';')
                                regex = row[0]
                                score = row[1]
                                if len(row) > 2:
                                    regex_fp = row[2]
                                desc = last_comment

                                # Catch legacy lines
                                if not score.isdigit():
                                    desc = score        # score is description (old format)
                                    score = 60          # default value

                            # Elements without description
                            else:
                                regex = line

                            # Replace environment variables
                            regex = replaceEnvVars(regex)
                            # OS specific transforms
                            regex = transformOS(regex, "windows")

                            # If false positive definition exists
                            regex_fp_comp = None
                            if 'regex_fp' in locals():
                                # Replacements
                                regex_fp = replaceEnvVars(regex_fp)
                                regex_fp = transformOS(regex_fp, "windows")
                                # String regex as key - value is compiled regex of false positive values
                                regex_fp_comp = re.compile(regex_fp)

                            # Create dictionary with IOC data
                            fioc = {'regex': re.compile(regex), 'score': score, 'description': desc, 'regex_fp': regex_fp_comp}

                        except Exception as e:
                            traceback.print_exc()
                            logging.error("Error reading line: %s" % line)
                            sys.exit(1)

    except Exception as e:
        traceback.print_exc()
        logging.error("Error reading File IOC file: %s" % ioc_filename)
        sys.exit(1)


def initialize_yara_rules():
    yaraRules = ""
    dummy = ""

    try:
        for yara_rule_directory in YARA_RULE_DIRECTORIES:
            if not os.path.exists(yara_rule_directory):
                continue
            logging.info("Processing YARA rules folder {0}".format(yara_rule_directory))
            for root, directories, files in os.walk(yara_rule_directory, onerror=walk_error, followlinks=False):
                for file in files:
                    try:

                        # Full Path
                        yaraRuleFile = os.path.join(root, file)

                        # Skip hidden, backup or system related files
                        if file.startswith(".") or file.startswith("~") or file.startswith("_"):
                            continue

                        # Extension
                        extension = os.path.splitext(file)[1].lower()

                        # Test Compile
                        try:
                            compiledRules = yara.compile(yaraRuleFile, externals={
                                'filename': dummy,
                                'filepath': dummy,
                                'extension': dummy,
                                'filetype': dummy,
                                'md5': dummy
                            })
                            logging.info("Initializing Yara rule %s" % file)
                        except Exception as e:
                            logging.error("Error in YARA rule: %s" % yaraRuleFile)
                            traceback.print_exc()
                            sys.exit(1)

                        # Encrypted
                        if extension == ".yar":
                            with open(yaraRuleFile, 'r') as rulefile:
                                data = rulefile.read()
                                yaraRules += data

                    except Exception as e:
                        logging.error("Error reading signature file %s ERROR: %s" % yaraRuleFile)
                        traceback.print_exc()
                        sys.exit(1)

        # Compile
        try:
            logging.info("Initializing all YARA rules at once (composed string of all rule files)")
            compiledRules = yara.compile(source=yaraRules, externals={
                'filename': dummy,
                'filepath': dummy,
                'extension': dummy,
                'filetype': dummy,
                'md5': dummy
            })
            logging.info("Initialized all Yara rules at once")

        except Exception as e:
            traceback.print_exc()
            logging.error("Error during YARA rule compilation when all YARA rules are are combined in a single file")
            sys.exit(1)

    except Exception as e:
        traceback.print_exc()
        logging.error("Unexpected error while walking the directories")
        sys.exit(1)

# MAIN ################################################################
if __name__ == '__main__':

    logging.basicConfig(level=logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    logging.getLogger('sigbase').addHandler(console)

    # Compile YARA rules
    initialize_yara_rules()

    # Compile Filename IOCs
    initialize_filename_iocs()
