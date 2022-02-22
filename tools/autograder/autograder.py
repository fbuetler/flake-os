#!/usr/bin/python3

import argparse
import os
import sys
import pathlib
import shutil
import pexpect
import multiprocessing
import json
import time

import traceback
import pprint

from plumbum import colors, local, commands, machines, path
from plumbum.cmd import mkdir, bash, make
from plumbum.commands.processes import ProcessExecutionError


#########################################################################################
# Configuration Options
#########################################################################################

# this is the expected string to be seen when booting
CFG_EXPECT_BOOT = "Barrelfish CPU driver starting on ARMv8"

# this is the timeout to wait after boot
CFG_BOOT_TIMEOUT = 10

# this is the delay between two characters sent to the serial
CFG_CONSOLE_TYPE_DELAY = 0.1


# this defines default strings that cause the test to fail.
CFG_DEFAULT_FAIL = ["Aborted.", "Panic", "panic"]

# this is the basic target to be build initially.
CFG_MAKE_BASE_TARGET = "imx8x"

# this is the menu.lst that defines the modules to be included in the image
CFG_MENU_LST = 'menu.lst.armv8_imx8x'

# this is the image used for testing and will be installed
CFG_MAKE_IMAGE_NAME = "armv8_imx8x_image.efi"


# this is the USB serial to be used
CFG_LOCAL_CONSOLE_USB = "/dev/ttyUSB0"

# this is the command to get the console locally
CFG_LOCAL_CONSOLE_CMD = ["picocom", "-b", "115200",  "-f", "n"]

# this is the local boot cmd i.e. the make target
CFG_LOCAL_BOOT_CMD = "usbboot_colibri"


# this is the default board to take for remote booting
CFG_REMOTE_BOARD_NAME = "colibri5"

# this is the command to get the console on the remote machine (ssh is added)
CFG_REMOTE_CONSOLE_CMD = ["console", "-f"]

# this is the command to boot the board remotely (ssh is added)
CFG_REMOTE_BOOT_CMD = "/home/netos/tools/bin/rackboot.sh -b {}"

# this is the docker image to be used for docker based compilation
CFG_DOCKER_IMAGE="achreto/barrelfish-ci"


#########################################################################################
# Get the script paths and tools directory
#########################################################################################

# XXX: this assumes that the autograder is in $SRC/tools/autograder

# this is the directory of the current script
SCRIPT_DIRECTORY=pathlib.Path(os.path.dirname(os.path.realpath(__file__)))

# this is the directory which contains the tests
TESTS_DIRECTORY=SCRIPT_DIRECTORY / "tests"

# this is the tools directory
TOOLS_DIRECTORY=SCRIPT_DIRECTORY.parent

# this is the root of the aos source tree
ROOT_DIRECTORY=TOOLS_DIRECTORY.parent

# this is the build path, defaults to $ROOT/build
BUILD_PATH=ROOT_DIRECTORY / 'build'

# this is the path of the menu.lst file
MENU_LST_PATH=ROOT_DIRECTORY / 'hake' / CFG_MENU_LST


#########################################################################################
# Logging Facility
#########################################################################################

verboselogging = False

def logwarn(msg) :
    print(colors.bold & colors.yellow | " + [WARN]  ", end=" "),
    print(colors.bold.reset & colors.yellow.reset | msg)

def logerr(msg) :
    print(colors.bold & colors.red | " + [ERROR] ", end=" "),
    print(colors.bold & colors.red.reset | msg)

def loginfo(msg) :
    print(colors.bold & colors.info | " + [INFO]  ", end=" "),
    print(colors.bold.reset & colors.info.reset | msg)

def logok(msg) :
    print(colors.bold & colors.success | " + [OK]    ", end=" "),
    print(colors.bold & colors.info.reset | msg)

def logstart(msg) :
    print(colors.bold & colors.info | "\n + [TEST]  ", end=" "),
    print(colors.bold & colors.info.reset | msg)

def logpass(msg) :
    print(colors.bold & colors.success | " # [PASS] ", end=" "),
    print(colors.bold & colors.success.reset | msg)

def logfail(msg) :
    print(colors.bold & colors.red | " # [FAIL] ", end=" "),
    print(colors.bold & colors.red.reset | msg)

def logtitle(msg) :
    print(colors.bold & colors.title | "\n\n{}".format(msg)),
    print(colors.bold.reset & colors.title.reset)

def logresult(msg) :
    print(colors.bold & colors.title | "\n# [RESULT] {}".format(msg)),
    print(colors.bold.reset & colors.title.reset)

def logmsg(msg):
    print(colors.bold.reset | "            > {}".format(msg))

def logverbose(msg) :
    if verboselogging :
        print(colors.bold.reset | "            > {}".format(msg))

def logoutput(msg) :
    print(colors.bold.reset | "            <------------- start of error output ------------->")
    lines = msg.split("\n")
    nlines = len(lines)
    if nlines > 10 :
        print(colors.bold.reset | "             | {} more lines".format(nlines - 10))
        print(colors.bold.reset | "             | ")
        lines = lines[-9:]

    for l in lines :
        print(colors.bold.reset | "             | {}".format(l))

    print(colors.bold.reset | "            <-------------- end of error output -------------->")


#########################################################################################
# Arguments Parser
#########################################################################################

parser = argparse.ArgumentParser()

parser.add_argument("-v", "--verbose", action="store_true",
                    help="increase output verbosity")

parser.add_argument("-d", "--docker", action="store_true",
                    help="use docker image to compile")

parser.add_argument("-f", "--forcehake", action="store_true",
                    help="run hake")

parser.add_argument("-t", "--tests", nargs='+', default=[],
                    help='the tests to run <test:subtest:subtest>')

parser.add_argument("-r", "--remote", default=None,
                    help='build on remote server')

parser.add_argument("-b", "--board", default=CFG_REMOTE_BOARD_NAME,
                    help='the board to use (default {})'.format(CFG_REMOTE_BOARD_NAME))

parser.add_argument("-u", "--usb", default=CFG_LOCAL_CONSOLE_USB,
                    help='the console usbserial to use (default {})'.format(CFG_LOCAL_CONSOLE_USB))


#########################################################################################
# Defining the modules to be loaded etc.
#########################################################################################

MENU_LST_MODULES = {
    'bootdriver' : None,
    'cpudriver' : None,
    'modules' : [],
    'original' : []
}


#########################################################################################
# Stage - Build Preparation
#########################################################################################

def prepare(args) :
    logtitle("Prepare")

    # do we need to create the build path?
    if not BUILD_PATH.exists() :
        loginfo("Creating build path '{}'".format(BUILD_PATH))
        mkdir(BUILD_PATH)
    else :
        loginfo("Build path '{}' already exists".format(BUILD_PATH))

    # parsing the menu.lst as provided.
    loginfo("Parsing menu.lst file '{}'".format(MENU_LST_PATH))
    with open(MENU_LST_PATH, 'r') as f:
        for l in f.readlines() :
            MENU_LST_MODULES['original'].append(l)
            l = l.strip()
            words = l.split(" ")
            nwords = len(words)
            if nwords == 0:
                continue

            if words[0].startswith("#") :
                continue

            cmdline = []
            for w in words[1:] :
                if w.startswith("#") :
                    break
                wstripped = w.strip()
                if wstripped != "" :
                    cmdline.append(wstripped)

            if len(cmdline) == 0:
                continue

            if cmdline[0].startswith('/') :
                cmdline[0] = cmdline[0][1:]

            if words[0] == "module" :
                MENU_LST_MODULES["modules"].append(cmdline)
            if words[0] == "bootdriver" :
                MENU_LST_MODULES["bootdriver"] = cmdline
            if words[0] == "cpudriver" :
                MENU_LST_MODULES["cpudriver"] = cmdline

    if MENU_LST_MODULES["bootdriver"] == None :
        logerr("Incomplete parsing of the menu.lst")
        raise("Did not find a bootdriver on the menu.lst file")

    if MENU_LST_MODULES["cpudriver"] == None :
        logerr("Incomplete parsing of the menu.lst")
        raise("Did not find a cpudriver on the menu.lst file")

    loginfo("Parserd menu.lst file, found total {} modules."
                .format(2 + len(MENU_LST_MODULES["modules"])))

    logok("preparation complete.")


#########################################################################################
# Stage - Hake
#########################################################################################

def hake(args) :
    logtitle("Hake")

    makefile = BUILD_PATH / "Makefile"
    if not makefile.exists() or args.forcehake :
        hake_cmd = ["../hake/hake.sh", "-s", "../"]
        loginfo("Running Hake...")
        with local.cwd(BUILD_PATH):
            logverbose("directory: '{}'".format(local.cwd))
            logverbose("command: '{}'".format(" ".join(hake_cmd)))
            try :
                res = bash(*hake_cmd)
            except ProcessExecutionError as e :
                logerr("Failed to run hake")
                logoutput(e.stdout)
                raise Exception("Running hake resulted in an ProcessExecutionError")
            except Exception as e:
                logerr("Unknown exception while running hake.")
                raise(e)
    else :
        loginfo("Makefile exist, skipping hake. (use -r to force running hake)")

    logok("Hake complete")


#########################################################################################
# Stage - Base Build
#########################################################################################

#----------------------------------------------------------------------------------------
# Build the base OS Image
#----------------------------------------------------------------------------------------

def build(args) :
    logtitle("Building Base OS Image")

    makefile = BUILD_PATH / "Makefile"
    if not makefile.exists() :
        raise Exception("Makefile does not exist! Run hake first")

    # obtain the number of available processors for parallel building
    nproc = multiprocessing.cpu_count()
    loginfo("Build parallel using {} processors".format(nproc))

    if args.docker :
        loginfo("Using docker to build the OS image")
        buildcmd = ["docker", "run", "-u", str(os.geteuid()), "-i", "-t",
            "--mount", "type=bind,source={},target=/source".format(ROOT_DIRECTORY),
            CFG_DOCKER_IMAGE, "ls"
        ]
        raise Exception("build using docker currently not supported")
    else :
        loginfo("Using native `make` call to build the OS image")
        makeargs = ["-j", str(nproc), CFG_MAKE_BASE_TARGET]
        with local.cwd(BUILD_PATH):
            logverbose("directory: '{}'".format(local.cwd))
            logverbose("command: 'make {}'".format(" ".join(makeargs)))
            try :
                res = make(*makeargs)
            except ProcessExecutionError as e :
                logerr("Failed to build the base image")
                logoutput(e.stderr)
                raise Exception("Running build resulted in an ProcessExecutionError")
            except Exception as e:
                logerr("Unknown exception while running make.")
                raise(e)

    logok("Built OS image")


#----------------------------------------------------------------------------------------
# Building a specific list of binaries
#----------------------------------------------------------------------------------------

def buildbinaries(args, cmdlines) :
    bins = []
    for c in cmdlines :
        bins.append(c[0])

    makefile = BUILD_PATH / "Makefile"
    if not makefile.exists() :
        raise Exception("Makefile does not exist! Run hake first")

    nproc = multiprocessing.cpu_count()
    if args.docker :
        buildcmd = ["docker", "run", "-u", str(os.geteuid()), "-i", "-t",
            "--mount", "type=bind,source={},target=/source".format(ROOT_DIRECTORY),
            CFG_DOCKER_IMAGE, "ls"
        ]
        raise Exception("build using docker currently not supported")
    else :
        makeargs = ["-j", str(nproc)] + bins
        with local.cwd(BUILD_PATH):
            logverbose("directory: '{}'".format(local.cwd))
            logverbose("command: 'make {}'".format(" ".join(makeargs)))
            make(*makeargs)
            try :
                res = make(*makeargs)
            except ProcessExecutionError as e :
                logerr("Failed to build the base image")
                logoutput(e.stdout)
                raise Exception("Running build resulted in an ProcessExecutionError")
            except Exception as e:
                logerr("Unknown exception while running make.")
                raise(e)


#########################################################################################
# Stage - Running Test
#########################################################################################


#----------------------------------------------------------------------------------------
# Create the OS image
#----------------------------------------------------------------------------------------

def createimage(args, modules) :

    logverbose("Creating OS image...")

    # create the directores in the platform
    PLATFORMS_PATH=BUILD_PATH / "platforms"
    if not PLATFORMS_PATH.exists() :
        mkdir(PLATFORMS_PATH)

    PLATFORMS_PATH=BUILD_PATH / "platforms" / "arm"
    if not PLATFORMS_PATH.exists() :
        mkdir(PLATFORMS_PATH)

    # write the menu.lst
    DST_MENU_LST_PATH = PLATFORMS_PATH / CFG_MENU_LST
    with open(DST_MENU_LST_PATH, "w") as f:
        for l in MENU_LST_MODULES['original'] :
            f.write("{}\n".format(l))

        for m in modules :
            f.write("module {}\n".format(" ".join(m)))

    # set the parallel buld and create the image
    nproc = multiprocessing.cpu_count()
    if args.docker :
        buildcmd = ["docker", "run", "-u", str(os.geteuid()), "-i", "-t",
            "--mount", "type=bind,source={},target=/source".format(ROOT_DIRECTORY),
            CFG_DOCKER_IMAGE, "ls"
        ]
        raise Exception("build using docker currently not supported")
    else :
        makeargs = ["-j", str(nproc), CFG_MAKE_IMAGE_NAME]
        with local.cwd(BUILD_PATH):
            logverbose("directory: '{}'".format(local.cwd))
            logverbose("command: 'make {}'".format(" ".join(makeargs)))
            make(*makeargs)
            try :
                res = make(*makeargs)
            except ProcessExecutionError as e :
                logerr("Failed to build the base image")
                logoutput(e.stdout)
                raise Exception("Running build resulted in an ProcessExecutionError")
            except Exception as e:
                logerr("Unknown exception while running make.")
                raise(e)


#----------------------------------------------------------------------------------------
# Installing
#----------------------------------------------------------------------------------------

def installimage(args, remotemachine = None, remotepath = None) :

    # no need to install if we're not running on the remote machine
    if remotemachine == None or remotepath == None:
        return

    logmsg("Installing to remote '{}'...".format(args.remote))
    try :
        with local.cwd(BUILD_PATH) :
            IMAGE=BUILD_PATH / CFG_MAKE_IMAGE_NAME
            fro = local.path(IMAGE)
            to = remotemachine.path(remotepath)

            # do a copy from the local machine to the remote machine
            path.utils.copy(fro, to)

    except Exception as e:
        logerr("Unknown exception while copying image")
        raise(e)


#----------------------------------------------------------------------------------------
# Booting the board
#----------------------------------------------------------------------------------------

def boot(args, remotemachine) :
    try :
        if remotemachine == None :
            logmsg("Booting locally with '{}'".format(CFG_LOCAL_BOOT_CMD))
            with local.cwd(BUILD_PATH) :
                makeargs = [ CFG_LOCAL_BOOT_CMD ]
                make(*makeargs)
        else :
            logmsg("Booting remotely with '{}'".format(CFG_REMOTE_BOOT_CMD.format(args.board)))
            r_ls = remotemachine[CFG_REMOTE_BOOT_CMD.format(args.board)]
            r_ls()
    except Exception as e:
        logerr("Could not boot the board")
        raise(e)
    return


#----------------------------------------------------------------------------------------
# Running a subtest
#----------------------------------------------------------------------------------------

def do_run_test(args, subtest, host, remotemachine, remotepath) :
    logstart("running test '{}'".format(subtest["title"]))

    # build required binaries
    buildbinaries(args, MENU_LST_MODULES["modules"] + subtest["modules"])

    # create the os image
    createimage(args, subtest["modules"])

    # install the image
    installimage(args, remotemachine, remotepath)

    # get all the points defined in the test
    points = 0
    pointsmax = 0
    for s in subtest['teststeps'] :
        if s["action"] == "expect" :
            pointsmax = pointsmax + s['points']

    # prepare the console cmd
    consolecmd = ""
    if remotemachine != None :
        consolecmd = "ssh"
        consolecmdargs = [host] + CFG_REMOTE_CONSOLE_CMD + [args.board]
    else :
        consolecmd = CFG_LOCAL_CONSOLE_CMD[0]
        consolecmdargs = CFG_LOCAL_CONSOLE_CMD[1:] + [args.usb]

    # run the console command
    logverbose("Starting console with command '{} {}".format(consolecmd, " ".join(consolecmdargs)))
    con = pexpect.spawn(consolecmd, consolecmdargs, timeout=subtest['timeout'])

    # we are now ready to boot the platform
    try :
        boot(args, remotemachine)
    except Exception as e:
        logerr("Failed to boot the platform")
        con.terminate(True) # teminate the console
        raise (e)

    # wait for the OS to boot into the OS kernel
    try :
        logverbose("Waiting for '{}'".format(CFG_EXPECT_BOOT))
        con.expect(CFG_EXPECT_BOOT)
        con.setecho(False)
    except pexpect.TIMEOUT as e :
        logerr("Did not see expected boot string '{}'".format(CFG_EXPECT_BOOT))
        raise(e)
    except Exception as e :
        logerr("Exception happened while waiting for OS to boot")
        raise (e)

    # waiting a few seconds to get userspace up
    time.sleep(CFG_BOOT_TIMEOUT)

    # run through the test stages
    try :
        for s in subtest['teststeps'] :
            action = s['action']

            # wait for some time
            if action == "wait" :
                logverbose("waiting for {} seconds".format(s["seconds"]))
                time.sleep(float(s["seconds"]))

            # expect certain output from the child
            elif action == "expect" :
                logverbose("expecting '{}'".format(s['pass']))
                idx = con.expect(CFG_DEFAULT_FAIL + s['fail'] + s['pass'] )
                if (idx >= len(s['fail'])  + len(CFG_DEFAULT_FAIL)) :
                    points = points + s["points"]

            # reboot the platform
            elif action == "reboot" :
                logverbose("rebooting the platform")
                boot(args, remotemachine)
                con.expect(CFG_EXPECT_BOOT)

            # provide intput to the serial console
            elif action == "input" :
                logverbose("input '{}' to stdio".format(s["value"]))
                for c in s["value"] :
                    con.write(c)                # write single characters at a time
                    con.write(chr(0x04))        # send the 'end of tranmission' control signal
                    time.sleep(CFG_CONSOLE_TYPE_DELAY)             # sleep a bit
                con.write("\n")

    except pexpect.TIMEOUT as e :
        # a timeout indicates a failed test
        logfail("Test failed (timeout) - {} / {} pts".format(points, pointsmax))
        return (False, points, pointsmax)

    except Exception as e:
        # another exception indicate other failure
        print(traceback.format_exc())
        pprint.pprint(e)
        raise(e)

    # the thest passed all expected output.
    logpass("Test Passed - {} / {} pts".format(str(points), str(pointsmax)))

    return (True, points, pointsmax)


#----------------------------------------------------------------------------------------
# Runs teset specified in a test file
#----------------------------------------------------------------------------------------

def runtest(args, test) :

    tests = test.split(":")
    maintest = tests[0]
    subtests = tests[1:]

    remotemachine = None
    testhost = "localhost"
    remotepath = None

    # create the remote connection
    if args.remote != None:
        machine = args.remote.split(":")
        testhost = machine[0]
        remotepath = machine[1]
        remotemachine = machines.SshMachine(testhost)

    testdesc = TESTS_DIRECTORY / "{}.json".format(maintest)
    try :
        with open(testdesc) as json_data:
            testdata = json.load(json_data)
    except FileNotFoundError as e:
        logerr("Could not open test description '{}'. not found.".format(maintest))
        raise(e)
    except Exception as e:
        logerr("Could not parse test description '{}'".format(maintest))
        raise(e)

    logtitle("Running Tests '{}' on '{}'".format(testdata['title'], testhost))
    logverbose("loaded test description from '{}'".format(testdesc))

    # statistics about runned tests and points
    nsuccess = 0
    nfailed = 0
    nerror = 0
    points = 0
    pointsmax = 0

    runtests = []
    for st in subtests :
        if st == "all" :
             runtests = testdata["tests"]
             break
        else :
            if st not in runtests :
                runtests.append(st)

    for st in runtests :
        try :
            (state, pts, ptsmax) = do_run_test(args, testdata["tests"][st], testhost,
                                             remotemachine, remotepath)
            if state :
                nsuccess = nsuccess + 1
            else :
                nfailed = nfailed + 1
            points = points + pts
            pointsmax = pointsmax + ptsmax
        except Exception as e:
            logerr("Test had an error")
            print(e)
            print(traceback.format_exc())
            nerror = nerror + 1

    # close the remote connection
    if remotemachine != None:
        remotemachine.close()

    # where there any errors?
    if nerror > 0 :
        logwarn("There were {} tests with errors".format(nerror))

    # print the results
    logresult("Test: '{}' - points {} / {} points.  total {} subtests. {} successful, {} failed"
        .format(maintest, points, pointsmax, nsuccess + nfailed + nerror, nsuccess, nfailed))


#----------------------------------------------------------------------------------------
# Wrapper to run all tests supplied in the test args
#----------------------------------------------------------------------------------------

def runtests(args) :
    for t in args.tests :
        runtest(args,t)


#########################################################################################
# Main
#########################################################################################

if __name__ == '__main__':
    "Execution pipeline for building and launching bespin"
    args = parser.parse_args()

    try :
        prepare(args)
        hake(args)
        build(args)
        runtests(args)
    except Exception as e :
        logtitle("Exception occurred")
        logerr("Execution Failed")
        logerr(str(e))
        print(traceback.format_exc())