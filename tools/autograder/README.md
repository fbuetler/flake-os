# AOS Autograding Tool

This is a basic autograding tool. It compiles your code and you can specify tests that are run.

**Note to AOS Students: We will overwrite this tool with our own version for running tests.**


## Dependencies

It's written in Python3 using pexpect and plumbum.

```
apt-get install python3 python3-pexpect  python3-plumbum
```

## Configuration Options


The paths and tools used in this grader are defined in the configuration options on top of the
file. There you can specify the make targets, image files, scripts and tools used.


## Specifying Tests

All test specifications are located in the `./test` directory of this folder. We use json to
specify the tests. Each json file can define a group of tests. For example, you can define
several tests that exercise a subsystem of your project.

The basic structure is as follows, where `tests` is a dictionary of tests.

```
{
    "title" : "Memory Management",
    "tests" : {
    }
}
```

Each entry of the `tests` dictionary has the following structure:

```
"testname" : {
    "title" :  "Malloc Test",
    "modules" : [
        ["armv8/sbin/mallocfree", "-n", "1000"]
    ],
    "teststeps" : [ ],
    "timeout" : 20
}
```

The `testname` is used to find the test specification as supplied from the command line
(see Running Tests). It should be chosen to be unique and must not contain `:`. The `title` gives
this test a name. The infrastucture takes the menu.lst file in the hake directory
e.g. `hake/menu.lst.armv8_imx8x`to figure out the basic modules and adds the modules listed.
Each module is a list of the path to the binary and all its arguments. The `timeout` defines a
timeout for this test in seconds.

Each test consists of a number of `teststeps` which define actions of the test. This is a list
of actions:

**wait** - Instructs the test to wait for some time.
```
{ "action" : "wait", "seconds" : 3 },
```

**input** - Sends a string to the serial console. (Keyboard input)
```
{ "action" : "input", "value"  : "m4_grading memif-alloc-single" },
```

**reboot** - Reboots the platform
```
{ "action" : "reboot" },
```

**expect** - Parses the output for an expected value.
```
{
"action" : "expect",
"pass" : ["Test succeeded."],
"fail" : ["Failed to malloc memory"],
"points" : 0
},
```
You can specify matching strings (or regex) that will make the test `pass` e.g. you print "Test succeeded."
in the code. To avoid false positives, you can also include strings that make the test `fail`, those
have precedent over the passing strings. Lastly you can assing `points` to this test.


## Test Specification Example

Here is a complete example test specification `mm.json' which defines two tests.

```
{
    "title" : "Memory Management",
    "tests" : {
        "Malloc-Small" : {
            "title" :  "Malloc() - Small Memory Region",
            "modules" : [
                ["armv8/sbin/mmtest"]
            ],
            "teststeps" : [
                {
                    "action" : "input",
                    "value"  : "mmtest malloc-small"
                },
                {
                    "action" : "expect",
                    "pass" : ["Completed test 'mmtest malloc-small' - SUCCESS"],
                    "fail" : [],
                    "points" : 2
                }
            ],
            "timeout" : 20
        },
        "Malloc-Medium" : {
            "title" :  "Malloc() - Medium Memory Region",
            "modules" : [
                ["armv8/sbin/mmtest"]
            ],
            "teststeps" : [
                {
                    "action" : "input",
                    "value"  : "mmtest malloc-medium"
                },
                {
                    "action" : "expect",
                    "pass" : ["Completed test 'mmtest malloc-medium' - SUCCESS"],
                    "fail" : [],
                    "points" : 2
                }
            ],
            "timeout" : 20
        }
    }
}
```


## Running Tests

The script has a few command line options to control the test execution e.g. which board to use
or the USB where the serial is attached. See the output when supplying the `-h` parameter.

You can specify tests to be run using the `-t` or `--tests` parameter followed by a list of test
To run the tests of the example above, you can do this as follows:

```
python3 autograder.py -t mm:Malloc-Small:Malloc-Medium
```

This will run the two tests `Malloc-Small` and `Malloc-Medium` in the `mm` test specification file.
If you want to run all tests in a given file you can do this as:

```
python3 autograder.py -t mm:all
```

Note, the test file specifyes the json file in the `./tests` directory. Here it looks for the file
`./tests/mm.json`

To run the tests remotely specify the machine and path where to install it.
```
python3 autograder.py -t mm:all --remote machine.ethz.ch:/path/to/install
```