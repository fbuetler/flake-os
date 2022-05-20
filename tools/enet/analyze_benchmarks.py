import os
import re


def main():
    pass

    for fname in os.listdir("./"):
        if not re.match(r".*\.txt$", fname):
            continue
        with open(fname) as f:
            for l in f:
                match = re.search(
                    ".*(?P<action>(start)|(stop)) '(?P<process>.*)'(: (?P<ticks>\d+) ticks)?",
                    l,
                )

                print(match.group("action"))
                print(match.group("process"))
                print(match.group("ticks"))


if __name__ == "__main__":
    main()
