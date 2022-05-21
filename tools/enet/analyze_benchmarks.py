import os
import re

from numpy import mean


def main():
    pass

    ms = dict()
    for fname in os.listdir("./"):
        if not re.match(r".*\.txt$", fname):
            continue
        with open(fname) as f:
            for l in f:
                match = re.search(
                    ".*stop '(?P<process>.*)'(: (?P<ticks>\d+) ticks)?",
                    l,
                )
                if not match:
                    continue

                process = match.group("process")
                ticks = int(match.group("ticks"))

                if process in ms:
                    ms[process] = ms[process] + [ticks]
                else:
                    ms[process] = [ticks]

    for process, ticks_list in sorted(ms.items()):
        print(f"{process:<30} {mean(ticks_list, dtype=int)}")


if __name__ == "__main__":
    main()
