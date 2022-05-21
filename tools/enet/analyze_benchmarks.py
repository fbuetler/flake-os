import os
import re

from numpy import mean


def main():
    ms = dict()
    for fname in os.listdir("./"):
        if not re.match(r".*\.txt$", fname):
            continue

        with open(fname) as f:
            prev_process = ""
            for line in f:
                match = re.search(
                    ".*stop '(?P<process>.*)'(: (?P<ticks>\d+) ticks)?",
                    line,
                )
                if not match:
                    continue

                process = match.group("process")
                ticks = int(match.group("ticks"))

                if len(prev_process) != 0 and prev_process != process:
                    # interleaving benchmarks take print statements into account
                    print(f"WARN: interleaving benchmarks ({prev_process}, {process})")

                if process in ms:
                    ms[process] = ms[process] + [ticks]
                else:
                    ms[process] = [ticks]

                prev_process = process

    for process, ticks_list in sorted(ms.items()):
        print(f"{process:<30} {mean(ticks_list, dtype=int):<8} ({len(ticks_list)})")


if __name__ == "__main__":
    main()
