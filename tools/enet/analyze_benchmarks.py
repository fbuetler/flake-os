import os
import re

from numpy import mean, median, min, max


def main():
    for fname in sorted(os.listdir("./")):
        if not re.match(r".*\.txt$", fname):
            continue

        ms = dict()
        print(f"> {fname}")
        with open(fname) as f:
            prev_process = ""
            for line in f:
                match = re.search(
                    ".*(?P<action>(start|stop)) '(?P<process>.*)'(: (?P<ticks>\d+) ticks)?",
                    line,
                )

                if not match:
                    continue

                action = match.group("action")
                process = match.group("process")

                if action != "stop":
                    prev_process = process
                    continue

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
            print(
                f"  {process:<30} mean: {mean(ticks_list, dtype=int):<8} median: {int(median(ticks_list)):<8} min: {min(ticks_list):<8}  max: {max(ticks_list):<8}  n: {len(ticks_list)}"
            )


if __name__ == "__main__":
    main()
