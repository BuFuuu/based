# Based

What's on your Omarchy that Omarchy didn't put there.

![The Based window: a timeline of what is new on the system, most unusual first](preview.png)

## The idea

Omarchy puts a known set of things on your computer. Based shows you
everything else: what came later, and when. It only looks; it never changes
or deletes anything.

It is not an antivirus: it does not scan for virus signatures.

**An example:** you install an app from the AUR. It quietly brings along
another package you never chose. Based lists that package as new, with the
day it came and how unusual it is. You press `p` and ask your AI what it is
and why it is there.

## Install

```sh
git clone https://github.com/BuFuuu/based.git && based/install.sh
```

This adds the `based` program and the bar icon. Remove both with
`based/install.sh --uninstall`.

## Use

Left click the bar icon to open Based, right click to scan.

| Tab | Shows |
|---|---|
| Timeline | everything new, most unusual first |
| Overview | every folder, and how much is new in it |
| Persistence | things that start by themselves |
| Network | programs that talk to the network right now |
| Accepted | what you marked as known |

`tab` next tab · `enter` open · click copies the path · `p` question for your
AI · `a` accept · `A` accept the folder · `r` scan · `R` scan as root ·
`h` help · `q` quit

## More

How Based decides what is unusual, what it reads and writes, its limits and
the command line: [docs/details.md](docs/details.md).

MIT license.
