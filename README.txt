objdot.pl - generate callflow graphs through static analysis
            using objdump and dot/graphviz

by Matthias Wenzel a.k.a. mazzoo in 2010

software license: GPLv3

usage
~~~~~

./objdot.pl myBIOS.bin

by default myBIOS.bin will be disassembled from the reset vector
of a x86 CPU in 16 bit mode. For all other settings use the source.

bugs
~~~~

- many
- switching CPU mode is more than crappy

