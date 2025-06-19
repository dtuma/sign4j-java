# sign4j-java

The [launch4j project](https://launch4j.sourceforge.net/) provides
functionality to create Windows EXE files from Java JAR files. One
piece of that solution is sign4j, a utility that assists in the
signing of launch4j EXEs.

Sign4j provides a clever solution to a tricky problem: signing the EXE
causes Java to believe the JAR file is corrupt, and repairing that
corruption causes the signature to become invalid. Sign4j solves this
problem by fixing and signing the file atomically.

Unfortunately, the original sign4j utility assumes that the signature
will contain the exact same number of bytes from one run to the
next. This is not the case for some signing algorithms - especially
when timestamping is enabled. When the signature size changes between
runs, the original sign4j utility produces an EXE that appears valid
to Windows, but is corrupt to Java.

This project provides a fix to that bug, by performing the atomic
signing step repeatedly until signature size remains stable across two
consecutive runs.
