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

This project provides a fix to that
[bug](https://sourceforge.net/p/launch4j/bugs/190/), by performing the
atomic signing step repeatedly until signature size remains stable
across two consecutive runs. It is written in Java, so it can be
incorporated into the build process on any platform. It can be run as
an Ant task or as a command-line utility.


## Ant Task Usage

Import the `<sign4j>` task definition into your build.xml file with
the following declaration:

```xml
<taskdef resource="com/tuma_solutions/sign4j/antlib.xml"
         classpath="path/to/sign4j-java-4.0-SNAPSHOT.jar"/>
```

### Parameters

| Attribute | Description | Required |
| :-------- | :---------- | :------: |
| file | The target file for the signing operation. If absent, it can possibly be inferred from the command line or from the nested signing task. | No |
| inputfile | The input file that will be signed, if it differs from the target file. | No |
| command | The full command line of an external program that can be run to sign the file. (Discouraged; use a nested signing task, or `executable` and nested `<arg>` elements, instead.) | No |
| executable | The external program that shoule be run to sign the file, without any command line arguments. | No |
| inplace | If true, the file is signed in-place without creating a temporary file. Your signing command must be able to sign twice, replacing the signature when signing the second time. Default is false. | No |
| onthespot | An alias for the inplace attribute. | No |
| lenient | If true, overlook size mismatch errors in the ZIP header of the original file. For example, if the file was previously signed (unsuccesfully) using the `inplace` option, the file will have a corrupt ZIP header. Lenient mode will correct this problem and re-sign. With the default (false), a size mismatch error will disable the sign4j logic, and the file will be passed to the external signing command unmodified. | No |
| maxpasses  | The maximum number of signature passes to attempt. If the signing process runs this many times without generating two consecutive signatures of the same size, the operation will abort and the task will fail. (Default is 10.) | No |
| backup | If true, a backup of the original file will be created and retained after signing is complete. Ignored in command line mode when inputfile and file differ, since the inputfile is not altered. Default is false. | No |
| verbose | If true, more detailed output will be logged. Default is false. | No |

### Parameters specified as nested elements

You must specify the signing operation to be run: either via the
`command` attribute (discouraged), via the `executable` attribute and
nested `<arg>` elements, or via a nested signing task.


#### Nested arg elements

The external signing command can be specified via the `executable`
attribute and nested `<arg>` elements. These take the same form as
those in a standard ant `<exec>` task.

```xml
<sign4j executable="signtool.exe">
    <arg value="sign"/>
    <arg value="/a"/>
    <arg value="/fd"/>
    <arg value="SHA256"/>
    <arg value="MyFile.exe"/>
</sign4j>
```

In the example above, the signtool.exe application is run to sign
MyFile.exe.  The sign4j task infers the target file by scanning the
command line, and finding the last filename with an `.exe` suffix
after all supplied options.

If the command line contains both `-in` and `-out` arguments, these
will be inferred as the (possibly distinct) input and output files.

If your command line does not follow either of those common patterns,
it will be necessary to redundantly specify the target `file` on the
`<sign4j>` tag (along with the `inputfile`, if it is distinct).

If desired, the executable can be provided via the first nested
`<arg>` instead of the `executable` attribute.


#### Nested signing task

An ant task for signing can be provided as the single child of the
sign4j task. The following example uses the
[jsign](https://ebourg.github.io/jsign/) ant task:

```xml
<sign4j>
    <jsign file="MyFile.exe"
           certfile="certificate.spc"
           keyfile="key.pvk"
           keypass="password"
           tsaurl="http://timestamp.digicert.com"/>
</sign4j>
```

If the child task has a "file" attribute, it will be inferred as the
target of the signing operation.  Otherwise, you will need to
redundantly specify the `file` on the `<sign4j>` parent (and the
`inputfile`, if it differs).

When using `<jsign>` as a child task, the `file` can be specified
either on the sign4j or the jsign task. Only one file can be signed at
a time; the fileset capability of jsign is not supported.


## Command-line Usage

Sign4j can be invoked from the command line with:

```
java -jar sign4j-java-4.0-SNAPSHOT.jar [options] <signing command>
```

The `[options]` are similar to those offered by the Ant task:

| Argument | Description |
| -------- | ----------- |
| --onthespot | avoid the creation of a temporary file (your tool must be able to sign twice) |
| --lenient | overlook ZIP header errors in the input file |
| --maxpasses N | abort if the file cannot be signed after N attempts (default is 10) |
| --backup | retain a backup of the original file before signing |
| --verbose | show diagnostics about intermediary steps of the process |

The full command line for your `<signing command>` must be provided;
this command line will be run repeatedly to sign the file. Inference
of the input and target files is performed by scanning the command
line, as described above for the ant task.

```
java -jar sign4j-java-4.0-SNAPSHOT.jar --verbose signtool.exe sign /a /fd SHA256 MyFile.exe
```

The example above uses signtool.exe to sign MyFile.exe automatically
by using the best certificate.


## Credits

The logic in this utility was patterned after the [original sign4j.c
tool](https://sourceforge.net/p/launch4j/git/ci/master/tree/sign4j/),
copyright (c) 2012 Servoy `<bramfeld@diogen.de>`.

Modifications to sign repeatedly, and to invoke directly from ant,
copyright (c) 2025 David Tuma `<sign4j@tuma-solutions.com>`.


## License

This utility is freely available for use, modification, and
redistribution under the 
[3-clause BSD license](https://opensource.org/license/bsd-3-clause).
