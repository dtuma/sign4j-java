// Sign4j.java: a Java utility to sign executables created by Launch4j
//
// Copyright (c) 2025 David Tuma
// Based on sign4j.c, copyright (c) 2012 Servoy
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above
//    copyright notice, this list of conditions and the following
//    disclaimer in the documentation and/or other materials provided
//    with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.tuma_solutions.sign4j;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.util.Arrays;


/**
 * Java reimplementation of the sign4j logic provided by the launch4j project.
 * 
 * Launch4j creates EXE files by wrapping JAR files. Signing the resulting EXE
 * files is tricky, because the appended signature makes the JAR file invalid.
 * To fix this, launch4j provides a "sign4j.c" program that cleverly tweaks the
 * JAR file to make it look like the signature is part of a terminal ZIP
 * comment.
 * 
 * Unfortunately, the logic in sign4j.c assumes the appended signature will be
 * the same number of bytes from one run to the next. This is not the case for
 * some signing algorithms, especially when timestamping is enabled.
 * 
 * This class resolves the problem by signing a file repeatedly until the
 * signature size matches in two successive passes. This approach has a good
 * chance of success if the sizes are not completely unstable from one run to
 * the next.
 */
public class Sign4j {

    public static final String SIGN4J_VERSION = "4.0 (Java)";


    public static void main(String[] args) {
        // create a sign4j task and run it
        Sign4j sign4j = new Sign4j();
        try {
            sign4j.setCmdLine(args);
            sign4j.execute();

        } catch (Failure f) {
            // if any error occurs, display the message
            System.err.println(f.getMessage());
            if (sign4j.isVerbose() && f.getCause() != null)
                f.getCause().printStackTrace();
            System.exit(1);
        }
    }



    private String[] cmdLine;

    private Runnable signingTask;

    private File baseDir;

    private boolean inPlace;

    private boolean lenient;

    private int maxSignaturePasses;

    private boolean verbose;

    private boolean backupOriginal;

    private File inputFile;

    private int inputFilePos;

    private File targetFile;

    private File fileToDelete;

    private long originalFileSize;

    private int originalCommentSize;

    private long commentSizeOffset;


    public Sign4j() {
        this.cmdLine = new String[0];
        this.maxSignaturePasses = 10;
    }

    public String[] getCmdLine() {
        return cmdLine;
    }

    public void setCmdLine(String[] cmdLine) {
        this.cmdLine = cmdLine;
    }

    public Runnable getSigningTask() {
        return signingTask;
    }

    public void setSigningTask(Runnable signingTask) {
        this.signingTask = signingTask;
    }

    public File getBaseDir() {
        return baseDir;
    }

    public void setBaseDir(File baseDir) {
        this.baseDir = baseDir;
    }

    public File getInputFile() {
        return inputFile;
    }

    public void setInputFile(File inputFile) {
        this.inputFile = inputFile;
    }

    public File getFile() {
        return this.targetFile;
    }

    public void setFile(File file) {
        this.inputFile = this.targetFile = file;
    }

    public boolean isInPlace() {
        return inPlace;
    }

    public void setInPlace(boolean inPlace) {
        this.inPlace = inPlace;
    }

    public boolean isLenient() {
        return lenient;
    }

    public void setLenient(boolean lenient) {
        this.lenient = lenient;
    }

    public int getMaxSignaturePasses() {
        return maxSignaturePasses;
    }

    public void setMaxSignaturePasses(int maxSignaturePasses) {
        this.maxSignaturePasses = Math.max(2, maxSignaturePasses);
    }

    public void setMaxSignaturePasses(String maxSignaturePasses) {
        try {
            setMaxSignaturePasses(Integer.parseInt(maxSignaturePasses));
        } catch (NumberFormatException nfe) {
            throw new Failure(usage());
        }
    }

    public boolean isVerbose() {
        return verbose;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public boolean isBackupOriginal() {
        return backupOriginal;
    }

    public void setBackupOriginal(boolean backupOriginal) {
        this.backupOriginal = backupOriginal;
    }


    public void execute() {
        try {
            executeImpl();
        } finally {
            copyBuffer = null;
            if (fileToDelete != null)
                fileToDelete.delete();
        }
    }

    private void executeImpl() {
        // get the name of the file to process
        parseCommandLineOptions();
        originalFileSize = inputFile.length();
        if (!inputFile.isFile() || originalFileSize == 0)
            throw new Failure("File does not exist: " + inputFile);

        // find the zip header and read the initial size of the zip comment
        boolean isZip = findZipHeaderMetadata();

        // identify a file to use for temp/backup purposes
        File cleanFile = null;
        if (isZip && !inPlace && inputFile.equals(targetFile)) {
            // if not signing in place, backup the input for repeated signing
            cleanFile = backupInputFile();
        } else if (isZip && inputFilePos > 0 && !inputFile.equals(targetFile)) {
            // if -in and -out were different files, backup the input file and
            // work against the backup so the input file remains unmodified
            backupOriginal = false;
            cleanFile = inputFile;
            inputFile = backupInputFile();
            cmdLine[inputFilePos] = inputFile.getPath();
        } else if (backupOriginal) {
            // backup the input file if requested by configuration
            backupInputFile();
        }

        // repeatedly sign the file, tweaking the size of the terminal ZIP
        // comment, until the signature size exactly matches the tweak we wrote
        int signatureSize = 0;
        int passCount = 0;
        while (true) {
            if (passCount == 0)
                System.out.println("Signing file " + targetFile);
            else if (verbose)
                System.out.println("Re-signing with signature size " //
                        + signatureSize);

            if (passCount > 0) {
                if (cleanFile != null)
                    copyFile(cleanFile, inputFile);
                writeNewSignatureSize(inputFile, signatureSize);
            }

            signFile();

            long thisSigSize = targetFile.length() - originalFileSize;
            if (thisSigSize == signatureSize || !isZip)
                break;
            else
                signatureSize = (int) thisSigSize;

            if (++passCount == maxSignaturePasses)
                throw new Failure("No consistent signature size seen after "
                        + maxSignaturePasses + " passes");
        }
    }


    private void parseCommandLineOptions() {
        // scan the first few arguments looking for sign4j options
        int i;
        for (i = 0; i < cmdLine.length; i++) {
            String arg = cmdLine[i];
            if (!arg.startsWith("-"))
                break;
            else if (arg.equals("--onthespot"))
                setInPlace(true);
            else if (arg.equals("--lenient"))
                setLenient(true);
            else if (arg.equals("--maxpasses") && i < cmdLine.length - 1)
                setMaxSignaturePasses(cmdLine[++i]);
            else if (arg.equals("--backup"))
                setBackupOriginal(true);
            else if (arg.equals("--verbose"))
                setVerbose(true);
        }

        // if any sign4j options were found and processed, remove them from
        // the beginning of the command line
        if (i > 0) {
            String[] signingCmd = new String[cmdLine.length - i];
            System.arraycopy(cmdLine, i, signingCmd, 0, signingCmd.length);
            cmdLine = signingCmd;
        }

        // if this object was preconfigured with input and target files, find
        // the position of the input file arg in the command line
        if (inputFile != null && targetFile != null) {
            inputFilePos = findInputFileArg();
            return;
        }

        // scan the rest of the arguments to find the filenames to process
        File sawFile = null;
        for (i = 1; i < cmdLine.length; i++) {
            String arg = cmdLine[i];
            if (arg.equals("-in") && i < cmdLine.length - 1) {
                inputFile = sawFile = getFileArg(cmdLine[inputFilePos = ++i]);
            } else if ("-out".equals(arg) && i < cmdLine.length - 1) {
                targetFile = sawFile = getFileArg(cmdLine[++i]);
            } else if (arg.startsWith("-")
                    || (arg.startsWith("/") && arg.length() < 5)) {
                if (sawFile == null)
                    inputFile = targetFile = null;
            } else if (sawFile == null && arg.toLowerCase().endsWith(".exe")) {
                inputFile = targetFile = getFileArg(arg);
            }
        }

        // ensure files were found
        if (inputFile == null || targetFile == null)
            throw new Failure(usage());
    }

    private int findInputFileArg() {
        // if there is a "-in" argument, trust that the input file follows it
        int pos = Arrays.asList(cmdLine).indexOf("-in") + 1;
        if (pos > 1 && pos < cmdLine.length)
            return pos;

        // search the command line, looking for a file with the same name
        String filename = inputFile.getName().toLowerCase();
        for (int i = 1; i < cmdLine.length; i++) {
            if (cmdLine[i].toLowerCase().endsWith(filename))
                return i;
        }

        // the input file was not found in the command line
        return -1;
    }

    private File getFileArg(String arg) {
        arg = arg.replace('/', File.separatorChar);
        arg = arg.replace('\\', File.separatorChar);
        File file = new File(arg);
        try {
            if (baseDir != null && !file.isAbsolute())
                file = new File(baseDir, arg);
            file = file.getCanonicalFile();
        } catch (IOException ioe) {
        }
        return file;
    }


    private File backupInputFile() {
        // add "-presign" to the end of the filename (before the extension)
        String filename = inputFile.getName();
        String backupName = filename.substring(0, filename.length() - 4)
                + "-presign.exe";
        File backupFile = new File(inputFile.getParentFile(), backupName);

        // copy the input file to the backup
        if (backupFile.exists() && !backupFile.delete())
            throw new Failure("Couldn't delete backup file " + backupFile);
        copyFile(inputFile, backupFile);
        if (!backupOriginal)
            fileToDelete = backupFile;

        return backupFile;
    }


    private boolean findZipHeaderMetadata() {
        FileInputStream in = null;
        try {
            // create a buffer for scanning the end of the file
            int bufLen = (int) Math.min(originalFileSize,
                END_HEADER_SIZE + MAX_COMMENT_SIZE);
            long bufOffset = originalFileSize - bufLen;
            byte[] buffer = new byte[bufLen];

            // open the file and read the final portion into the buffer
            in = new FileInputStream(inputFile);
            in.getChannel().position(bufOffset);
            if (in.read(buffer) != bufLen)
                throw new IOException("Problem reading ZIP end buffer");

            // scan the buffer, looking for the ZIP end header
            boolean sawBadSize = false;
            for (int pos = bufLen - END_HEADER_SIZE; pos >= 0; pos--) {
                if (isZipEndHeaderStart(buffer, pos)) {
                    int headerEnd = pos + END_HEADER_SIZE;
                    int sizePos = headerEnd - 2;
                    commentSizeOffset = sizePos + bufOffset;

                    if (lenient) {
                        // in lenient mode, overlook errors in the original ZIP
                        // comment size. For example, if the file was previously
                        // signed (unsuccessfully) using "in place" mode, the
                        // comment size in the ZIP header might be wrong.
                        // Lenient mode ignores the size in the ZIP header and
                        // computes a new effective value from the file size.
                        originalCommentSize = bufLen - headerEnd;
                        return true;

                    } else {
                        // when lenient mode is off, double-check the ZIP
                        // comment size. If it's wrong, consider this file not
                        // to be a ZIP at all, and proceed without sign4j logic.
                        originalCommentSize = ((buffer[sizePos] & 0xFF)
                                | ((buffer[sizePos + 1] << 8) & 0xFF00));
                        if (headerEnd + originalCommentSize == bufLen)
                            return true;
                        else
                            sawBadSize = true;
                    }
                }
            }

            // if we found a ZIP header with an incorrect size, print a warning
            if (sawBadSize) {
                System.err.println("WARNING: Size mismatch in ZIP header; proceeding without sign4j logic.");
                System.err.println("    Create a clean file to sign, or re-run with lenient option.");
            } else {
                // if no ZIP header was found, print an informational message
                System.out.println("You don't need sign4j to sign this file");
            }

            // no valid ZIP header was found
            return false;

        } catch (IOException ioe) {
            throw new Failure("Unable to read file " + inputFile, ioe);
        } finally {
            safelyClose(in);
        }
    }

    private boolean isZipEndHeaderStart(byte[] buffer, int pos) {
        for (int i = ZIP_END_HEADER.length; i-- > 0;) {
            if (buffer[pos + i] != ZIP_END_HEADER[i])
                return false;
        }
        return true;
    }


    private byte[] copyBuffer;

    private void copyFile(File src, File dest) {
        FileInputStream in = null;
        FileOutputStream out = null;
        try {
            in = new FileInputStream(src);
            out = new FileOutputStream(dest);

            if (copyBuffer == null)
                copyBuffer = new byte[COPY_BUF_SIZE];

            int bytesRead;
            while ((bytesRead = in.read(copyBuffer)) != -1)
                out.write(copyBuffer, 0, bytesRead);

        } catch (Exception ioe) {
            throw new Failure("Unable to write data to " + dest, ioe);

        } finally {
            safelyClose(in);
            safelyClose(out);
        }
    }

    private void writeNewSignatureSize(File file, int signatureSize) {
        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(file, "rw");
            raf.seek(commentSizeOffset);

            int newCommentSize = signatureSize + originalCommentSize;
            raf.write(newCommentSize & 0xFF);
            raf.write((newCommentSize >> 8) & 0xFF);

        } catch (Exception ioe) {
            throw new Failure("Unable to write signature size to " + file);
        } finally {
            safelyClose(raf);
        }
    }

    private void signFile() {
        if (signingTask != null) {
            signingTask.run();
            return;
        }

        int exitCode;
        try {
            Process process = Runtime.getRuntime().exec(cmdLine, null, baseDir);
            exitCode = waitForProcess(process, verbose);

        } catch (Exception e) {
            throw new Failure("Unexpected error signing file " + targetFile, e);
        }

        if (exitCode != 0)
            throw new Failure("Unable to sign file " + targetFile);
    }

    /**
     * Consume the output generated by a process until it completes, and return
     * its exit value.
     * 
     * The javadoc for the Runtime.exec() method casually mentions that if you
     * launch a process which generates output (to stdout or stderr), you must
     * consume that output, or the process will become blocked when its
     * OS-provided output buffers become full. This method consumes process
     * output, as required, while waiting for it to terminate.
     */
    private static int waitForProcess(Process p, boolean copyOutput) {

        int exitValue = -1; // returned to caller when p is finished

        try {

            InputStream in = p.getInputStream();
            InputStream err = p.getErrorStream();

            boolean finished = false; // Set to true when p is finished

            while (!finished) {
                try {
                    int c;

                    while (in.available() > 0 && (c = in.read()) != -1)
                        // copy stdout from child process if requested
                        if (copyOutput)
                            System.out.write(c);
                    System.out.flush();

                    while (err.available() > 0 && (c = err.read()) != -1)
                        // always copy stderr from the child process
                        System.err.write(c);
                    System.err.flush();

                    // Ask the process for its exitValue. If the process
                    // is not finished, an IllegalThreadStateException
                    // is thrown. If it is finished, we fall through and
                    // the variable finished is set to true.

                    exitValue = p.exitValue();
                    finished = true;

                } catch (IllegalThreadStateException e) {

                    // Process is not finished yet;
                    // Sleep a little to save on CPU cycles
                    Thread.sleep(10);
                }
            }


        } catch (Exception e) {
        }

        // return completion status to caller
        return exitValue;
    }


    private static void safelyClose(Closeable c) {
        try {
            if (c != null)
                c.close();
        } catch (IOException ioe) {
        }
    }



    protected static class Failure extends RuntimeException {

        public Failure(String m) {
            super(m);
        }

        public Failure(String m, Throwable t) {
            super(m, t);
        }
    }

    private static final String usage() {
        return String.join(System.lineSeparator(),
            "This is sign4j version " + SIGN4J_VERSION, "", //
            "Usage: sign4j [options] <arguments>", //
            "", //
            "  [options] may include:",
            "    --onthespot    avoid the creation of a temporary file (your tool must be",
            "                   able to sign twice)", //
            "    --lenient      overlook ZIP header errors in the input file (for example,",
            "                   if an unsuccesful attempt has already been made to sign",
            "                   the file in the past)", //
            "    --maxpasses N  abort if the file cannot be signed after N attempts",
            "                   (default is 10)",
            "    --backup       retain a backup of the original file before signing",
            "    --verbose      show diagnostics about intermediary steps of the process",
            "", //
            "  <arguments> must specify verbatim the command line for your signing tool.",
            "              Only one file can be signed on each invocation");
    }



    private static final byte[] ZIP_END_HEADER = { 0x50, 0x4B, 0x05, 0x06 };

    private static final int END_HEADER_SIZE = 22;

    private static final int MAX_COMMENT_SIZE = 0xFFFF;

    private static final int COPY_BUF_SIZE = 4 * 1024 * 1024;

}
