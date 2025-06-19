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
        Sign4j sign4j = new Sign4j(args);
        try {
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

    private boolean verbose;

    private boolean backupOriginal;

    private File targetFile;

    private long originalFileSize;

    private int originalCommentSize;

    private long commentSizeOffset;

    private File backupFile;


    public Sign4j(String[] cmdLine) {
        this.cmdLine = cmdLine;
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
        }
    }

    private void executeImpl() {
        // get the name of the file to process
        parseCommandLineOptions();
        String targetFilename = findExe();
        try {
            targetFile = new File(targetFilename).getCanonicalFile();
        } catch (IOException ioe) {
            targetFile = new File(targetFilename);
        }
        originalFileSize = targetFile.length();
        if (!targetFile.isFile() || originalFileSize == 0)
            throw new Failure("File does not exist: " + targetFile);

        // identify a file to use for temp/backup purposes
        backupFile = getBackupFile();
        if (backupFile.exists() && !backupFile.delete())
            throw new Failure("Couldn't delete backup file " + backupFile);

        // find the zip header and read the initial size of the zip comment
        boolean isZip = findZipHeaderMetadata();
        if (!isZip) {
            System.out.println("You don't need sign4j to sign this file");
            System.out.println("Signing file " + targetFile);
            if (backupOriginal)
                copyFile(targetFile, backupFile, 0);
            signFile();
            return;
        }

        // keep a copy of the original file before modifications
        if (!targetFile.renameTo(backupFile))
            throw new Failure("Couldn't move file " + targetFile);

        // repeatedly sign the file, tweaking the size of the terminal ZIP
        // comment, until the signature size exactly matches the tweak we wrote
        int signatureSize = 0;
        while (true) {
            System.out.println(signatureSize == 0 //
                    ? "Signing file " + targetFile //
                    : "    Resigning with signature size " + signatureSize);

            copyFile(backupFile, targetFile, signatureSize);

            signFile();

            long thisSigSize = targetFile.length() - originalFileSize;
            if (thisSigSize == signatureSize)
                break;
            else
                signatureSize = (int) thisSigSize;
        }

        // delete the backup file after successful signing
        if (!backupOriginal)
            backupFile.delete();
    }


    private void parseCommandLineOptions() {
        // scan the first few arguments looking for sign4j options
        int i;
        for (i = 0; i < cmdLine.length; i++) {
            String arg = cmdLine[i];
            if (!arg.startsWith("-"))
                break;
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
    }

    private String findExe() {
        for (int i = cmdLine.length; i-- > 1;) {
            String arg = cmdLine[i];
            if (arg.toLowerCase().endsWith(".exe")) {
                String file = arg;
                file = file.replace('/', File.separatorChar);
                file = file.replace('\\', File.separatorChar);
                return file;
            }
        }
        throw new Failure(usage());
    }


    private File getBackupFile() {
        // add "-presign" to the end of the filename (before the extension)
        String filename = targetFile.getName();
        String backupName = filename.substring(0, filename.length() - 4)
                + "-presign.exe";
        return new File(targetFile.getParentFile(), backupName);
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
            in = new FileInputStream(targetFile);
            in.getChannel().position(bufOffset);
            if (in.read(buffer) != bufLen)
                throw new IOException("Problem reading ZIP end buffer");

            // scan the buffer, looking for the ZIP end header
            for (int pos = bufLen - END_HEADER_SIZE; pos >= 0; pos--) {
                if (isZipEndHeaderStart(buffer, pos)) {
                    int headerEnd = pos + END_HEADER_SIZE;
                    int sizePos = headerEnd - 2;
                    originalCommentSize = ((buffer[sizePos] & 0xFF)
                            | ((buffer[sizePos + 1] << 8) & 0xFF00));
                    if (headerEnd + originalCommentSize == bufLen) {
                        commentSizeOffset = sizePos + bufOffset;
                        return true;
                    }
                }
            }

            // no ZIP header was found
            return false;

        } catch (IOException ioe) {
            throw new Failure("Unable to read file " + targetFile, ioe);
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

    private void copyFile(File src, File dest, int signatureSize) {
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

            if (signatureSize > 0) {
                int newCommentSize = signatureSize + originalCommentSize;
                out.getChannel().position(commentSizeOffset);
                out.write(newCommentSize & 0xFF);
                out.write((newCommentSize >> 8) & 0xFF);
            }

        } catch (Exception ioe) {
            throw new Failure("Unable to write data to " + dest, ioe);

        } finally {
            safelyClose(in);
            safelyClose(out);
        }
    }

    private void signFile() {
        int exitCode;
        try {
            Process process = Runtime.getRuntime().exec(cmdLine);
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
