// Copyright (C) 2025 Tuma Solutions, LLC
// Process Dashboard - Data Automation Tool for high-maturity processes
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 3
// of the License, or (at your option) any later version.
//
// Additional permissions also apply; see the README-license.txt
// file in the project root directory for more information.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//
// The author(s) may be contacted at:
//     processdash@tuma-solutions.com
//     processdash-devel@lists.sourceforge.net

package com.tuma_solutions.sign4j;

import java.io.File;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.RuntimeConfigurable;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.TaskContainer;
import org.apache.tools.ant.types.Commandline;


public class Sign4jTask extends Task implements TaskContainer {

    private Commandline cmdLine;

    private Task signingTask;

    private File file;

    private File inputFile;

    private boolean inPlace;

    private boolean lenient;

    private int maxPasses;

    private boolean backupOriginal;

    private boolean verbose;

    public Sign4jTask() {
        this.cmdLine = new Commandline();
        this.inPlace = false;
        this.lenient = false;
        this.maxPasses = -1;
        this.backupOriginal = false;
        this.verbose = false;
    }

    public void setInplace(boolean inPlace) {
        this.inPlace = inPlace;
    }

    public void setOnthespot(boolean onTheSpot) {
        this.inPlace = onTheSpot;
    }

    public void setLenient(boolean lenient) {
        this.lenient = lenient;
    }

    public void setMaxpasses(int maxPasses) {
        this.maxPasses = maxPasses;
    }

    public void setBackup(boolean backup) {
        this.backupOriginal = backup;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public void setExecutable(String value) {
        cmdLine.setExecutable(value);
    }

    public void setCommand(String line) {
        createArg().setLine(line);
    }

    public Commandline.Argument createArg() {
        return cmdLine.createArgument();
    }

    @Override
    public void addTask(Task task) {
        if (this.signingTask == null)
            this.signingTask = task;
        else
            throw new BuildException("Only one nested signing task allowed.");
    }

    public void setFile(File file) {
        this.file = file;
    }

    public void setInputfile(File inputFile) {
        this.inputFile = inputFile;
    }

    @Override
    public void execute() throws BuildException {
        // validate configuration
        String[] signingCmd = cmdLine.getCommandline();
        if (signingTask != null) {
            if (signingCmd.length > 0)
                throw new BuildException("You must provide either a signing "
                        + "command line, or a nested signing task; but not both.");
            syncFileAttrWithSigningTask();

        } else if (signingCmd.length == 0) {
            throw new BuildException("The signing operation must be "
                    + "specified; either with the 'command' attribute, "
                    + "with nested <arg> elements, or with a nested "
                    + "signing task.");
        }

        try {
            Sign4j s = new Sign4j();
            if (signingCmd.length > 0)
                s.setCmdLine(signingCmd);
            if (signingTask != null)
                s.setSigningTask(new SigningTaskExecutor());
            s.setBaseDir(getProject().getBaseDir());
            s.setFile(file);
            if (inputFile != null)
                s.setInputFile(inputFile);
            s.setInPlace(inPlace);
            s.setLenient(lenient);
            if (maxPasses != -1)
                s.setMaxSignaturePasses(maxPasses);
            s.setBackupOriginal(backupOriginal);
            s.setVerbose(verbose);
            s.execute();

        } catch (Sign4j.Failure f) {
            throw new BuildException(f.getMessage(), f.getCause(),
                    getLocation());
        }
    }

    private void syncFileAttrWithSigningTask() {
        RuntimeConfigurable rc = signingTask.getRuntimeConfigurableWrapper();
        if (file == null) {
            // if no file attribute was provided on this task, try to read it
            // from the signingTask
            String childAttr = (String) rc.getAttributeMap().get("file");
            if (childAttr == null)
                throw new BuildException("You must provide a file argument "
                        + "when using a nested signing task.");

            // resolve placeholders and relative file paths
            String filename = getProject().replaceProperties(childAttr);
            file = getProject().resolveFile(filename);

        } else if (signingTask.getTaskType().equals("jsign")) {
            // if a file attribute was provided on this task, copy it down to
            // a jsign child task. (If the child task isn't jsign, we don't
            // know if it uses a file attribute, so we can't risk copying.)
            rc.setAttribute("file", file.getPath());
        }
    }


    private class SigningTaskExecutor implements Runnable {
        @Override
        public void run() {
            // run the signing task
            signingTask.perform();
            // afterwards, re-register this as the active task
            getProject().registerThreadTask(Thread.currentThread(),
                Sign4jTask.this);
        }
    }

}
