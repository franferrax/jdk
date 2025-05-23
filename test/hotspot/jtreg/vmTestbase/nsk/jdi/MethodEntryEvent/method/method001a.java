/*
 * Copyright (c) 2001, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package nsk.jdi.MethodEntryEvent.method;

import nsk.share.*;
import nsk.share.jpda.*;
import nsk.share.jdi.*;

import java.io.*;

//    THIS TEST IS LINE NUMBER SENSITIVE
// This class is the debugged application in the test
public class method001a {

    // exit status constants
    static final int PASSED = 0;
    static final int FAILED = 2;
    static final int JCK_STATUS_BASE = 95;

    // synchronization commands
    static final String COMMAND_READY = "ready";
    static final String COMMAND_QUIT  = "quit";
    static final String COMMAND_GO    = "go";
    static final String COMMAND_DONE  = "done";

    // line numbers for auxilary breakpoints
    public static final int STARTING_BREAKPOINT_LINE = 89;
    public static final int ENDING_BREAKPOINT_LINE = 94;

    // scaffold objects
    static private ArgumentHandler argHandler;
    static private Log log;
    static private IOPipe pipe;

    // flags and counters
    static private int flag;
    static private int depth;
    static private boolean methodInvoked;

    static Thread mainThread = null;

    // start debuggee
    public static void main(String args[]) {
        method001a _method001a = new method001a();
        mainThread = Thread.currentThread();
        System.exit(JCK_STATUS_BASE + _method001a.run(args, System.err));
    }

    // perform the test
    int run(String args[], PrintStream out) {
        argHandler = new ArgumentHandler(args);
        log = new Log(out, argHandler);
        pipe = argHandler.createDebugeeIOPipe();

        depth = 10;
        flag = 0;

        // notify debugger that debuggee has been started
        pipe.println(COMMAND_READY);

        // wait for GO commnad from debugger
        String command = pipe.readln();
        if (!command.equals(COMMAND_GO)) {
            log.complain("TEST BUG: Debugee: unknown command: " + command);
            return FAILED;
        }

        methodInvoked = false; // STARTING_BREAKPOINT_LINE

        // invoke checked method
        foo();

        methodInvoked = true; // ENDING_BREAKPOINT_LINE

        // notify debugger that checked method has been invoked
        pipe.println(COMMAND_DONE);

        // wait for command QUIT from debugger
        command = pipe.readln();
        if (!command.equals(COMMAND_QUIT)) {
            System.err.println("TEST BUG: Debugee: unknown command: " + command);
            return FAILED;
        }

        return PASSED;
    }

    // checked method
    void foo() {
        flag++;
        if (depth > 1) {
            depth--;
            flag--;
            foo();
        }
    }
}
