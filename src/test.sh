#!/usr/bin/env bash
#
# Copyright (c) 2023, Red Hat, Inc.
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

ALT_JAVA_PATH="$1"
JAVA_PATH="$2"

# Validate alt-java executable path
if ! [ -x "$ALT_JAVA_PATH" ]; then
    echo "ERROR: $ALT_JAVA_PATH does not seem to be an existing executable" 1>&2 && exit 2
else
    cp "$ALT_JAVA_PATH" ./alt-java
fi

# Validate java executable path
if [ "$JAVA_PATH" ]; then
    echo "Using specified JAVA_PATH=$JAVA_PATH"
else
    echo "Searching java in \$PATH, to use a different binary, invoke as 'make JAVA_PATH=/path/to/java ...'"
    JAVA_PATH=$(which java)
    if [ "$JAVA_PATH" ]; then
        JAVA_PATH=$(realpath "$JAVA_PATH")
        echo "Found java in \$PATH: $JAVA_PATH"
    else
        exit 1
    fi
fi
if [ -x "$JAVA_PATH" ]; then
    ln -s "$JAVA_PATH" ./java || exit 1
else
    echo "ERROR: $JAVA_PATH is not an existing executable" 1>&2 && exit 1
fi

# Run the testing execution
./java -version 2>java.stderr.log && cat java.stderr.log || exit 3
strace -o strace.log ./alt-java -version 2>alt-java.stderr.log || exit 3

# Make assertions
if ! grep '^prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE) = 0$' strace.log; then
    echo "ERROR: Speculative Store Bypass (CVE-2018-3639) mitigation not detected" 1>&2 && exit 4
fi
if ! grep '^execve(".*/java", \["\./alt-java", "-version"\], 0x[0-9a-f]\+ /\* [0-9]\+ vars \*/) = 0$' strace.log; then
    echo "ERROR: execve execution of java not detected" 1>&2 && exit 5
fi
if ! diff -u java.stderr.log alt-java.stderr.log; then
    echo "ERROR: java and alt-java behaved differently" 1>&2 && exit 5
fi
echo "SUCCESS: Test Passed"
