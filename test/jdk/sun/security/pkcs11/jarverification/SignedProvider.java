/*
 * Copyright (c) 2025, Red Hat, Inc.
 *
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

import java.io.Serial;
import java.security.MessageDigestSpi;
import java.security.Provider;

public final class SignedProvider extends Provider {
    @Serial
    private static final long serialVersionUID = 8718893220249648594L;

    public final static class FaultySha256 extends MessageDigestSpi {
        @Override
        protected void engineUpdate(byte input) {
            throw new RuntimeException(this.getClass().getName());
        }

        @Override
        protected void engineUpdate(byte[] input, int offset, int len) {
            throw new RuntimeException(this.getClass().getName());
        }

        @Override
        protected byte[] engineDigest() {
            throw new RuntimeException(this.getClass().getName());
        }

        @Override
        protected void engineReset() {
            throw new RuntimeException(this.getClass().getName());
        }
    }

    public SignedProvider() {
        super("SignedProvider", "0", "");
        // Do not use FaultySha256.getClass().getName() to avoid linking
        // FaultySha256 too early. We need FaultySha256 be loaded once
        // SignedProvider is installed.
        putService(new Service(this, "MessageDigest", "SHA-256",
                "SignedProvider$FaultySha256", null, null));
    }
}
