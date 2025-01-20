/*
 * Copyright (c) 2003, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

package sun.security.jca;

import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jdk.internal.loader.ClassLoaders;
import sun.security.x509.AlgorithmId;

/**
 * Collection of methods to get and set provider list. Also includes
 * special code for the provider list during JAR verification.
 *
 * @author  Andreas Sterbenz
 * @since   1.5
 */
public class Providers {

    private static final ThreadLocal<ProviderList> threadLists =
        new ThreadLocal<>();

    // number of threads currently using thread-local provider lists
    // tracked to allow an optimization if == 0
    private static volatile int threadListsUsed;

    // current system-wide provider list
    // Note volatile immutable object, so no synchronization needed.
    private static volatile ProviderList providerList;

    static {
        // set providerList to empty list first in case initialization somehow
        // triggers a getInstance() call (although that should not happen)
        providerList = ProviderList.EMPTY;
        providerList = ProviderList.fromSecurityProperties();
    }

    private Providers() {
        // empty
    }

    // JDK providers loaded by the Bootstrap and Platform class loaders are all
    // in modules that do not require JAR signature verification. Thus, they
    // are safe to be used for verifying JAR signatures without circularities
    // and infinite recursion. Otherwise, loading a service implementation
    // class of a signed-JAR (installed) provider could trigger lazy class file
    // verification and the same provider chosen again, repeating the cycle.
    //
    // The strategy for JAR signature verification is to execute all
    // cryptographic operations required by
    // sun.security.util.SignatureFileVerifier and
    // sun.security.util.ManifestEntryVerifier (e.g. CertificateFactory,
    // Signature, MessageDigest) within a thread-local context where
    // Providers::getProviderList returns a safe list of providers.
    //
    // The safe list of providers is the result of filtering those
    // coming from the JDK configuration (installed statically or
    // dynamically) and a minimal fixed list referred by
    // Providers::jarVerificationProviders.
    private static final String[] jarVerificationProviders = {
        "SUN",
        "SunRsaSign",
        "SunEC",
        "SunJCE",
    };

    /**
     * Get a ProviderList for JAR verification.
     */
    public static ProviderList getProviderListForJarVerification() {
        ProviderList systemProviderList = getSystemProviderList();
        List<Provider> systemProviders = systemProviderList.providers();
        List<ProviderConfig> systemConfigs = systemProviderList.configs();
        List<Provider> jarProviderList = new ArrayList<>();
        systemProviders.stream().filter((Provider p) -> {
            ClassLoader cl = p.getClass().getClassLoader();
            return cl == null || cl.equals(ClassLoaders.platformClassLoader());
        }).forEach(jarProviderList::add);
        Arrays.stream(jarVerificationProviders).map(ProviderConfig::new)
                .filter((ProviderConfig pc) -> !systemConfigs.contains(pc))
                .map(ProviderConfig::getProvider)
                .forEach(jarProviderList::add);
        return ProviderList.newList(jarProviderList.toArray(new Provider[0]));
    }

    // Return Sun provider.
    // This method should only be called by java.security.SecureRandom.
    public static Provider getSunProvider() {
        return new sun.security.provider.Sun();
    }

    /**
     * Return the current ProviderList. If the thread-local list is set,
     * it is returned. Otherwise, the system-wide list is returned.
     */
    public static ProviderList getProviderList() {
        ProviderList list = getThreadProviderList();
        if (list == null) {
            list = getSystemProviderList();
        }
        return list;
    }

    /**
     * Set the current ProviderList. Affects the thread-local list if set,
     * otherwise the system-wide list.
     */
    public static void setProviderList(ProviderList newList) {
        if (getThreadProviderList() == null) {
            setSystemProviderList(newList);
        } else {
            changeThreadProviderList(newList);
        }
        clearCachedValues();
    }

    /**
     * Clears the cached provider-list-specific values. These values need to
     * be re-generated whenever provider list is changed. The logic for
     * generating them is in the respective classes.
     */
    private static void clearCachedValues() {
        JCAUtil.clearDefSecureRandom();
        AlgorithmId.clearAliasOidsTable();
    }

    /**
     * Get the full provider list with invalid providers (those that
     * could not be loaded) removed. This is the list we need to
     * present to applications.
     */
    public static ProviderList getFullProviderList() {
        ProviderList list;
        synchronized (Providers.class) {
            list = getThreadProviderList();
            if (list != null) {
                ProviderList newList = list.removeInvalid();
                if (newList != list) {
                    changeThreadProviderList(newList);
                    list = newList;
                }
                return list;
            }
        }
        list = getSystemProviderList();
        ProviderList newList = list.removeInvalid();
        if (newList != list) {
            setSystemProviderList(newList);
            list = newList;
        }
        return list;
    }

    private static ProviderList getSystemProviderList() {
        return providerList;
    }

    private static void setSystemProviderList(ProviderList list) {
        providerList = list;
    }

    public static ProviderList getThreadProviderList() {
        // avoid accessing the threadlocal if none are currently in use
        // (first use of ThreadLocal.get() for a Thread allocates a Map)
        if (threadListsUsed == 0) {
            return null;
        }
        return threadLists.get();
    }

    // Change the thread local provider list. Use only if the current thread
    // is already using a thread local list and you want to change it in place.
    // In other cases, use the begin/endThreadProviderList() methods.
    private static void changeThreadProviderList(ProviderList list) {
        threadLists.set(list);
    }

    /**
     * AutoCloseable to temporarily manipulate the thread local provider list.
     * It is for use by JAR verification (see above).
     *
     * It should be used as follows:
     * <pre>{@code
     * ProviderList list = ...;
     * try (var _ = new Providers.ThreadLocalList(list)) {
     *     // code that needs thread local provider list
     * }
     * }</pre>
     */
    public static final class ThreadLocalList implements AutoCloseable {
        private final ProviderList oldList;

        public ThreadLocalList(ProviderList list) {
            oldList = beginThreadProviderList(list);
        }

        @Override
        public void close() {
            endThreadProviderList(oldList);
        }
    }

    private static synchronized ProviderList beginThreadProviderList(ProviderList list) {
        if (ProviderList.debug != null) {
            ProviderList.debug.println("ThreadLocal providers: " + list);
        }
        ProviderList oldList = threadLists.get();
        threadListsUsed++;
        threadLists.set(list);
        return oldList;
    }

    private static synchronized void endThreadProviderList(ProviderList list) {
        if (list == null) {
            if (ProviderList.debug != null) {
                ProviderList.debug.println("Disabling ThreadLocal providers");
            }
            threadLists.remove();
        } else {
            if (ProviderList.debug != null) {
                ProviderList.debug.println
                    ("Restoring previous ThreadLocal providers: " + list);
            }
            threadLists.set(list);
        }
        threadListsUsed--;
    }

}
