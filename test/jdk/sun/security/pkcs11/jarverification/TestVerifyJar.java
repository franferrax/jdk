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

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSigner;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;

import jdk.test.lib.SecurityTools;
import jdk.test.lib.util.JarUtils;

/*
 * @test
 * @bug 8347827
 * @summary Use a SunPKCS11 provider to verify signed JAR files without infinite
 * recursion.
 * @library /test/lib ..
 * @compile SignedProvider.java
 * @compile SignedApp.java
 * @run main/othervm/timeout=30 TestVerifyJar
 */

public final class TestVerifyJar extends PKCS11Test {
    private static final Path PROVIDER_JAR_FILE = Path.of("SignedProvider.jar");
    private static final Path APP_JAR_FILE = Path.of("SignedApp.jar");
    private static final Path KEYSTORE_FILE = Path.of("ks.p12");
    private static final String PRINCIPAL = "CN=TestPrincipal";
    private static final String KEYSTORE_TYPE = "pkcs12";
    private static final String PASSWORD = "changeit";
    private static final String ALIAS = "signer";
    private static final String DIGEST_ALG = "SHA-256";
    private static final Path TEST_CLASSPATH =
            Path.of(System.getProperty("test.classes"));

    private static void createKeystore() throws Exception {
        // Create keystore with a new keypair and a self-signed certificate
        Files.deleteIfExists(KEYSTORE_FILE);
        SecurityTools.keytool("-keystore", KEYSTORE_FILE.toString(),
                "-storetype", KEYSTORE_TYPE, "-storepass", PASSWORD,
                "-keypass", PASSWORD, "-dname", PRINCIPAL, "-alias", ALIAS,
                "-genkeypair", "-keyalg", "RSA");
    }

    private static void createSignedJar(Path jarFile, String... classNames)
            throws Exception {
        Files.deleteIfExists(jarFile);

        // NOTE: passed classes are created by @compile
        Path[] classFiles = Arrays.stream(classNames).map(className ->
                Path.of(className + ".class")).toList().toArray(new Path[0]);
        JarUtils.createJarFile(jarFile, TEST_CLASSPATH, classFiles);

        // Sign the JAR file with the self-signed certificate in KEYSTORE_FILE
        SecurityTools.jarsigner("-keystore", KEYSTORE_FILE.toString(),
                "-storetype", KEYSTORE_TYPE, "-storepass", PASSWORD,
                "-digestalg", DIGEST_ALG, jarFile.toString(), ALIAS);

        // Delete class files to prevent load from app class loader
        for (Path classFile : classFiles) {
            Files.delete(TEST_CLASSPATH.resolve(classFile));
        }
    }

    public void main(Provider sunPKCS11NSS) throws Exception {
        Security.insertProviderAt(sunPKCS11NSS, 1);

        createKeystore();

        createSignedJar(PROVIDER_JAR_FILE, "SignedProvider",
                "SignedProvider$FaultySha256");
        createSignedJar(APP_JAR_FILE, "SignedApp");

        checkSignedJar(APP_JAR_FILE);
        checkSignedJar(PROVIDER_JAR_FILE);

        try (URLClassLoader cl = new URLClassLoader("TestClassLoader",
                new URL[] { PROVIDER_JAR_FILE.toUri().toURL(),
                APP_JAR_FILE.toUri().toURL() },
                Thread.currentThread().getContextClassLoader())) {
            Class<?> SignedProviderClass = cl.loadClass("SignedProvider");
            Provider signedProvider = (Provider) SignedProviderClass
                    .getConstructor().newInstance();
            Security.insertProviderAt(signedProvider, 1);

            // Use the faulty message digest service from SignedProvider
            MessageDigest md = MessageDigest.getInstance(DIGEST_ALG);
            String expectedMsg = "SignedProvider$FaultySha256";
            try {
                md.digest(new byte[20]);
                throw new Exception(
                        "RuntimeException(\"" + expectedMsg + "\") expected.");
            } catch (RuntimeException e) {
                if (!e.getMessage().equals(expectedMsg)) {
                    throw e;
                }
            }

            // Invoke main app
            cl.loadClass("SignedApp").getDeclaredMethod("run").invoke(null);
        }

        System.out.println("TEST PASS - OK");
    }

    private static void checkSignedJar(Path jarFile) throws Exception {
        // As JarFile
        try (JarFile jf = new JarFile(jarFile.toFile(), true)) {
            jf.stream().forEach((JarEntry je) -> {
                try {
                    jf.getInputStream(je).readAllBytes();
                } catch (IOException ioe) {
                    throw new RuntimeException(ioe);
                }
                checkJarEntry(je, "(JarFile) " + jarFile);
            });
        }
        // As JarInputStream (jis.getNextJarEntry() skips META-INF/MANIFEST.MF)
        try (JarInputStream jis = new JarInputStream(
                Files.newInputStream(jarFile), true)) {
            JarEntry je;
            while ((je = jis.getNextJarEntry()) != null) {
                jis.readAllBytes();
                checkJarEntry(je, "(JarInputStream) " + jarFile);
            }
        }
    }

    private static void checkJarEntry(JarEntry je, String jarFileRepr) {
        CodeSigner[] css = je.getCodeSigners();
        if (css != null) {
            if (css.length != 1) {
                throw new RuntimeException(
                        "There should be exactly a single signer.");
            }
            String principal = ((X509Certificate) css[0].getSignerCertPath()
                    .getCertificates().getFirst()).getSubjectX500Principal()
                    .toString();
            if (!PRINCIPAL.equals(principal)) {
                throw new RuntimeException(
                        "Unexpected principal: " + principal + ".");
            }
        } else if (je.getName().endsWith(".MF") ||
                je.getName().endsWith(".class")) {
            throw new RuntimeException("Manifest or class entry should " +
                    "be signed: " + jarFileRepr + "/" + je + ".");
        }
    }

    public static void main(String[] args) throws Exception {
        main(new TestVerifyJar(), args);
    }
}
