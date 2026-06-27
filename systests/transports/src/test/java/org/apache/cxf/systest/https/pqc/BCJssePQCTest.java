/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.cxf.systest.https.pqc;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.apache.cxf.common.classloader.ClassLoaderUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Verifies that BouncyCastle JSSE ({@code bctls-jdk18on} 1.81+) can complete a TLS 1.3
 * handshake using the X25519MLKEM768 hybrid post-quantum named group on JDK 17–26.
 *
 * <p>Both server and client use BC JSSE directly via raw {@link SSLServerSocket} /
 * {@link SSLSocket} — Jetty is deliberately bypassed.  On JDK 17–26 SunJSSE does not
 * support X25519MLKEM768, so BC JSSE is the only way to exercise the group.
 * On JDK 27+ SunJSSE gains native X25519MLKEM768 support (JEP 527) and BC JSSE 1.81
 * has TLS handshake compatibility issues with that JDK release, so this test is
 * skipped there — {@code PQCTLSTest} provides coverage via SunJSSE on JDK 27+.
 *
 * <p>The server is restricted to {@value #MLKEM_GROUP} as its sole named group.
 * A successful handshake therefore proves X25519MLKEM768 was negotiated.
 */
public class BCJssePQCTest {

    static final String MLKEM_GROUP = "X25519MLKEM768";

    @BeforeClass
    public static void registerBcProviders() {
        // BC JSSE 1.81 has TLS handshake compatibility issues on JDK 27+.
        // PQCTLSTest covers X25519MLKEM768 via SunJSSE (JEP 527) on JDK 27+.
        Assume.assumeTrue(
            "BCJssePQCTest targets JDK 17-26; use PQCTLSTest on JDK 27+",
            Runtime.version().feature() < 27);

        // Append so Sun's JKS (which supports private-key entries) stays first.
        // BC's JKS is read-only and cannot load private-key entries.
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
    }

    @AfterClass
    public static void removeBcProviders() {
        Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    // ------------------------------------------------------------------ test

    /**
     * Starts a BC SSLServerSocket restricted to X25519MLKEM768, connects a BC
     * SSLSocket with the same restriction, exchanges a line of text, and
     * asserts TLS 1.3 was negotiated on both sides.
     */
    @Test
    public void testMlKemHandshakeSucceeds() throws Exception {
        SSLContext serverCtx = buildBcSslContext(true);
        SSLContext clientCtx = buildBcSslContext(false);

        // Port 0 lets the OS choose a free port; avoids allocation conflicts.
        SSLServerSocket serverSocket =
            (SSLServerSocket) serverCtx.getServerSocketFactory()
                .createServerSocket(0);
        serverSocket.setSoTimeout(10_000);

        int port = serverSocket.getLocalPort();

        // Run the server in a background thread.
        // BCSSLSocket has no BCSSLServerSocket counterpart, so named groups are
        // set on the accepted socket (before startHandshake) rather than on the
        // SSLServerSocket itself.
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<String> serverProtocol = executor.submit(() -> {
            try (SSLSocket accepted = (SSLSocket) serverSocket.accept()) {
                // Restrict to the single PQC group; a successful handshake proves
                // X25519MLKEM768 was negotiated.
                if (accepted instanceof BCSSLSocket) {
                    BCSSLParameters p = new BCSSLParameters();
                    p.setNamedGroups(new String[]{MLKEM_GROUP});
                    ((BCSSLSocket) accepted).setParameters(p);
                }
                accepted.startHandshake();
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(accepted.getInputStream()));
                PrintWriter out = new PrintWriter(accepted.getOutputStream(), true);
                out.println("echo:" + in.readLine());
                return accepted.getSession().getProtocol();
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                try {
                    serverSocket.close();
                } catch (IOException ignored) {
                    // ignored
                }
            }
        });

        // Client side.
        try (SSLSocket client =
                (SSLSocket) clientCtx.getSocketFactory()
                    .createSocket("localhost", port)) {
            if (client instanceof BCSSLSocket) {
                BCSSLParameters p = new BCSSLParameters();
                p.setNamedGroups(new String[]{MLKEM_GROUP});
                ((BCSSLSocket) client).setParameters(p);
            }
            client.startHandshake();

            PrintWriter out = new PrintWriter(client.getOutputStream(), true);
            BufferedReader in = new BufferedReader(
                new InputStreamReader(client.getInputStream()));

            out.println("ping");
            assertEquals("echo:ping", in.readLine());

            // Verify the client side negotiated TLS 1.3.
            assertEquals("TLSv1.3", client.getSession().getProtocol());
        }

        executor.shutdown();
        // Verify the server side also saw TLS 1.3.
        assertEquals("TLSv1.3", serverProtocol.get(5, TimeUnit.SECONDS));
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Builds a BC JSSE SSLContext.  Key and trust managers are loaded via Sun's
     * factories so that JKS keystores with private-key entries are readable.
     *
     * @param server true → load server key material (Bethal.jks);
     *               false → trust-only (client)
     */
    private static SSLContext buildBcSslContext(boolean server) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS", "BCJSSE");

        KeyManagerFactory kmf = null;
        if (server) {
            // Explicitly request Sun's JKS to ensure private-key entries load.
            // BC's JKS implementation is read-only (certificates only).
            KeyStore ks = KeyStore.getInstance("JKS");
            try (InputStream is = ClassLoaderUtils.getResourceAsStream(
                    "keys/Bethal.jks", BCJssePQCTest.class)) {
                ks.load(is, "password".toCharArray());
            }
            kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, "password".toCharArray());
        }

        KeyStore ts = KeyStore.getInstance("JKS");
        try (InputStream is = ClassLoaderUtils.getResourceAsStream(
                "keys/Truststore.jks", BCJssePQCTest.class)) {
            ts.load(is, "password".toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        ctx.init(
            kmf != null ? kmf.getKeyManagers() : null,
            tmf.getTrustManagers(),
            null);
        return ctx;
    }
}
