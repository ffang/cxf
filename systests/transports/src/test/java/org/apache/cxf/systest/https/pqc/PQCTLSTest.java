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

import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.namespace.QName;

import jakarta.xml.ws.BindingProvider;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.common.classloader.ClassLoaderUtils;
import org.apache.cxf.configuration.jsse.SSLContextServerParameters;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.jsse.TLSServerParameters;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.systest.http.GreeterImpl;
import org.apache.cxf.testutil.common.AbstractBusClientServerTestBase;
import org.apache.cxf.testutil.common.AbstractBusTestServerBase;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transport.http_jetty.JettyHTTPServerEngineFactory;
import org.apache.hello_world.Greeter;
import org.apache.hello_world.services.SOAPService;

import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Verifies that CXF can complete a TLS 1.3 handshake using the post-quantum
 * hybrid key-encapsulation mechanism X25519MLKEM768 (JEP 527, JDK 27+).
 *
 * <p>The test requires SunJSSE to list {@value #MLKEM_GROUP} as a supported TLS
 * named group.  This is the case only when running under the {@code pqc-tls-test}
 * surefire execution, which overrides the parent-pom's classical-only
 * {@code jdk.tls.namedGroups} setting and requires JDK 27+.  The test is
 * automatically skipped on older JDKs or when the named-group override is absent.
 */
public class PQCTLSTest extends AbstractBusClientServerTestBase {

    static final String MLKEM_GROUP = "X25519MLKEM768";

    static final String PORT = allocatePort(PQCTLSTest.class);

    /**
     * True when SunJSSE lists {@value #MLKEM_GROUP} as a supported TLS named
     * group in the current JVM configuration — JDK 27+ (JEP 527) with the right
     * {@code jdk.tls.namedGroups} setting.
     */
    private static final boolean ML_KEM_AVAILABLE = isMlKemTlsSupported();

    // ------------------------------------------------------------------ server

    public static class PQCServer extends AbstractBusTestServerBase {
        @Override
        protected void run() {
            Bus bus = BusFactory.getDefaultBus(true);
            setBus(bus);

            try {
                SSLContext ctx = buildSSLContext(true);
                SSLParameters sp = ctx.getDefaultSSLParameters();
                // Restrict server to the hybrid PQC group so the client must
                // negotiate ML-KEM; any other group causes handshake failure.
                setNamedGroups(sp, MLKEM_GROUP);
                SSLContext serverCtx = new NamedGroupSSLContext(ctx, sp);

                SSLContextServerParameters serverParams =
                    new SSLContextServerParameters(serverCtx);

                Map<String, TLSServerParameters> map = new HashMap<>();
                map.put("pqcTls", serverParams);

                JettyHTTPServerEngineFactory factory =
                    bus.getExtension(JettyHTTPServerEngineFactory.class);
                factory.setTlsServerParametersMap(map);
                factory.createJettyHTTPServerEngine(
                    "localhost", Integer.parseInt(PORT), "https", "pqcTls");
                factory.initComplete();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            jakarta.xml.ws.Endpoint.publish(
                "https://localhost:" + PORT + "/SoapContext/HttpsPort",
                new GreeterImpl());
        }
    }

    // ------------------------------------------------------------------ setup

    @BeforeClass
    public static void startServer() throws Exception {
        Assume.assumeTrue(
            "X25519MLKEM768 TLS not available — requires JDK 27+ with "
            + "jdk.tls.namedGroups including " + MLKEM_GROUP,
            ML_KEM_AVAILABLE);
        assertTrue("Server failed to launch",
            launchServer(PQCServer.class, true));
    }

    @AfterClass
    public static void cleanup() throws Exception {
        stopAllServers();
    }

    // ------------------------------------------------------------------ tests

    @Test
    public void testMlKemHandshakeSucceeds() throws Exception {
        QName serviceName =
            new QName("http://apache.org/hello_world/services", "SOAPService");
        URL wsdl = SOAPService.WSDL_LOCATION;
        SOAPService service = new SOAPService(wsdl, serviceName);
        assertNotNull("Service is null", service);

        Greeter port = service.getHttpsPort();
        assertNotNull("Port is null", port);

        Client client = ClientProxy.getClient(port);
        HTTPConduit conduit = (HTTPConduit) client.getConduit();

        TLSClientParameters tlsParams = new TLSClientParameters();
        tlsParams.setDisableCNCheck(true);

        SSLContext ctx = buildSSLContext(false);
        SSLParameters sp = ctx.getDefaultSSLParameters();
        setNamedGroups(sp, MLKEM_GROUP);
        tlsParams.setSslContext(new NamedGroupSSLContext(ctx, sp));

        conduit.setTlsClientParameters(tlsParams);

        BindingProvider bp = (BindingProvider) port;
        bp.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
            "https://localhost:" + PORT + "/SoapContext/HttpsPort");

        assertEquals("Hello Kitty", port.greetMe("Kitty"));

        ((java.io.Closeable) port).close();
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Returns true only when SunJSSE lists {@value #MLKEM_GROUP} in its supported
     * TLS named groups — JDK 27+ (JEP 527) with the right
     * {@code jdk.tls.namedGroups} configuration.
     */
    private static boolean isMlKemTlsSupported() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, null, null);
            Method gm = SSLParameters.class.getMethod("getNamedGroups");
            String[] groups = (String[]) gm.invoke(ctx.getSupportedSSLParameters());
            return groups != null && Arrays.asList(groups).contains(MLKEM_GROUP);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Builds a SunJSSE SSLContext for the given role.
     *
     * @param server true → load server key material; false → trust-only (client)
     */
    static SSLContext buildSSLContext(boolean server) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = null;
        if (server) {
            kmf = loadKeyManagers("keys/Bethal.jks", "password", "password");
        }
        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        KeyStore ts = loadKeyStore("keys/Truststore.jks", "password");
        tmf.init(ts);
        ctx.init(
            kmf != null ? kmf.getKeyManagers() : null,
            tmf.getTrustManagers(),
            null);
        return ctx;
    }

    /**
     * Calls {@code SSLParameters.setNamedGroups(String[])} via reflection so
     * this class compiles on JDK 17 but exercises the API at runtime on JDK 20+.
     */
    static void setNamedGroups(SSLParameters sp, String... groups) {
        try {
            Method m = SSLParameters.class.getMethod(
                "setNamedGroups", String[].class);
            m.invoke(sp, (Object) groups);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(
                "SSLParameters.setNamedGroups not available — JDK 20+ required",
                e);
        }
    }

    private static KeyManagerFactory loadKeyManagers(
            String resource, String storePass, String keyPass)
            throws KeyStoreException, NoSuchAlgorithmException,
                   UnrecoverableKeyException, Exception {
        KeyStore ks = loadKeyStore(resource, storePass);
        KeyManagerFactory kmf =
            KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keyPass.toCharArray());
        return kmf;
    }

    private static KeyStore loadKeyStore(String resource, String password)
            throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream is =
                ClassLoaderUtils.getResourceAsStream(resource,
                    PQCTLSTest.class)) {
            ks.load(is, password.toCharArray());
        }
        return ks;
    }

    /**
     * Thin SSLContext wrapper that injects a fixed set of {@link SSLParameters}
     * (including named groups) into every engine/socket created.  Used to enforce
     * {@code X25519MLKEM768} without a custom provider.
     */
    static final class NamedGroupSSLContext extends SSLContext {
        NamedGroupSSLContext(SSLContext delegate, SSLParameters params) {
            super(new NamedGroupSpi(delegate, params),
                  delegate.getProvider(),
                  delegate.getProtocol());
        }
    }

    static final class NamedGroupSpi
            extends javax.net.ssl.SSLContextSpi {

        private final SSLContext delegate;
        private final SSLParameters params;

        NamedGroupSpi(SSLContext delegate, SSLParameters params) {
            this.delegate = delegate;
            this.params = params;
        }

        @Override
        protected void engineInit(
                javax.net.ssl.KeyManager[] km,
                javax.net.ssl.TrustManager[] tm,
                java.security.SecureRandom sr)
                throws java.security.KeyManagementException {
            delegate.init(km, tm, sr);
        }

        @Override
        protected javax.net.ssl.SSLSocketFactory engineGetSocketFactory() {
            return new NamedGroupSocketFactory(
                delegate.getSocketFactory(), params);
        }

        @Override
        protected javax.net.ssl.SSLServerSocketFactory
                engineGetServerSocketFactory() {
            return delegate.getServerSocketFactory();
        }

        @Override
        protected javax.net.ssl.SSLEngine engineCreateSSLEngine() {
            javax.net.ssl.SSLEngine e = delegate.createSSLEngine();
            e.setSSLParameters(params);
            return e;
        }

        @Override
        protected javax.net.ssl.SSLEngine engineCreateSSLEngine(
                String host, int port) {
            javax.net.ssl.SSLEngine e = delegate.createSSLEngine(host, port);
            e.setSSLParameters(params);
            return e;
        }

        @Override
        protected javax.net.ssl.SSLSessionContext
                engineGetServerSessionContext() {
            return delegate.getServerSessionContext();
        }

        @Override
        protected javax.net.ssl.SSLSessionContext
                engineGetClientSessionContext() {
            return delegate.getClientSessionContext();
        }

        @Override
        protected SSLParameters engineGetDefaultSSLParameters() {
            return params;
        }

        @Override
        protected SSLParameters engineGetSupportedSSLParameters() {
            return delegate.getSupportedSSLParameters();
        }
    }

    static final class NamedGroupSocketFactory
            extends javax.net.ssl.SSLSocketFactory {

        private final javax.net.ssl.SSLSocketFactory delegate;
        private final SSLParameters params;

        NamedGroupSocketFactory(javax.net.ssl.SSLSocketFactory delegate,
                                SSLParameters params) {
            this.delegate = delegate;
            this.params = params;
        }

        private javax.net.ssl.SSLSocket configure(
                javax.net.ssl.SSLSocket s) {
            s.setSSLParameters(params);
            return s;
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return delegate.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return delegate.getSupportedCipherSuites();
        }

        @Override
        public java.net.Socket createSocket(java.net.Socket s,
                String host, int port, boolean autoClose)
                throws java.io.IOException {
            return configure((javax.net.ssl.SSLSocket)
                delegate.createSocket(s, host, port, autoClose));
        }

        @Override
        public java.net.Socket createSocket(String host, int port)
                throws java.io.IOException {
            return configure((javax.net.ssl.SSLSocket)
                delegate.createSocket(host, port));
        }

        @Override
        public java.net.Socket createSocket(String host, int port,
                java.net.InetAddress localHost, int localPort)
                throws java.io.IOException {
            return configure((javax.net.ssl.SSLSocket)
                delegate.createSocket(host, port, localHost, localPort));
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress host,
                int port) throws java.io.IOException {
            return configure((javax.net.ssl.SSLSocket)
                delegate.createSocket(host, port));
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress address,
                int port, java.net.InetAddress localAddress,
                int localPort) throws java.io.IOException {
            return configure((javax.net.ssl.SSLSocket)
                delegate.createSocket(
                    address, port, localAddress, localPort));
        }
    }
}
