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
package org.apache.cxf.systest.wssec.examples.pqc;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import jakarta.xml.ws.BindingProvider;
import jakarta.xml.ws.Service;
import jakarta.xml.ws.soap.SOAPBinding;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.testutil.common.AbstractBusClientServerTestBase;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.crypto.Merlin;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.example.contract.doubleit.DoubleItPortType;

import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * System tests for Post-Quantum Cryptography in CXF WS-Security.
 *
 * <p>Covers:
 * <ul>
 *   <li><b>ML-DSA (FIPS 204)</b> digital signatures — three parameter sets
 *       (ML-DSA-44, ML-DSA-65, ML-DSA-87) via {@link WSS4JOutInterceptor}
 *       with {@code action=Signature}.</li>
 *   <li><b>ML-KEM (FIPS 203)</b> key encapsulation + AES-256-GCM body
 *       encryption — ML-KEM-768 via {@link WSS4JOutInterceptor} with
 *       {@code action=Encrypt} and
 *       {@code encryptionKeyTransportAlgorithm=ML-KEM-768}.</li>
 * </ul>
 *
 * <p>Requires BouncyCastle 1.81+ on the classpath.
 */
@RunWith(Parameterized.class)
public class PQCTest extends AbstractBusClientServerTestBase {

    static final String PORT = allocatePort(PQCServer.class);

    /** Key alias used for the ephemeral ML-KEM key pair generated at test startup. */
    static final String ML_KEM_ALIAS = "mlkem768-test";
    /** PKCS12 password for the ephemeral ML-KEM keystore entry. */
    static final char[] ML_KEM_KS_PASSWORD = "pqctest".toCharArray();

    private static final String NAMESPACE = "http://www.example.org/contract/DoubleIt";
    private static final QName SERVICE_QNAME = new QName(NAMESPACE, "DoubleItService");

    /** ML-DSA algorithm URIs (provisional; draft-ietf-xmlsec-pqc-sigalg). */
    private static final String ML_DSA_44_URI =
        "http://www.w3.org/2021/04/xmldsig-more#ml-dsa-44";
    private static final String ML_DSA_65_URI =
        "http://www.w3.org/2021/04/xmldsig-more#ml-dsa-65";
    private static final String ML_DSA_87_URI =
        "http://www.w3.org/2021/04/xmldsig-more#ml-dsa-87";

    /** ML-KEM-768 key transport URI (provisional; draft-ietf-xmlsec-pqc-encalg). */
    private static final String ML_KEM_768_URI =
        "http://www.w3.org/2021/04/xmlenc-more#ml-kem-768";

    private static boolean bcAvailable;

    // ---- parameterisation for ML-DSA tests --------------------------------

    /** JCA key-gen algorithm name for the ML-DSA parameter set under test. */
    private final String jcaName;
    /** Key alias in mldsa.p12 for the parameter set under test. */
    private final String alias;
    /** XML-DSIG algorithm URI for the parameter set under test. */
    private final String sigUri;

    public PQCTest(String jcaName, String alias, String sigUri) {
        this.jcaName = jcaName;
        this.alias = alias;
        this.sigUri = sigUri;
    }

    @Parameters(name = "{0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
            {"ML-DSA-44", "ml-dsa-44", ML_DSA_44_URI},
            {"ML-DSA-65", "ml-dsa-65", ML_DSA_65_URI},
            {"ML-DSA-87", "ml-dsa-87", ML_DSA_87_URI},
        });
    }

    // ---- server startup ---------------------------------------------------

    @BeforeClass
    public static void startServers() throws Exception {
        try {
            if (Security.getProvider("BC") == null) {
                Security.insertProviderAt(new BouncyCastleProvider(), 2);
            }
            // Verify BC supports both PQC algorithm families.
            KeyPairGenerator.getInstance("ML-DSA-65", "BC").generateKeyPair();
            KeyPairGenerator.getInstance("ML-KEM-768", "BC").generateKeyPair();
            bcAvailable = true;
        } catch (Exception e) {
            bcAvailable = false;
        }

        if (bcAvailable) {
            // Pre-generate the ML-KEM key pair and share it with PQCServer.
            // Both server (decryption) and client (encryption) use the same Merlin.
            PQCServer.setMlKemCrypto(buildMlKemCrypto());

            assertTrue("Server failed to launch",
                launchServer(PQCServer.class, true));
        }
    }

    @AfterClass
    public static void cleanup() throws Exception {
        stopAllServers();
    }

    // ---- ML-DSA signing test (parameterised) ------------------------------

    /**
     * Signs a SOAP message with the given ML-DSA variant, sends it to the server,
     * and asserts the service returns the correct doubled value.
     */
    @org.junit.Test
    public void testMLDSASignAndVerify() throws Exception {
        Assume.assumeTrue("BouncyCastle 1.81+ with ML-DSA support is required", bcAvailable);

        // Load the ML-DSA PKCS12 keystore (same file used on the server side).
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        try (InputStream is = PQCTest.class.getResourceAsStream("mldsa.p12")) {
            ks.load(is, "security".toCharArray());
        }
        Merlin merlin = new Merlin();
        merlin.setKeyStore(ks);

        DoubleItPortType port = createPort("DoubleItMLDSASignPort",
            "http://localhost:" + PORT + "/DoubleItMLDSASign");

        Map<String, Object> props = new HashMap<>();
        props.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE);
        props.put(ConfigurationConstants.SIG_PROP_REF_ID, "mldsaSignCrypto");
        props.put("mldsaSignCrypto", merlin);
        props.put(ConfigurationConstants.SIGNATURE_USER, alias);
        props.put(ConfigurationConstants.SIG_KEY_ID, "IssuerSerial");
        props.put(ConfigurationConstants.SIG_ALGO, sigUri);
        props.put(ConfigurationConstants.PW_CALLBACK_CLASS,
            PQCPasswordCallback.class.getName());
        props.put("isBSPCompliant", "false");

        Client client = ClientProxy.getClient(port);
        client.getOutInterceptors().add(new WSS4JOutInterceptor(props));

        assertEquals("ML-DSA (" + jcaName + ") sign+verify failed", 50, port.doubleIt(25));
        ((java.io.Closeable) port).close();
    }

    // ---- ML-KEM encryption test -------------------------------------------

    /**
     * Encrypts a SOAP message body using ML-KEM-768 key transport + AES-256-GCM
     * content encryption, sends it to the server, and asserts the service returns
     * the correct doubled value.
     *
     * <p>The ML-KEM key pair is generated fresh at test startup; the server's
     * Merlin (holding the private key for decapsulation) is pre-set in
     * {@link PQCServer#mlKemCrypto} before the server is launched.
     */
    @org.junit.Test
    public void testMLKEMEncryptAndDecrypt() throws Exception {
        Assume.assumeTrue("BouncyCastle 1.81+ with ML-KEM support is required", bcAvailable);
        Assume.assumeTrue("ML-KEM crypto not initialised", PQCServer.getMlKemCrypto() != null);

        // The client uses the same Merlin instance as the server to look up the
        // recipient certificate (public key) by alias for encryption.
        Merlin clientMerlin = (Merlin) PQCServer.getMlKemCrypto();

        DoubleItPortType port = createPort("DoubleItMLKEMEncryptPort",
            "http://localhost:" + PORT + "/DoubleItMLKEMEncrypt");

        Map<String, Object> props = new HashMap<>();
        props.put(ConfigurationConstants.ACTION, ConfigurationConstants.ENCRYPTION);
        props.put(ConfigurationConstants.ENC_PROP_REF_ID, "mlKemEncCrypto");
        props.put("mlKemEncCrypto", clientMerlin);
        props.put(ConfigurationConstants.ENCRYPTION_USER, ML_KEM_ALIAS);
        props.put(ConfigurationConstants.ENC_KEY_TRANSPORT, ML_KEM_768_URI);
        props.put(ConfigurationConstants.ENC_SYM_ALGO,
            "http://www.w3.org/2009/xmlenc11#aes256-gcm");
        props.put(ConfigurationConstants.ENC_KEY_ID, "IssuerSerial");
        props.put("isBSPCompliant", "false");

        Client client = ClientProxy.getClient(port);
        client.getOutInterceptors().add(new WSS4JOutInterceptor(props));

        assertEquals("ML-KEM encrypt+decrypt failed", 50, port.doubleIt(25));
        ((java.io.Closeable) port).close();
    }

    // ---- helpers ----------------------------------------------------------

    private static DoubleItPortType createPort(String portLocalName, String address) {
        QName portQName = new QName(NAMESPACE, portLocalName);
        Service service = Service.create(SERVICE_QNAME);
        service.addPort(portQName, SOAPBinding.SOAP11HTTP_BINDING, address);
        DoubleItPortType port = service.getPort(portQName, DoubleItPortType.class);
        ((BindingProvider) port).getRequestContext()
            .put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, address);
        return port;
    }

    /**
     * Generates an ephemeral ML-KEM-768 key pair, wraps it in a PKCS12 keystore
     * (with an EC-signed self-signed certificate), and returns a Merlin Crypto.
     *
     * <p>ML-KEM keys cannot sign; an ephemeral EC key is used to sign the cert.
     */
    static Merlin buildMlKemCrypto() throws Exception {
        KeyPair kemKP = KeyPairGenerator.getInstance("ML-KEM-768", "BC").generateKeyPair();

        // ML-KEM keys cannot self-sign — use a transient EC key for the certificate.
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC", "BC");
        ecGen.initialize(new java.security.spec.ECGenParameterSpec("P-256"));
        KeyPair sigKP = ecGen.generateKeyPair();

        X500Name subject = new X500Name("CN=ML-KEM-768 Test, O=CXF PQC Test");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 86_400_000L);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            subject, BigInteger.ONE, notBefore, notAfter, subject, kemKP.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider("BC").build(sigKP.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter()
            .setProvider("BC").getCertificate(certBuilder.build(signer));

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, ML_KEM_KS_PASSWORD);
        ks.setKeyEntry(ML_KEM_ALIAS, kemKP.getPrivate(), ML_KEM_KS_PASSWORD,
            new java.security.cert.Certificate[]{cert});

        Merlin merlin = new Merlin();
        merlin.setKeyStore(ks);
        return merlin;
    }
}
