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
package org.apache.cxf.ws.security.wss4j;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.endpoint.Server;
import org.apache.cxf.ext.logging.LoggingInInterceptor;
import org.apache.cxf.ext.logging.LoggingOutInterceptor;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.jaxws.JaxWsServerFactoryBean;
import org.apache.cxf.service.Service;
import org.apache.cxf.transport.local.LocalTransportFactory;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * End-to-end CXF WS-Security StAX tests for Post-Quantum Cryptography algorithms.
 *
 * <ul>
 *   <li>ML-KEM-512/768/1024 (FIPS 203) key transport for SOAP body encryption</li>
 *   <li>ML-DSA-44/65/87 (FIPS 204) digital signatures for SOAP body signing</li>
 * </ul>
 *
 * Uses BC 1.84+ (installed as provider at position 2). Tests are skipped automatically
 * when BC is not available.
 */
public class PQCStaxTest extends AbstractSecurityTest {

    private static final char[] KS_PASSWORD = "pqctest".toCharArray();
    private static final String ALIAS = "pqc-test";

    private static boolean bcAvailable;
    private static boolean bcAddedByTest;

    /** Key pairs generated once for the entire test class. */
    private static KeyPair mlKem512KP;
    private static KeyPair mlKem768KP;
    private static KeyPair mlKem1024KP;

    /** ML-DSA keystores: each holds private key + self-signed cert. */
    private static KeyStore mlDsa44KeyStore;
    private static KeyStore mlDsa65KeyStore;
    private static KeyStore mlDsa87KeyStore;

    @BeforeClass
    public static void setUpPQC() throws Exception {
        if (Security.getProvider("BC") == null) {
            try {
                Provider bc = new BouncyCastleProvider();
                Security.insertProviderAt(bc, 2);
                bcAddedByTest = true;
            } catch (Exception e) {
                bcAvailable = false;
                return;
            }
        }
        try {
            mlKem512KP = KeyPairGenerator.getInstance("ML-KEM-512", "BC").generateKeyPair();
            mlKem768KP = KeyPairGenerator.getInstance("ML-KEM-768", "BC").generateKeyPair();
            mlKem1024KP = KeyPairGenerator.getInstance("ML-KEM-1024", "BC").generateKeyPair();

            mlDsa44KeyStore = buildMLDSAKeyStore("ML-DSA-44");
            mlDsa65KeyStore = buildMLDSAKeyStore("ML-DSA-65");
            mlDsa87KeyStore = buildMLDSAKeyStore("ML-DSA-87");

            bcAvailable = true;
        } catch (Exception e) {
            bcAvailable = false;
        }
    }

    @AfterClass
    public static void tearDownPQC() {
        if (bcAddedByTest) {
            Security.removeProvider("BC");
        }
    }

    // -------------------------------------------------------------------------
    // ML-KEM encryption tests
    // -------------------------------------------------------------------------

    @Test
    public void testMLKEM512StaxEncryptDecrypt() throws Exception {
        runMLKEMEncryptDecryptTest(WSS4JConstants.KEYTRANSPORT_ML_KEM_512, mlKem512KP);
    }

    @Test
    public void testMLKEM768StaxEncryptDecrypt() throws Exception {
        runMLKEMEncryptDecryptTest(WSS4JConstants.KEYTRANSPORT_ML_KEM_768, mlKem768KP);
    }

    @Test
    public void testMLKEM1024StaxEncryptDecrypt() throws Exception {
        runMLKEMEncryptDecryptTest(WSS4JConstants.KEYTRANSPORT_ML_KEM_1024, mlKem1024KP);
    }

    // -------------------------------------------------------------------------
    // ML-DSA signature tests
    // -------------------------------------------------------------------------

    @Test
    public void testMLDSA44StaxSignVerify() throws Exception {
        runMLDSASignVerifyTest("http://www.w3.org/2021/04/xmldsig-more#ml-dsa-44", mlDsa44KeyStore);
    }

    @Test
    public void testMLDSA65StaxSignVerify() throws Exception {
        runMLDSASignVerifyTest("http://www.w3.org/2021/04/xmldsig-more#ml-dsa-65", mlDsa65KeyStore);
    }

    @Test
    public void testMLDSA87StaxSignVerify() throws Exception {
        runMLDSASignVerifyTest("http://www.w3.org/2021/04/xmldsig-more#ml-dsa-87", mlDsa87KeyStore);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void runMLKEMEncryptDecryptTest(String keyTransportUri, KeyPair kp) throws Exception {
        Assume.assumeTrue("BC 1.84+ required for ML-KEM", bcAvailable);

        Service service = createService();

        // Inbound (service): decrypt using the ML-KEM private key directly
        WSSSecurityProperties inProps = new WSSSecurityProperties();
        inProps.setDecryptionKey(kp.getPrivate());
        service.getInInterceptors().add(new WSS4JStaxInInterceptor(inProps));

        // Outbound (client): encrypt using the ML-KEM public key
        Echo echo = createClientProxy();
        Client client = ClientProxy.getClient(echo);
        client.getInInterceptors().add(new LoggingInInterceptor());
        client.getOutInterceptors().add(new LoggingOutInterceptor());

        WSSSecurityProperties outProps = new WSSSecurityProperties();
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        outProps.setActions(actions);
        outProps.setEncryptionKeyTransportAlgorithm(keyTransportUri);
        outProps.setEncryptionTransportKey(kp.getPublic());
        outProps.setEncryptionSymAlgorithm(WSS4JConstants.AES_256_GCM);
        client.getOutInterceptors().add(new WSS4JStaxOutInterceptor(outProps));

        assertEquals("test", echo.echo("test"));
    }

    private void runMLDSASignVerifyTest(String sigAlgorithmUri, KeyStore keyStore) throws Exception {
        Assume.assumeTrue("BC 1.84+ required for ML-DSA", bcAvailable);

        Merlin crypto = new Merlin();
        crypto.setKeyStore(keyStore);
        crypto.setTrustStore(keyStore);

        Service service = createService();

        // Inbound (service): verify ML-DSA signature
        WSSSecurityProperties inProps = new WSSSecurityProperties();
        inProps.setSignatureVerificationCrypto(crypto);
        service.getInInterceptors().add(new WSS4JStaxInInterceptor(inProps));

        // Outbound (client): sign with ML-DSA private key
        Echo echo = createClientProxy();
        Client client = ClientProxy.getClient(echo);
        client.getInInterceptors().add(new LoggingInInterceptor());
        client.getOutInterceptors().add(new LoggingOutInterceptor());

        WSSSecurityProperties outProps = new WSSSecurityProperties();
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        outProps.setActions(actions);
        outProps.setSignatureAlgorithm(sigAlgorithmUri);
        outProps.setSignatureCrypto(crypto);
        outProps.setSignatureUser(ALIAS);
        outProps.setCallbackHandler(callbacks -> {
            for (Object cb : callbacks) {
                if (cb instanceof org.apache.wss4j.common.ext.WSPasswordCallback) {
                    ((org.apache.wss4j.common.ext.WSPasswordCallback) cb)
                        .setPassword(new String(KS_PASSWORD));
                }
            }
        });
        client.getOutInterceptors().add(new WSS4JStaxOutInterceptor(outProps));

        assertEquals("test", echo.echo("test"));
    }

    /**
     * Builds a PKCS12 KeyStore containing an ML-DSA key pair and a genuine self-signed certificate
     * (the ML-DSA private key signs its own cert, so trust validation passes with the same keystore).
     */
    private static KeyStore buildMLDSAKeyStore(String mlDsaAlgorithm) throws Exception {
        KeyPair mlDsaKP = KeyPairGenerator.getInstance(mlDsaAlgorithm, "BC").generateKeyPair();

        X500Name subject = new X500Name("CN=" + mlDsaAlgorithm + " Test, O=CXF PQC Test");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 86_400_000L);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE, notBefore, notAfter, subject, mlDsaKP.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(mlDsaAlgorithm)
                .setProvider("BC").build(mlDsaKP.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(certBuilder.build(signer));

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, KS_PASSWORD);
        ks.setKeyEntry(ALIAS, mlDsaKP.getPrivate(), KS_PASSWORD,
                new java.security.cert.Certificate[]{cert});
        return ks;
    }

    private Service createService() {
        JaxWsServerFactoryBean factory = new JaxWsServerFactoryBean();
        factory.setServiceBean(new EchoImpl());
        factory.setAddress("local://EchoPQC");
        factory.setTransportId(LocalTransportFactory.TRANSPORT_ID);
        Server server = factory.create();
        Service service = server.getEndpoint().getService();
        service.getInInterceptors().add(new LoggingInInterceptor());
        service.getOutInterceptors().add(new LoggingOutInterceptor());
        return service;
    }

    private Echo createClientProxy() {
        JaxWsProxyFactoryBean proxyFac = new JaxWsProxyFactoryBean();
        proxyFac.setServiceClass(Echo.class);
        proxyFac.setAddress("local://EchoPQC");
        proxyFac.getClientFactoryBean().setTransportId(LocalTransportFactory.TRANSPORT_ID);
        return (Echo) proxyFac.create();
    }
}
