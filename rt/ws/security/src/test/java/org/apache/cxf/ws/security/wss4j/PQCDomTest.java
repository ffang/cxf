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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.helpers.CastUtils;
import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

/**
 * End-to-end CXF WS-Security DOM tests for Post-Quantum Cryptography algorithms.
 *
 * <ul>
 *   <li>ML-KEM-512/768/1024 (FIPS 203) key transport for SOAP body encryption</li>
 *   <li>ML-DSA-44/65/87 (FIPS 204) digital signatures for SOAP body signing</li>
 * </ul>
 *
 * Uses BC 1.84+ (installed as provider at position 2). Tests are skipped automatically
 * when BC is not available.
 */
public class PQCDomTest extends AbstractSecurityTest {

    private static final char[] KS_PASSWORD = "pqctest".toCharArray();
    private static final String ALIAS = "pqc-test";

    private static boolean bcAvailable;
    private static boolean bcAddedByTest;

    /** ML-KEM Merlin instances: keystore holds ML-KEM private key + EC-signed cert. */
    private static Merlin mlKem512Crypto;
    private static Merlin mlKem768Crypto;
    private static Merlin mlKem1024Crypto;

    /** ML-DSA Merlin instances: keystore holds ML-DSA private key + self-signed cert. */
    private static Merlin mlDsa44Crypto;
    private static Merlin mlDsa65Crypto;
    private static Merlin mlDsa87Crypto;

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
            mlKem512Crypto = buildMLKEMCrypto("ML-KEM-512");
            mlKem768Crypto = buildMLKEMCrypto("ML-KEM-768");
            mlKem1024Crypto = buildMLKEMCrypto("ML-KEM-1024");

            mlDsa44Crypto = buildMLDSACrypto("ML-DSA-44");
            mlDsa65Crypto = buildMLDSACrypto("ML-DSA-65");
            mlDsa87Crypto = buildMLDSACrypto("ML-DSA-87");

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
    public void testMLKEM512DomEncryptDecrypt() throws Exception {
        runMLKEMEncryptDecryptTest(WSS4JConstants.KEYTRANSPORT_ML_KEM_512, mlKem512Crypto);
    }

    @Test
    public void testMLKEM768DomEncryptDecrypt() throws Exception {
        runMLKEMEncryptDecryptTest(WSS4JConstants.KEYTRANSPORT_ML_KEM_768, mlKem768Crypto);
    }

    @Test
    public void testMLKEM1024DomEncryptDecrypt() throws Exception {
        runMLKEMEncryptDecryptTest(WSS4JConstants.KEYTRANSPORT_ML_KEM_1024, mlKem1024Crypto);
    }

    // -------------------------------------------------------------------------
    // ML-DSA signature tests
    // -------------------------------------------------------------------------

    @Test
    public void testMLDSA44DomSignVerify() throws Exception {
        runMLDSASignVerifyTest(WSS4JConstants.ML_DSA_44, mlDsa44Crypto);
    }

    @Test
    public void testMLDSA65DomSignVerify() throws Exception {
        runMLDSASignVerifyTest(WSS4JConstants.ML_DSA_65, mlDsa65Crypto);
    }

    @Test
    public void testMLDSA87DomSignVerify() throws Exception {
        runMLDSASignVerifyTest(WSS4JConstants.ML_DSA_87, mlDsa87Crypto);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void runMLKEMEncryptDecryptTest(String keyTransportUri, Merlin crypto) throws Exception {
        Assume.assumeTrue("BC 1.84+ required for ML-KEM", bcAvailable);

        Map<String, Object> outProperties = new HashMap<>();
        outProperties.put(ConfigurationConstants.ACTION, ConfigurationConstants.ENCRYPTION);
        outProperties.put(ConfigurationConstants.USER, ALIAS);
        outProperties.put(ConfigurationConstants.ENC_KEY_TRANSPORT, keyTransportUri);
        outProperties.put(ConfigurationConstants.ENC_SYM_ALGO, WSConstants.AES_256_GCM);
        outProperties.put(ConfigurationConstants.ENC_KEY_ID, "IssuerSerial");
        outProperties.put(ConfigurationConstants.ENC_PROP_REF_ID, "pqcEncCrypto");
        outProperties.put("pqcEncCrypto", crypto);

        Map<String, Object> inProperties = new HashMap<>();
        inProperties.put(ConfigurationConstants.ACTION, ConfigurationConstants.ENCRYPTION);
        inProperties.put(ConfigurationConstants.DEC_PROP_REF_ID, "pqcDecCrypto");
        inProperties.put("pqcDecCrypto", crypto);
        inProperties.put(ConfigurationConstants.PW_CALLBACK_REF, buildCallbackHandler());

        List<String> xpaths = new ArrayList<>();
        xpaths.add("//wsse:Security");
        xpaths.add("//s:Body/xenc:EncryptedData");

        List<WSHandlerResult> results = getResults(makeInvocation(outProperties, xpaths, inProperties));
        assertNotNull(results);
    }

    private void runMLDSASignVerifyTest(String sigAlgorithmUri, Merlin crypto) throws Exception {
        Assume.assumeTrue("BC 1.84+ required for ML-DSA", bcAvailable);

        Map<String, Object> outProperties = new HashMap<>();
        outProperties.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE);
        outProperties.put(ConfigurationConstants.USER, ALIAS);
        outProperties.put(ConfigurationConstants.SIG_ALGO, sigAlgorithmUri);
        outProperties.put(ConfigurationConstants.SIG_KEY_ID, "DirectReference");
        outProperties.put(ConfigurationConstants.SIG_PROP_REF_ID, "pqcSigCrypto");
        outProperties.put("pqcSigCrypto", crypto);
        outProperties.put(ConfigurationConstants.PW_CALLBACK_REF, buildCallbackHandler());

        Map<String, Object> inProperties = new HashMap<>();
        inProperties.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE);
        inProperties.put(ConfigurationConstants.SIG_VER_PROP_REF_ID, "pqcVerCrypto");
        inProperties.put("pqcVerCrypto", crypto);

        List<String> xpaths = new ArrayList<>();
        xpaths.add("//wsse:Security");
        xpaths.add("//wsse:Security/wsse:BinarySecurityToken");
        xpaths.add("//wsse:Security/ds:Signature");

        List<WSHandlerResult> results = getResults(makeInvocation(outProperties, xpaths, inProperties));
        assertNotNull(results);

        WSSecurityEngineResult sigResult =
            results.get(0).getActionResults().get(WSConstants.SIGN).get(0);
        assertNotNull(sigResult);
        X509Certificate cert =
            (X509Certificate) sigResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertNotNull(cert);
    }

    /**
     * Builds a Merlin keystore for ML-KEM: private key is ML-KEM, cert is EC-signed
     * (ML-KEM keys cannot self-sign).
     */
    private static Merlin buildMLKEMCrypto(String mlKemAlgorithm) throws Exception {
        KeyPair kemKP = KeyPairGenerator.getInstance(mlKemAlgorithm, "BC").generateKeyPair();

        // ML-KEM keys cannot sign; use an ephemeral EC key to sign the certificate.
        KeyPair ecSignKP = KeyPairGenerator.getInstance("EC", "BC").generateKeyPair();

        X500Name subject = new X500Name("CN=" + mlKemAlgorithm + " Test, O=CXF PQC Test");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 86_400_000L);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider("BC").build(ecSignKP.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE, notBefore, notAfter, subject, kemKP.getPublic())
                .build(signer));

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, KS_PASSWORD);
        ks.setKeyEntry(ALIAS, kemKP.getPrivate(), KS_PASSWORD,
            new java.security.cert.Certificate[]{cert});

        Merlin merlin = new Merlin();
        merlin.setKeyStore(ks);
        merlin.setTrustStore(ks);
        return merlin;
    }

    /**
     * Builds a Merlin keystore for ML-DSA: genuinely self-signed cert
     * (ML-DSA private key signs its own cert).
     */
    private static Merlin buildMLDSACrypto(String mlDsaAlgorithm) throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance(mlDsaAlgorithm, "BC").generateKeyPair();

        X500Name subject = new X500Name("CN=" + mlDsaAlgorithm + " Test, O=CXF PQC Test");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 86_400_000L);
        ContentSigner signer = new JcaContentSignerBuilder(mlDsaAlgorithm)
            .setProvider("BC").build(kp.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE, notBefore, notAfter, subject, kp.getPublic())
                .build(signer));

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, KS_PASSWORD);
        ks.setKeyEntry(ALIAS, kp.getPrivate(), KS_PASSWORD,
            new java.security.cert.Certificate[]{cert});

        Merlin merlin = new Merlin();
        merlin.setKeyStore(ks);
        merlin.setTrustStore(ks);
        return merlin;
    }

    private List<WSHandlerResult> getResults(SoapMessage inmsg) {
        return CastUtils.cast((List<?>) inmsg.get(WSHandlerConstants.RECV_RESULTS));
    }

    private javax.security.auth.callback.CallbackHandler buildCallbackHandler() {
        return callbacks -> {
            for (Object cb : callbacks) {
                if (cb instanceof WSPasswordCallback) {
                    ((WSPasswordCallback) cb).setPassword(new String(KS_PASSWORD));
                }
            }
        };
    }
}
