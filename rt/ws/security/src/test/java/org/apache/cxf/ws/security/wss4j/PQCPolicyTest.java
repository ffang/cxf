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
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.w3c.dom.Document;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.ws.policy.AssertionInfoMap;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.wss4j.CryptoCoverageUtil.CoverageType;
import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.policy.SP12Constants;
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

/**
 * WS-SecurityPolicy-driven tests for Post-Quantum Cryptography algorithms.
 *
 * <p>Security policy is declared in XML policy files using the WS-SP 1.2 namespace.
 * Each test uses one of the PQC algorithm suites defined in wss4j:
 * <ul>
 *   <li>Basic128MlDsa44 — ML-DSA-44 signature, ML-KEM-512 key wrap, AES-128 (NIST Level 1)</li>
 *   <li>Basic256MlDsa65 — ML-DSA-65 signature, ML-KEM-768 key wrap, AES-256 (NIST Level 3)</li>
 *   <li>Basic256MlDsa87 — ML-DSA-87 signature, ML-KEM-1024 key wrap, AES-256 (NIST Level 5)</li>
 * </ul>
 *
 * <p>The {@link PolicyBasedWSS4JOutInterceptor} reads the algorithm suite from the
 * {@link AssertionInfoMap} and selects the ML-DSA signing / ML-KEM key-wrap algorithm
 * automatically (via {@code AlgorithmSuiteType#getAsymmetricSignature()}/
 * {@code #getAsymmetricKeyWrap()}) - no PQC-specific code exists in CXF itself, this is
 * purely generic algorithm-suite-driven configuration. The ML-KEM key transport goes over
 * the W3C "XML Security: Generic Hybrid Cipher" wire structure (see SANTUARIO-633),
 * produced by wss4j's {@code WSSecEncryptedKey}/{@code EncryptedKeyProcessor}.
 *
 * <p>Crypto is injected via {@link SecurityConstants#SIGNATURE_CRYPTO}/{@link
 * SecurityConstants#ENCRYPT_CRYPTO} so no properties files are needed.
 */
public class PQCPolicyTest extends AbstractPolicySecurityTest {

    private static final char[] KS_PASSWORD = "pqctest".toCharArray();
    private static final String ALIAS = "pqc-test";

    private static boolean bcAvailable;
    private static boolean bcAddedByTest;

    private static Merlin mlDsa44Crypto;
    private static Merlin mlDsa65Crypto;
    private static Merlin mlDsa87Crypto;

    private static Merlin mlKem512Crypto;
    private static Merlin mlKem768Crypto;
    private static Merlin mlKem1024Crypto;

    /** Set by each test before calling runAndValidate; overrides the classical crypto. */
    private Merlin currentCrypto;

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
            mlDsa44Crypto = buildMLDSACrypto("ML-DSA-44");
            mlDsa65Crypto = buildMLDSACrypto("ML-DSA-65");
            mlDsa87Crypto = buildMLDSACrypto("ML-DSA-87");
            mlKem512Crypto = buildMLKEMCrypto("ML-KEM-512");
            mlKem768Crypto = buildMLKEMCrypto("ML-KEM-768");
            mlKem1024Crypto = buildMLKEMCrypto("ML-KEM-1024");
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
    // Tests: ML-DSA signing via WS-SecurityPolicy algorithm suites
    // -------------------------------------------------------------------------

    @Test
    public void testMLDSA44PolicySign() throws Exception {
        Assume.assumeTrue("BC 1.84+ required for ML-DSA", bcAvailable);
        currentCrypto = mlDsa44Crypto;
        runAndValidate(
            "wsse-request-clean.xml",
            "pqc_basic128_mldsa44_sign_policy.xml",
            null, null,
            Arrays.asList(SP12Constants.SIGNED_PARTS), null,
            Arrays.asList(CoverageType.SIGNED));
    }

    @Test
    public void testMLDSA65PolicySign() throws Exception {
        Assume.assumeTrue("BC 1.84+ required for ML-DSA", bcAvailable);
        currentCrypto = mlDsa65Crypto;
        runAndValidate(
            "wsse-request-clean.xml",
            "pqc_basic256_mldsa65_sign_policy.xml",
            null, null,
            Arrays.asList(SP12Constants.SIGNED_PARTS), null,
            Arrays.asList(CoverageType.SIGNED));
    }

    @Test
    public void testMLDSA87PolicySign() throws Exception {
        Assume.assumeTrue("BC 1.84+ required for ML-DSA", bcAvailable);
        currentCrypto = mlDsa87Crypto;
        runAndValidate(
            "wsse-request-clean.xml",
            "pqc_basic256_mldsa87_sign_policy.xml",
            null, null,
            Arrays.asList(SP12Constants.SIGNED_PARTS), null,
            Arrays.asList(CoverageType.SIGNED));
    }

    // -------------------------------------------------------------------------
    // Tests: ML-KEM encryption via WS-SecurityPolicy algorithm suites
    // -------------------------------------------------------------------------

    @Test
    public void testMLKEM512PolicyEncrypt() throws Exception {
        Assume.assumeTrue("BC 1.84+ required for ML-KEM", bcAvailable);
        currentCrypto = mlKem512Crypto;
        runAndValidate(
            "wsse-request-clean.xml",
            "pqc_basic128_mldsa44_encrypt_policy.xml",
            null, null,
            Arrays.asList(SP12Constants.ENCRYPTED_PARTS), null,
            Arrays.asList(CoverageType.ENCRYPTED));
    }

    @Test
    public void testMLKEM768PolicyEncrypt() throws Exception {
        Assume.assumeTrue("BC 1.84+ required for ML-KEM", bcAvailable);
        currentCrypto = mlKem768Crypto;
        runAndValidate(
            "wsse-request-clean.xml",
            "pqc_basic256_mldsa65_encrypt_policy.xml",
            null, null,
            Arrays.asList(SP12Constants.ENCRYPTED_PARTS), null,
            Arrays.asList(CoverageType.ENCRYPTED));
    }

    @Test
    public void testMLKEM1024PolicyEncrypt() throws Exception {
        Assume.assumeTrue("BC 1.84+ required for ML-KEM", bcAvailable);
        currentCrypto = mlKem1024Crypto;
        runAndValidate(
            "wsse-request-clean.xml",
            "pqc_basic256_mldsa87_encrypt_policy.xml",
            null, null,
            Arrays.asList(SP12Constants.ENCRYPTED_PARTS), null,
            Arrays.asList(CoverageType.ENCRYPTED));
    }

    // -------------------------------------------------------------------------
    // Overrides: inject PQC crypto into both outbound and inbound messages
    // -------------------------------------------------------------------------

    /**
     * Injects PQC crypto into every SoapMessage (both outbound and inbound paths).
     * SecurityConstants.SIGNATURE_CRYPTO takes priority over SIGNATURE_PROPERTIES
     * in WSS4JUtils, so the "outsecurity.properties" fallback set by super is ignored.
     */
    @Override
    protected SoapMessage getSoapMessageForDom(Document doc, AssertionInfoMap aim)
        throws Exception {
        SoapMessage msg = super.getSoapMessageForDom(doc, aim);
        msg.put(SecurityConstants.SIGNATURE_CRYPTO, currentCrypto);
        msg.put(SecurityConstants.ENCRYPT_CRYPTO, currentCrypto);
        msg.put(SecurityConstants.CALLBACK_HANDLER, buildCallbackHandler());
        return msg;
    }

    /**
     * Fixes the signing/encryption username to our PQC alias.
     * Super sets "myalias" (for outsecurity.properties); we override to ALIAS.
     * Exchange setup (MockEndpoint, Bus, REQUESTOR_ROLE) is inherited from super.
     */
    @Override
    protected SoapMessage getOutSoapMessageForDom(Document doc, AssertionInfoMap aim)
        throws Exception {
        SoapMessage msg = super.getOutSoapMessageForDom(doc, aim);
        msg.put(SecurityConstants.SIGNATURE_USERNAME, ALIAS);
        msg.put(SecurityConstants.ENCRYPT_USERNAME, ALIAS);
        return msg;
    }

    /**
     * Returns a PolicyBasedWSS4JInInterceptor without file-based crypto properties.
     * Crypto is resolved from SecurityConstants in the SoapMessage (set via getSoapMessageForDom).
     */
    @Override
    protected PolicyBasedWSS4JInInterceptor getInInterceptor(List<CoverageType> types) {
        PolicyBasedWSS4JInInterceptor handler = new PolicyBasedWSS4JInInterceptor();
        String action = "";
        for (CoverageType type : types) {
            switch (type) {
            case SIGNED:
                action += " " + ConfigurationConstants.SIGNATURE;
                break;
            case ENCRYPTED:
                action += " " + ConfigurationConstants.ENCRYPTION;
                break;
            default:
                break;
            }
        }
        handler.setProperty(ConfigurationConstants.ACTION, action.trim());
        handler.setProperty(ConfigurationConstants.IS_BSP_COMPLIANT, "false");
        return handler;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

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
