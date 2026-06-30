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
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import jakarta.xml.ws.Endpoint;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.systest.wssec.examples.common.DoubleItPortTypeImpl;
import org.apache.cxf.testutil.common.AbstractBusTestServerBase;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.Merlin;

/**
 * Embedded JAX-WS server for PQC (ML-DSA signature + ML-KEM encryption) system tests.
 *
 * <p>BouncyCastle must already be registered as a JCA provider before {@code run()}
 * is invoked (done by {@link PQCTest#startServers()}).
 *
 * <p>For ML-KEM, the test pre-populates the server's key pair via
 * {@link #setMlKemCrypto(Crypto)} before calling {@code launchServer()}.
 * This avoids needing a committed binary keystore for a key type that cannot
 * yet be stored portably.
 */
public class PQCServer extends AbstractBusTestServerBase {

    public static final String PORT = allocatePort(PQCServer.class);

    private static volatile Crypto mlKemCrypto;

    public PQCServer() {
    }

    public static void setMlKemCrypto(Crypto crypto) {
        mlKemCrypto = crypto;
    }

    public static Crypto getMlKemCrypto() {
        return mlKemCrypto;
    }

    @Override
    protected void run() {
        try {
            startMLDSAEndpoint();
            if (mlKemCrypto != null) {
                startMLKEMEndpoint();
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to start PQCServer", e);
        }
    }

    private void startMLDSAEndpoint() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        try (InputStream is = PQCServer.class.getResourceAsStream("mldsa.p12")) {
            ks.load(is, "security".toCharArray());
        }
        Merlin merlin = new Merlin();
        merlin.setKeyStore(ks);

        DoubleItPortTypeImpl impl = new DoubleItPortTypeImpl();
        impl.setEnforcePrincipal(false);

        EndpointImpl ep = (EndpointImpl) Endpoint.publish(
            "http://localhost:" + PORT + "/DoubleItMLDSASign", impl);

        Map<String, Object> props = new HashMap<>();
        props.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE);
        props.put(ConfigurationConstants.SIG_VER_PROP_REF_ID, "mldsaVerifyCrypto");
        props.put("mldsaVerifyCrypto", merlin);
        props.put("isBSPCompliant", "false");

        ep.getServer().getEndpoint().getInInterceptors()
            .add(new WSS4JInInterceptor(props));
    }

    private void startMLKEMEndpoint() throws Exception {
        DoubleItPortTypeImpl impl = new DoubleItPortTypeImpl();
        impl.setEnforcePrincipal(false);

        EndpointImpl ep = (EndpointImpl) Endpoint.publish(
            "http://localhost:" + PORT + "/DoubleItMLKEMEncrypt", impl);

        Map<String, Object> props = new HashMap<>();
        props.put(ConfigurationConstants.ACTION, ConfigurationConstants.ENCRYPTION);
        props.put(ConfigurationConstants.DEC_PROP_REF_ID, "mlKemDecCrypto");
        props.put("mlKemDecCrypto", mlKemCrypto);
        props.put(ConfigurationConstants.PW_CALLBACK_CLASS,
            PQCPasswordCallback.class.getName());
        props.put("isBSPCompliant", "false");

        ep.getServer().getEndpoint().getInInterceptors()
            .add(new WSS4JInInterceptor(props));
    }
}
