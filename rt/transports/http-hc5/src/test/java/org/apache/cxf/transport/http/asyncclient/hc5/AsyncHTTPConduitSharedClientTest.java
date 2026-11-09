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

package org.apache.cxf.transport.http.asyncclient.hc5;

import org.apache.cxf.Bus;
import org.apache.cxf.bus.extension.ExtensionManagerBus;
import org.apache.cxf.service.model.EndpointInfo;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.core5.reactor.IOReactorStatus;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;

/**
 * Conduits with the same policy share one hc5 client, which must stay open while a conduit uses it
 */
public class AsyncHTTPConduitSharedClientTest {
    private Bus bus;
    private AsyncHTTPConduitFactory factory;
    private final HTTPClientPolicy policy = new HTTPClientPolicy();

    @Before
    public void setUp() {
        bus = new ExtensionManagerBus();
        factory = new AsyncHTTPConduitFactory(bus);
    }

    @After
    public void tearDown() {
        factory.shutdown();
        bus.shutdown(true);
    }

    @Test
    public void testClosingConduitKeepsClientOfOtherConduits() throws Exception {
        AsyncHTTPConduit conduit1 = newConduit();
        AsyncHTTPConduit conduit2 = newConduit();
        CloseableHttpAsyncClient client = conduit1.getHttpAsyncClient(null);
        assertSame(client, conduit2.getHttpAsyncClient(null));

        conduit1.close();
        // closing it again, as a finalizer may do, does not release the client twice
        conduit1.close();
        assertEquals(IOReactorStatus.ACTIVE, client.getStatus());

        conduit2.close();
        assertNotEquals(IOReactorStatus.ACTIVE, client.getStatus());
    }

    @Test
    public void testClosingConduitWithoutClientKeepsClientOfOtherConduits() throws Exception {
        AsyncHTTPConduit conduit = newConduit();
        CloseableHttpAsyncClient client = conduit.getHttpAsyncClient(null);

        // a conduit that has not got the client does not release it
        newConduit().close();
        assertEquals(IOReactorStatus.ACTIVE, client.getStatus());
        conduit.close();
    }

    @Test
    public void testConduitGetsNewClientAfterClose() throws Exception {
        AsyncHTTPConduit conduit = newConduit();
        CloseableHttpAsyncClient client = conduit.getHttpAsyncClient(null);
        conduit.close();

        // a conduit used after it was closed does not keep using the client it released
        CloseableHttpAsyncClient newClient = conduit.getHttpAsyncClient(null);
        assertNotSame(client, newClient);
        assertEquals(IOReactorStatus.ACTIVE, newClient.getStatus());
        conduit.close();
    }

    private AsyncHTTPConduit newConduit() throws Exception {
        EndpointInfo ei = new EndpointInfo();
        ei.setAddress("http://localhost/test");
        AsyncHTTPConduit conduit = new AsyncHTTPConduit(bus, ei, null, factory);
        conduit.finalizeConfig();
        conduit.setClient(policy);
        return conduit;
    }
}
