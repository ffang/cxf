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

package org.apache.cxf.systest.ws.rm;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import jakarta.activation.DataHandler;
import jakarta.mail.util.ByteArrayDataSource;
import jakarta.xml.ws.BindingProvider;
import jakarta.xml.ws.Endpoint;
import jakarta.xml.ws.soap.SOAPBinding;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.attachment.AttachmentImpl;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.greeter_control.Greeter;
import org.apache.cxf.greeter_control.GreeterService;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.message.Attachment;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.service.model.BindingOperationInfo;
import org.apache.cxf.testutil.common.AbstractBusClientServerTestBase;
import org.apache.cxf.testutil.common.AbstractBusTestServerBase;
import org.apache.cxf.ws.rm.RMManager;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests the retransmission of messages with attachments, which are written by the
 * AttachmentOutInterceptor again for each retransmission.
 */
public class RetransmissionAttachmentTest extends AbstractBusClientServerTestBase {
    public static final String PORT = allocatePort(RetransmissionAttachmentTest.class);

    static final byte[] ATTACHMENT = "attachment content".getBytes(StandardCharsets.UTF_8);
    /** The Content-Type and the attachments of the greetMeOneWay requests received by the server */
    static final BlockingQueue<String> RECEIVED_CONTENT_TYPES = new LinkedBlockingQueue<>();
    static final BlockingQueue<byte[]> RECEIVED_ATTACHMENTS = new LinkedBlockingQueue<>();

    private static final String CONFIG = "/org/apache/cxf/systest/ws/rm/simple.xml";

    private Bus bus;

    public static class Server extends AbstractBusTestServerBase {
        protected void run() {
            Bus bus = new SpringBusFactory().createBus(CONFIG);
            BusFactory.setDefaultBus(bus);
            setBus(bus);
            EndpointImpl ep = (EndpointImpl)Endpoint.create(new GreeterImpl());
            ep.getInInterceptors().add(new RequestRecorder());
            ep.publish("http://localhost:" + PORT + "/SoapContext/GreeterPort");
        }
    }

    static class RequestRecorder extends AbstractPhaseInterceptor<Message> {
        RequestRecorder() {
            super(Phase.PRE_INVOKE);
        }

        public void handleMessage(Message message) {
            if (!isGreetMeOneWay(message)) {
                return;
            }
            RECEIVED_CONTENT_TYPES.add((String)message.get(Message.CONTENT_TYPE));
            if (message.getAttachments() != null) {
                for (Attachment a : message.getAttachments()) {
                    try (InputStream in = a.getDataHandler().getInputStream()) {
                        RECEIVED_ATTACHMENTS.add(in.readAllBytes());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }
    }

    /** Adds a SwA attachment to the greetMeOneWay requests */
    static class AttachmentAdder extends AbstractPhaseInterceptor<Message> {
        AttachmentAdder() {
            super(Phase.PRE_LOGICAL);
        }

        public void handleMessage(Message message) {
            if (isGreetMeOneWay(message)) {
                List<Attachment> attachments = new ArrayList<>();
                attachments.add(new AttachmentImpl("attachment-1@cxf.apache.org",
                    new DataHandler(new ByteArrayDataSource(ATTACHMENT, "text/plain"))));
                message.setAttachments(attachments);
            }
        }
    }

    static boolean isGreetMeOneWay(Message message) {
        BindingOperationInfo boi = message.getExchange().getBindingOperationInfo();
        return boi != null && "greetMeOneWay".equals(boi.getName().getLocalPart());
    }

    @BeforeClass
    public static void startServers() throws Exception {
        assertTrue("server did not launch correctly", launchServer(Server.class, true));
    }

    @Before
    public void clearReceived() {
        RECEIVED_CONTENT_TYPES.clear();
        RECEIVED_ATTACHMENTS.clear();
    }

    @After
    public void shutdownBus() {
        if (bus != null) {
            bus.shutdown(true);
            bus = null;
        }
    }

    @Test
    public void testAttachmentRetransmitted() throws Exception {
        Greeter greeter = createGreeter();
        ClientProxy.getClient(greeter).getOutInterceptors().add(new AttachmentAdder());

        greeter.greetMeOneWay("attachment");

        String contentType = RECEIVED_CONTENT_TYPES.poll(10, TimeUnit.SECONDS);
        assertNotNull("the retransmitted message was not received", contentType);
        assertTrue(contentType, contentType.startsWith("multipart/related; type=\"text/xml\";"));
        byte[] attachment = RECEIVED_ATTACHMENTS.poll(1, TimeUnit.SECONDS);
        assertNotNull("no attachment was received", attachment);
        assertArrayEquals(ATTACHMENT, attachment);
    }

    @Test
    public void testMtomRetransmitted() throws Exception {
        Greeter greeter = createGreeter();
        ((SOAPBinding)((BindingProvider)greeter).getBinding()).setMTOMEnabled(true);

        greeter.greetMeOneWay("mtom");

        String contentType = RECEIVED_CONTENT_TYPES.poll(10, TimeUnit.SECONDS);
        assertNotNull("the retransmitted message was not received", contentType);
        assertTrue(contentType, contentType.contains("start-info=\"text/xml\""));
    }

    /**
     * Creates a client whose first transmission of each application message is lost, so that
     * the server only receives the retransmission.
     */
    private Greeter createGreeter() throws Exception {
        bus = new SpringBusFactory().createBus(CONFIG);
        BusFactory.setDefaultBus(bus);
        BusFactory.setThreadDefaultBus(bus);
        bus.getExtension(RMManager.class).getConfiguration().setBaseRetransmissionInterval(2000L);
        MessageLossSimulator loser = new MessageLossSimulator();
        loser.setMode(-1);
        bus.getOutInterceptors().add(loser);

        Greeter greeter = new GreeterService().getGreeterPort();
        updateAddressPort(greeter, PORT);
        return greeter;
    }
}
