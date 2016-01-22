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

package org.apache.cxf.transport.http_undertow.continuations;

import java.io.IOException;

import javax.servlet.AsyncContext;
import javax.servlet.AsyncEvent;
import javax.servlet.AsyncListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.continuations.Continuation;
import org.apache.cxf.continuations.ContinuationCallback;
import org.apache.cxf.message.Message;
import org.apache.cxf.transport.http.AbstractHTTPDestination;

public class UndertowContinuationWrapper implements Continuation {
    volatile boolean isNew;
    volatile boolean isResumed;
    volatile boolean isPending;
    volatile long pendingTimeout;
    volatile Object obj;
        
    private Message message;
    private ContinuationCallback callback;
    private AsyncContext context;
    private HttpServletRequest request;
   
    
    public UndertowContinuationWrapper(HttpServletRequest request, 
                                    HttpServletResponse resp, 
                                    Message m) {
        this.request = request;
        message = m;
        isNew = request.getAttribute(AbstractHTTPDestination.CXF_CONTINUATION_MESSAGE) == null;
        if (isNew) {
            request.setAttribute(AbstractHTTPDestination.CXF_CONTINUATION_MESSAGE,
                                 message.getExchange().getInMessage());
            callback = message.getExchange().get(ContinuationCallback.class);
        }
    }

    public Object getObject() {
        return obj;
    }
    public void setObject(Object userObject) {
        obj = userObject;
    }

    public void resume() {
        isResumed = true;
        isPending = false;
        //context.complete();
        context.dispatch();
    }

    public boolean isNew() {
        return isNew;
    }

    public boolean isPending() {
        return isPending;
    }

    public boolean isResumed() {
        return isResumed;
    }

    public void reset() {
        try {
            context.complete();
        } catch (Throwable ex) {
            // explicit complete call does not seem to work 
            // with the non-Servlet3 Undertow Continuation
        }
        obj = null;
        pendingTimeout = 0;
    }


    public boolean suspend(long timeout) {
        if (isPending && timeout != 0) {
            pendingTimeout += pendingTimeout + timeout;
        } else {
            pendingTimeout = timeout;
        }
        isNew = false;
        
        message.getExchange().getInMessage().getInterceptorChain().suspend();
        
        if (!isPending) {
            /*ManagedServlet managedServlet = new ManagedServlet(
                                                               new ServletInfo("default", DefaultServlet.class), 
                                                               ((HttpServletRequestImpl)request).getServletContext());
            ServletChain currentServlet = 
                new ServletChain((HttpHandler)request.getAttribute("HTTP_HANDLER"), managedServlet, null, true);
            ((HttpServletRequestImpl)request).getExchange().getAttachment(
                ServletRequestContext.ATTACHMENT_KEY).setCurrentServlet(currentServlet);*/
            context = request.startAsync();
            context.setTimeout(pendingTimeout);
            //context.setTimeout(300000); //just for the debug
            context.addListener(new AsyncListener() {

                @Override
                public void onComplete(AsyncEvent event) throws IOException {
                    getMessage().remove(AbstractHTTPDestination.CXF_CONTINUATION_MESSAGE);
                    isPending = false;
                    pendingTimeout = 0;
                    //REVISIT: isResumed = false;
                    if (callback != null) {
                        callback.onComplete();
                    }
                }

                @Override
                public void onTimeout(AsyncEvent event) throws IOException {
                    isPending = false;
                    pendingTimeout = 0;
                }

                @Override
                public void onError(AsyncEvent event) throws IOException {
                }

                @Override
                public void onStartAsync(AsyncEvent event) throws IOException {
                }
                
            });
            isPending = true;
        }
        return true;
    }
    
    protected Message getMessage() {
        Message m = message;
        if (m != null && m.getExchange().getInMessage() != null) {
            m = m.getExchange().getInMessage();
        }
        return m;
    }
        
}
