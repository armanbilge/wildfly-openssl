/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.openssl;

import org.wildfly.openssl.OpenSSLEngine.isTLS13Supported;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
class ALPNTest extends AbstractOpenSSLTest {

    final val MESSAGE = "Hello World";

    @Test
    def testALPN() = {
        Assume.assumeTrue(OpenSSLEngine.isAlpnSupported());
        testALPNBase("TLSv1.2");
    }

    @Test
    def testALPNTLS13() = {
        Assume.assumeTrue(OpenSSLEngine.isAlpnSupported());
        Assume.assumeTrue(isTLS13Supported());
        testALPNBase("TLSv1.3");
    }

    private def testALPNBase(protocol: String) = {
        val serverSocket = SSLTestUtils.createServerSocket()
        try {
            val sessionID = new AtomicReference[Array[Byte]]();
            val sslContext = SSLTestUtils.createSSLContext("openssl." + protocol);
            val engineAtomicReference = new AtomicReference[OpenSSLEngine]();
            val acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID, (engine => {
                val openSSLEngine = engine.asInstanceOf[OpenSSLEngine];
                openSSLEngine.setApplicationProtocols("h2", "h2/13", "http");
                engineAtomicReference.set(openSSLEngine);
                openSSLEngine;
            })));
            acceptThread.start();

            val clientSslContext = SSLTestUtils.createClientSSLContext("openssl." + protocol);
            val socket = clientSslContext.getSocketFactory().createSocket().asInstanceOf[OpenSSLSocket];
            socket.setReuseAddress(true);
            socket.setApplicationProtocols("h2/13", "h2", "http");
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            val data = new Array[Byte](100);
            val read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertEquals("server side", "h2", engineAtomicReference.get().getSelectedApplicationProtocol());
            Assert.assertEquals("client side", "h2", socket.getSelectedApplicationProtocol());
            Assert.assertEquals(protocol, socket.getSession().getProtocol());
            Assert.assertEquals(protocol.equals("TLSv1.3"), CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        } finally {
            serverSocket.close()
        }
    }

    @Test
    def testALPNFailure() = {
        Assume.assumeTrue(OpenSSLEngine.isAlpnSupported());
        testALPNFailureBase("TLSv1.2");
    }

    @Test
    def testALPNFailureTLS13() = {
        Assume.assumeTrue(OpenSSLEngine.isAlpnSupported());
        Assume.assumeTrue(isTLS13Supported());
        testALPNFailureBase("TLSv1.3");
    }

    def testALPNFailureBase(protocol: String) = {
        val serverSocket = SSLTestUtils.createServerSocket()
        try {
            val sessionID = new AtomicReference[Array[Byte]]();
            val sslContext = SSLTestUtils.createSSLContext("openssl." + protocol);
            val clientSslContext = SSLTestUtils.createClientSSLContext("openssl." + protocol);
            val engineAtomicReference = new AtomicReference[OpenSSLEngine]();
            val acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID, (engine => {
                val openSSLEngine = engine.asInstanceOf[OpenSSLEngine];
                openSSLEngine.setApplicationProtocols("h2", "h2/13", "http");
                engineAtomicReference.set(openSSLEngine);
                openSSLEngine;
            })));
            acceptThread.start();
            val socket = clientSslContext.getSocketFactory().createSocket().asInstanceOf[OpenSSLSocket];
            socket.setReuseAddress(true);
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            val data = new Array[Byte](100);
            val read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            Assert.assertNull("server side", engineAtomicReference.get().getSelectedApplicationProtocol());
            Assert.assertNull("client side", socket.getSelectedApplicationProtocol());
            Assert.assertEquals(protocol, socket.getSession().getProtocol());
            Assert.assertEquals(protocol.equals("TLSv1.3"), CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        } finally {
            serverSocket.close()
        }
    }
}
