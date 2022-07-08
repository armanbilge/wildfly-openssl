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
import org.wildfly.openssl.SSL.SSL_PROTO_SSLv2Hello;
import org.wildfly.openssl.SSLTestUtils.HOST;
import org.wildfly.openssl.SSLTestUtils.PORT;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
class BasicOpenSSLEngineTest extends AbstractOpenSSLTest  {

    val MESSAGE = "Hello World";

    @Test
    def basicOpenSSLTest() = {
        basicTest("openssl.TLSv1.2", "openssl.TLSv1.2");
    }

    @Test
    def basicOpenSSLTestTLS13() = {
        Assume.assumeTrue(isTLS13Supported());
        basicTest("openssl.TLSv1.3", "openssl.TLSv1.3");
    }

    @Test
    def basicOpenSSLTestInterop() = {
        basicTest("openssl.TLSv1.2", "TLSv1.2");
        basicTest("TLSv1.2", "openssl.TLSv1.2");
    }

    @Test
    def basicOpenSSLTestInteropTLS13() = {
        Assume.assumeTrue(isTLS13Supported());
        basicTest("openssl.TLSv1.3", "TLSv1.3");
        basicTest("TLSv1.3", "openssl.TLSv1.3");
    }

    private def basicTest(serverProvider: String, clientProvider: String) = {
        val serverSocket = SSLTestUtils.createServerSocket()
        try {
            val sessionID = new AtomicReference[Array[Byte]]();
            val sslContext = SSLTestUtils.createSSLContext(serverProvider);

            val acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID));
            acceptThread.start();
            val socket = SSLTestUtils.createClientSSLContext(clientProvider).getSocketFactory().createSocket().asInstanceOf[SSLSocket];
            socket.setReuseAddress(true);
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            val data = new Array[Byte](100);
            val read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            if (! isTLS13Supported()) {
                Assert.assertNotNull(socket.getSession().getId());
                if (sessionID.get() != null) {
                    // may be null with some older versions of OpenSSL (this assertion is also commented
                    // out in other existing tests)
                    Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
                }
            }
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        } finally {
            serverSocket.close()
        }
    }

    @Test
    def testNoExplicitEnabledProtocols() = {
        val serverSocket = SSLTestUtils.createServerSocket()
        try {
            val sessionID = new AtomicReference[Array[Byte]]();
            val sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            val engineRef = new AtomicReference[SSLEngine]();

            val echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine => {
                engineRef.set(engine);
                try {
                    engine;
                } catch { case e: Exception =>
                    throw new RuntimeException(e);
                }
            }));
            val acceptThread = new Thread(echo);
            acceptThread.start();
            val socket = SSLSocketFactory.getDefault().createSocket().asInstanceOf[SSLSocket];
            socket.setReuseAddress(true);
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            val data = new Array[Byte](100);
            val read = socket.getInputStream().read(data);
            val sslEngine = engineRef.get();
            val session = sslEngine.getSession();

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            if (! isTLS13Supported()) {
                Assert.assertArrayEquals(sessionID.get(), socket.getSession().getId());
                Assert.assertEquals("TLSv1.2", socket.getSession().getProtocol());
                Assert.assertArrayEquals(sessionID.get(), session.getId());
                Assert.assertFalse(CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            } else {
                Assert.assertEquals("TLSv1.3", socket.getSession().getProtocol());
                Assert.assertTrue(CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            }
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        } finally {
            serverSocket.close()
        }
    }

    @Test
   def testSingleEnabledProtocol() = {
        testSingleEnabledProtocolBase("TLSv1.2");
    }

    @Test
    def testSingleEnabledProtocolTLS13() = {
        Assume.assumeTrue(isTLS13Supported());
        testSingleEnabledProtocolBase("TLSv1.3");
    }

    def testSingleEnabledProtocolBase(protocol: String) = {
        val serverSocket = SSLTestUtils.createServerSocket()
        try {
            val sessionID = new AtomicReference[Array[Byte]]();
            val sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            val engineRef = new AtomicReference[SSLEngine]();

            val echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine => {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(Array(protocol)); // only one protocol enabled on server side
                    engine;
                } catch { case e: Exception =>
                    throw new RuntimeException(e);
                }
            }));
            val acceptThread = new Thread(echo);
            acceptThread.start();
            val socket = SSLSocketFactory.getDefault().createSocket().asInstanceOf[SSLSocket];
            socket.setReuseAddress(true);
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            val data = new Array[Byte](100)
            val read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            val session = engineRef.get().getSession();
            Assert.assertNotNull(session);
            if (! protocol.equals("TLSv1.3")) {
                Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
                Assert.assertArrayEquals(socket.getSession().getId(), session.getId());
            }
            Assert.assertEquals(protocol, socket.getSession().getProtocol());
            Assert.assertEquals(protocol.equals("TLSv1.3"), CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            Assert.assertArrayEquals(Array[Object](SSL_PROTO_SSLv2Hello, protocol), engineRef.get().getEnabledProtocols().asInstanceOf[Array[Object]]);
            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        } finally {
            serverSocket.close()
        }
    }

    @Test
    def testNoTLS13CipherSuitesEnabled() = {
        Assume.assumeTrue(isTLS13Supported());
        testEnabledCipherSuites(Array("ALL"), false); // only enable TLS v1.2 cipher suites
    }

    @Test
    def testBothTLS12AndTLS13CipherSuitesEnabled() = {
        Assume.assumeTrue(isTLS13Supported());
        testEnabledCipherSuites(Array("TLS_AES_128_GCM_SHA256", "ALL"), true);
    }

    @Test
    def testTLS13CipherSuiteEnabled() = {
        Assume.assumeTrue(isTLS13Supported());
        testEnabledCipherSuites(Array("TLS_AES_128_GCM_SHA256"), true);
    }

    @Test
    def testTLS13UsedByDefault() = {
        Assume.assumeTrue(isTLS13Supported());
        testEnabledCipherSuites(Array("TLS_AES_128_GCM_SHA256"), true);
    }

    private def testEnabledCipherSuites(cipherSuites: Array[String], tls13Expected: Boolean) = {
        val serverSocket = SSLTestUtils.createServerSocket()
        try {
            val sessionID = new AtomicReference[Array[Byte]]();
            val sslContext = SSLTestUtils.createSSLContext("openssl.TLS");
            val engineRef = new AtomicReference[SSLEngine]();

            val echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine => {
                engineRef.set(engine);
                try {
                    if (! tls13Expected) {
                        engine.setEnabledProtocols(Array("TLSv1.2"));
                    }
                    engine.setEnabledCipherSuites(cipherSuites);
                    engine;
                } catch { case e: Exception =>
                    throw new RuntimeException(e);
                }
            }));
            val acceptThread = new Thread(echo);
            acceptThread.start();
            val socket = SSLSocketFactory.getDefault().createSocket().asInstanceOf[SSLSocket];
            socket.setReuseAddress(true);
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
            val data = new Array[Byte](100);
            val read = socket.getInputStream().read(data);

            Assert.assertEquals(MESSAGE, new String(data, 0, read));
            if (! tls13Expected) {
                Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
                Assert.assertEquals("TLSv1.2", socket.getSession().getProtocol());
                Assert.assertEquals(false, CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
            } else {
                Assert.assertEquals("TLSv1.3", socket.getSession().getProtocol());
                Assert.assertEquals(true, CipherSuiteConverter.isTLSv13CipherSuite(socket.getSession().getCipherSuite()));
                Assert.assertEquals(cipherSuites(0), socket.getSession().getCipherSuite());
            }

            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        } finally {
            serverSocket.close()
        }
    }

    @Test
    def testWrongClientSideTrustManagerFailsValidation() = {
        val serverSocket = SSLTestUtils.createServerSocket()
        try {
            val sessionID = new AtomicReference[Array[Byte]]();
            val sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1.2");

            val acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID));
            acceptThread.start();
            val socket = SSLTestUtils.createSSLContext("openssl.TLSv1.2").getSocketFactory().createSocket().asInstanceOf[SSLSocket]
            socket.setReuseAddress(true);
            socket.setSSLParameters(socket.getSSLParameters());
            socket.connect(SSLTestUtils.createSocketAddress());
            try {
                socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                Assert.fail("Expected SSLException not thrown");
            } catch { case _: SSLException =>
                socket.close();
                serverSocket.close();
                acceptThread.join();
            }
        } finally {
            serverSocket.close()
        }
    }


    @Test
    def openSslLotsOfDataTest() = {
        openSslLotsOfDataTestBase("TLSv1.2");
    }

    @Test
    def openSslLotsOfDataTestTLS13() = {
        Assume.assumeTrue(isTLS13Supported());
        openSslLotsOfDataTestBase("TLSv1.3");
    }

    private def openSslLotsOfDataTestBase(protocol: String) = {
        val serverSocket = SSLTestUtils.createServerSocket()
        try {
            val sessionID = new AtomicReference[Array[Byte]]();
            val sslContext = SSLTestUtils.createSSLContext("openssl.TLS");

            val engineRef = new AtomicReference[SSLEngine]();
            val target = new EchoRunnable(serverSocket, sslContext, sessionID, (engine => {
                engineRef.set(engine);
                try {
                    engine.setEnabledProtocols(Array(protocol)); // only one protocol enabled on server side
                    engine;
                } catch { case e: Exception =>
                    throw new RuntimeException(e);
                }
            }));
            val acceptThread = new Thread(target);
            acceptThread.start();
            val socket = SSLSocketFactory.getDefault().createSocket().asInstanceOf[SSLSocket];
            socket.setReuseAddress(true);
            socket.connect(SSLTestUtils.createSocketAddress());
            val message = generateMessage(1000);
            socket.getOutputStream().write(message.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().write(Array[Byte](0));

            Assert.assertEquals(message, new String(SSLTestUtils.readData(socket.getInputStream())));
            if (! isTLS13Supported()) {
                Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            }

            socket.getSession().invalidate();
            socket.close();
            serverSocket.close();
            acceptThread.join();
        } finally {
            serverSocket.close()
        }
    }

    @Test
    def testTwoWay() = {
        performTestTwoWay("openssl.TLSv1.2", "openssl.TLSv1.2", "TLSv1.2");
    }

    @Test
    def testTwoWayTLS13() = {
        Assume.assumeTrue(isTLS13Supported());
        performTestTwoWay("openssl.TLSv1.3", "openssl.TLSv1.3", "TLSv1.3");
    }

    @Test
    def testTwoWayInterop() = {
        performTestTwoWay("openssl.TLSv1.2", "TLSv1.2", "TLSv1.2"); // openssl server
        performTestTwoWay("TLSv1.2", "openssl.TLSv1.2", "TLSv1.2"); // openssl client
    }

    @Test
    def testTwoWayInteropTLS13() = {
        Assume.assumeTrue(isTLS13Supported());
        performTestTwoWay("openssl.TLSv1.3", "TLSv1.3", "TLSv1.3"); // openssl server
        performTestTwoWay("TLSv1.3", "openssl.TLSv1.3", "TLSv1.3"); // openssl client
    }

    private def performTestTwoWay(serverProvider: String, clientProvider: String, protocol: String) = {
        val serverContext = SSLTestUtils.createSSLContext(serverProvider);
        val executorService = Executors.newSingleThreadExecutor();
        val socketFuture = executorService.submit(() => {
            try {
                val clientContext = SSLTestUtils.createClientSSLContext(clientProvider);
                val sslSocket = clientContext.getSocketFactory().createSocket(HOST, PORT).asInstanceOf[SSLSocket];
                sslSocket.setReuseAddress(true);
                sslSocket.getSession();
                sslSocket;
            } catch { case e: Exception =>
                throw new RuntimeException(e);
            }
        });

        val sslServerSocket = serverContext.getServerSocketFactory().createServerSocket(PORT, 10, InetAddress.getByName(HOST)).asInstanceOf[SSLServerSocket];
        sslServerSocket.setNeedClientAuth(true);
        val serverSocket = sslServerSocket.accept().asInstanceOf[SSLSocket];
        val serverSession = serverSocket.getSession();
        val clientSocket = socketFuture.get();
        val clientSession = clientSocket.getSession();

        try {
            var expectedProtocol: String = null
            if (protocol.equals("TLS")) {
                expectedProtocol = if (isTLS13Supported()) "TLSv1.3" else "TLSv1.2";
            } else {
                expectedProtocol = protocol;
            }
            Assert.assertEquals(expectedProtocol, clientSession.getProtocol());
            Assert.assertEquals(expectedProtocol, serverSession.getProtocol());
            Assert.assertEquals(expectedProtocol.equals("TLSv1.3"), CipherSuiteConverter.isTLSv13CipherSuite(clientSession.getCipherSuite()));
            Assert.assertEquals(expectedProtocol.equals("TLSv1.3"), CipherSuiteConverter.isTLSv13CipherSuite(serverSession.getCipherSuite()));
            Assert.assertNotNull(clientSession.getPeerCertificates());
            Assert.assertNotNull(serverSession.getPeerCertificates());
        } finally {
            serverSocket.close();
            clientSocket.close();
            sslServerSocket.close();
        }
    }


    private def generateMessage(repetitions: Int): String = {
        val builder = new StringBuilder(repetitions * MESSAGE.length());
        for (i <- 0 until repetitions) {
            builder.append(MESSAGE);
        }
        return builder.toString();
    }
}
