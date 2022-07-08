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
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

object SslCiphersTest {
    @BeforeClass
    def setup() = {
        OpenSSLProvider.register();
    }
}

/**
 * @author Stuart Douglas
 */
class SslCiphersTest extends AbstractOpenSSLTest {

    @Test
    def testCipherSuiteConverter() = {

        val socket = SSLSocketFactory.getDefault().createSocket().asInstanceOf[SSLSocket];
        socket.setReuseAddress(true);
        socket.getSupportedCipherSuites().foreach { cipher =>
            if (!cipher.contains("EMPTY")) {
                val openSslCipherSuite = CipherSuiteConverter.toOpenSsl(cipher);
                Assert.assertNotNull(cipher, openSslCipherSuite);
                Assert.assertEquals(cipher, CipherSuiteConverter.toJava(openSslCipherSuite, cipher.substring(0, 3)));
            }
        }
        socket.close();
    }

    @Test
    def testAvailableProtocols() {
        val sessionID = new AtomicReference[Array[Byte]]();
        val sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1.2");

        //we only test a subset of ciphers
        //TODO: figure out which ones we need to support, and what sort of cert we need for each
        val suites = Array(
                //"TLS_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                //"TLS_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                //"TLS_RSA_WITH_AES_256_CBC_SHA"
        );

        suites.foreach { suite =>

            val engineRef = new AtomicReference[SSLEngine]();

            val serverSocket = SSLTestUtils.createServerSocket();
            val echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine => {
                engineRef.set(engine);
                try {
                    engine.setEnabledCipherSuites(Array(suite));
                    engine;
                } catch { case e: Exception =>
                    throw new RuntimeException(e);
                }
            }));
            val acceptThread = new Thread(echo);
            acceptThread.start();

            val socket = SSLSocketFactory.getDefault().createSocket().asInstanceOf[SSLSocket];
            socket.setReuseAddress(true);
            socket.setEnabledCipherSuites(Array(suite));
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write("hello world".getBytes(StandardCharsets.US_ASCII));
            val data = new Array[Byte](100);
            val read = socket.getInputStream().read(data);

            Assert.assertEquals("hello world", new String(data, 0, read));
            //make sure the names match
            var cipherSuite = socket.getSession().getCipherSuite();
            val sslEngine = engineRef.get();
            val session = sslEngine.getSession();
            // SSL is an alias for TLS, Windows and IBM J9 seem to use SSL for simplicity we'll just replace SSL with
            // TLS to match what we're expecting
            if(cipherSuite.startsWith("SSL")) {
                cipherSuite = cipherSuite.replace("SSL", "TLS");
            }
            Assert.assertEquals(session.getCipherSuite(), cipherSuite);
            Assert.assertEquals(session.getCipherSuite(), suite);
            Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
            socket.getSession().invalidate();
            socket.close();
            echo.stop();
            serverSocket.close();
            acceptThread.join();
        }
    }

    @Test
    def testAvailableProtocolsWithTLS13CipherSuites() = {
        Assume.assumeTrue(isTLS13Supported());
        val sessionID = new AtomicReference[Array[Byte]]();
        val sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1.3");

        val suites = Array(
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_128_CCM_8_SHA256",
                "TLS_AES_128_CCM_SHA256"
        );

        suites.foreach { suite =>

            val engineRef = new AtomicReference[SSLEngine]();

            val serverSocket = SSLTestUtils.createServerSocket();
            val echo = new EchoRunnable(serverSocket, sslContext, sessionID, (engine => {
                engineRef.set(engine);
                try {
                    engine.setEnabledCipherSuites(Array("TLS_RSA_WITH_AES_128_CBC_SHA256", suite));
                    engine;
                } catch { case e: Exception =>
                    throw new RuntimeException(e);
                }
            }));
            val acceptThread = new Thread(echo);
            acceptThread.start();

            val clientContext = SSLTestUtils.createClientSSLContext("openssl.TLSv1.3");
            val socket = clientContext.getSocketFactory().createSocket().asInstanceOf[SSLSocket];
            socket.setReuseAddress(true);
            socket.setEnabledCipherSuites(Array("TLS_RSA_WITH_AES_128_CBC_SHA256", suite));
            socket.connect(SSLTestUtils.createSocketAddress());
            socket.getOutputStream().write("hello world".getBytes(StandardCharsets.US_ASCII));
            val data = new Array[Byte](100);
            val read = socket.getInputStream().read(data);

            Assert.assertEquals("hello world", new String(data, 0, read));
            //make sure the names match
            val cipherSuite = socket.getSession().getCipherSuite();
            val protocol = socket.getSession().getProtocol();
            val sslEngine = engineRef.get();
            val session = sslEngine.getSession();
            Assert.assertEquals(session.getCipherSuite(), cipherSuite);
            Assert.assertEquals(session.getCipherSuite(), suite);
            Assert.assertEquals(session.getProtocol(), protocol);

            socket.getSession().invalidate();
            socket.close();
            echo.stop();
            serverSocket.close();
            acceptThread.join();
        }
    }
}
