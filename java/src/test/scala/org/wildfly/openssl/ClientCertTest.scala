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
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Stuart Douglas
 */
class ClientCertTest extends AbstractOpenSSLTest {

    val MESSAGE = "Hello World";

    @Test
    def jsseClientCertTest() = {
        val serverSocket = SSLTestUtils.createServerSocket()
        try {
            val sessionID = new AtomicReference[Array[Byte]]();
            val sslContext = SSLTestUtils.createSSLContext("openssl.TLSv1.2");

            val acceptThread = new Thread(new EchoRunnable(serverSocket, sslContext, sessionID, (engine => {
                //engine.setNeedClientAuth(true);
                engine;
            })));
            acceptThread.start();
            val socket = SSLSocketFactory.getDefault().createSocket().asInstanceOf[SSLSocket]
            try {
                socket.setReuseAddress(true);
                socket.connect(SSLTestUtils.createSocketAddress());
                socket.getOutputStream().write(MESSAGE.getBytes(StandardCharsets.US_ASCII));
                val data = new Array[Byte](100);
                val read = socket.getInputStream().read(data);

                Assert.assertEquals(MESSAGE, new String(data, 0, read));
                if (! isTLS13Supported()) {
                    Assert.assertArrayEquals(socket.getSession().getId(), sessionID.get());
                }
            } finally {
                socket.close()
            }

            serverSocket.close();
            acceptThread.join();
        } finally {
            serverSocket.close()
        }
    }

}
