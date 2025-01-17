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

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.Assert;
import org.junit.internal.matchers.StringContains;

/**
 * A really hacky test that all methods are implemented
 *
 * @author Stuart Douglas
 */
class TestAllMethodsImplemented extends AbstractOpenSSLTest  {

    // @Test
    // public void testAllMethodsImplemented() throws IOException {

    //     Set<String> implemented = new HashSet<>();
    //     Pattern pattern = Pattern.compile("WF_OPENSSL\\([^,]*,([^\\)]*)");
    //     File path = new File("target/libwfssl" + File.separator + "src");
    //     for(String i : path.list()) {
    //         String file = read(new File(path, i));
    //         Matcher matcher = pattern.matcher(file);
    //         while (matcher.find()) {
    //             implemented.add(matcher.toMatchResult().group(1).trim() + "0");
    //         }
    //     }
    //     Set<String> notImplemented = new HashSet<>();
    //     for(Method m : SSLImpl.class.getDeclaredMethods()) {
    //         if(Modifier.isNative(m.getModifiers())) {
    //             if(!implemented.remove(m.getName())) {
    //                 notImplemented.add(m.getName());
    //             }
    //         }
    //     }
    //     if(!notImplemented.isEmpty()) {
    //         throw new RuntimeException("Not implemented " + notImplemented);
    //     }
    //     if(!implemented.isEmpty()) {
    //         throw new RuntimeException("Not needed " + implemented);
    //     }
    // }

    @Test(expected = classOf[RuntimeException])
    def testOpenSSLMessagesAreIncluded(): Unit = {
        var ssl: SSL = null;
        var ctx = 0L;
        try {
            ssl = SSL.getInstance();
            ctx = ssl.makeSSLContext(SSL.SSL_PROTOCOL_SSLV2, SSL.SSL_MODE_CLIENT);
            ssl.setCipherSuite(ctx, "invalid-cypher");
        } catch { case e: RuntimeException =>
            // check the root cause has the OpenSSL stack-trace message
            var rootCause: Throwable = e;
            while (rootCause.getCause() != null) {
                rootCause = rootCause.getCause();
            }
            Assert.assertThat(rootCause.getMessage(), StringContains.containsString(":no cipher match:"));
            throw e;
        } finally {
            if (ssl != null && ctx != 0) {
                ssl.freeSSLContext(ctx);
            }
        }
    }

    private def read(file: File): String = {
        val out = new ByteArrayOutputStream();
        val buf = new Array[Byte](100);
        val in = new FileInputStream(file)
        try {
            var r = 0;
            while ({r = in.read(buf); r > 0}) {
                out.write(buf, 0, r);
            }
        } finally {
            in.close()
        }
        return new String(out.toByteArray());
    }

}
