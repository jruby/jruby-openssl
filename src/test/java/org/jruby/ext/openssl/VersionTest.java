/*
 * The MIT License
 *
 * Copyright 2017 Ketan Padegaonkar
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jruby.ext.openssl;

import org.junit.Test;
import org.junit.After;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import static org.jruby.ext.openssl.OpenSSL.*;

public class VersionTest {

    private final String javaVersion = System.getProperty("java.version");

    @After
    public void restoreJavaVersion() {
        System.setProperty("java.version", javaVersion);
    }

    @Test
    public void testAndroid0() {
        System.setProperty("java.version", "0");

        assertTrue(javaVersion7(true));
        assertTrue(javaVersion7(false));

        assertFalse(javaVersion8(true));
        assertFalse(javaVersion8(false));

        assertFalse(javaVersion9(false));
        assertFalse(javaVersion9(true));
    }

    @Test
    public void testInvalid() {
        System.setProperty("java.version", "");

        //assertTrue(javaVersion7(true));
        //assertTrue(javaVersion7(false));

        assertFalse(javaVersion8(true));
        assertFalse(javaVersion8(false));

        assertFalse(javaVersion9(false));
        assertFalse(javaVersion9(true));
    }

    @Test
    public void testJava7() {
        System.setProperty("java.version", "1.7.0");

        assertTrue(javaVersion7(true));
        assertTrue(javaVersion7(false));

        assertFalse(javaVersion8(true));
        assertFalse(javaVersion8(false));

        assertFalse(javaVersion9(false));
        assertFalse(javaVersion9(true));
    }

	@Test
	public void testJava8() {
        System.setProperty("java.version", "1.8.1");

		assertTrue(javaVersion7(true));
        assertFalse(javaVersion7(false));

        assertTrue(javaVersion8(true));
        assertTrue(javaVersion8(false));

        assertFalse(javaVersion9(false));
        assertFalse(javaVersion9(true));
	}

    @Test
    public void testJava8Crap() {
        System.setProperty("java.version", "1.8.PRE");

        assertTrue(javaVersion7(true));
        assertFalse(javaVersion7(false));

        assertTrue(javaVersion8(true));
        assertTrue(javaVersion8(false));

        assertFalse(javaVersion9(false));
        assertFalse(javaVersion9(true));
    }

    @Test
    public void testJava9Pre() {
        System.setProperty("java.version", "9");

        assertTrue(javaVersion7(true));
        assertFalse(javaVersion7(false));

        assertTrue(javaVersion8(true));
        assertFalse(javaVersion8(false));

        assertTrue(javaVersion9(false));
        assertTrue(javaVersion9(true));
    }

    @Test
    public void testJava9Noiz() {
        System.setProperty("java.version", "9-alfa");

        assertTrue(javaVersion7(true));
        assertFalse(javaVersion7(false));

        assertTrue(javaVersion8(true));
        assertFalse(javaVersion8(false));

        assertTrue(javaVersion9(false));
        assertTrue(javaVersion9(true));
    }

    @Test
    public void testJava9Bleh() {
        System.setProperty("java.version", "9.X");

        assertTrue(javaVersion7(true));
        assertFalse(javaVersion7(false));

        assertTrue(javaVersion8(true));
        assertFalse(javaVersion8(false));

        assertTrue(javaVersion9(false));
        assertTrue(javaVersion9(true));
    }

    @Test
    public void testJava9() {
        System.setProperty("java.version", "9.0.4");

        assertTrue(javaVersion7(true));
        assertFalse(javaVersion7(false));

        assertTrue(javaVersion8(true));
        assertFalse(javaVersion8(false));

        assertTrue(javaVersion9(false));
        assertTrue(javaVersion9(true));
    }

    @Test
    public void testJava10Pre() {
        System.setProperty("java.version", "10");

        assertTrue(javaVersion7(true));
        assertFalse(javaVersion7(false));

        assertTrue(javaVersion8(true));
        assertFalse(javaVersion8(false));

        assertFalse(javaVersion9(false));
        assertTrue(javaVersion9(true));

        assertTrue(javaVersion10(false));
        assertTrue(javaVersion10(true));
    }

    @Test
    public void testJava10Noiz() {
        System.setProperty("java.version", "10-RC");

        assertTrue(javaVersion7(true));
        assertFalse(javaVersion7(false));

        assertTrue(javaVersion8(true));
        assertFalse(javaVersion8(false));

        assertFalse(javaVersion9(false));
        assertTrue(javaVersion9(true));

        assertTrue(javaVersion10(false));
        assertTrue(javaVersion10(true));
    }

    @Test
    public void testJava10() {
        System.setProperty("java.version", "10.0");

        assertTrue(javaVersion7(true));
        assertFalse(javaVersion7(false));

        assertTrue(javaVersion8(true));
        assertFalse(javaVersion8(false));

        assertFalse(javaVersion9(false));
        assertTrue(javaVersion9(true));

        assertTrue(javaVersion10(false));
        assertTrue(javaVersion10(true));
    }

}
