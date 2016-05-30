/*
 * Copyright (c) 2016 kares.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.jruby.ext.openssl.util;

/**
 * Allows direct buffer access for less copy-ing.
 *
 * @author kares
 */
public final class ByteArrayOutputStream extends java.io.ByteArrayOutputStream {

    public ByteArrayOutputStream() {
        super();
    }

    public ByteArrayOutputStream(int size) {
        super(size);
    }

    public byte[] buffer() {
        return buf;
    }

    public int size() {
        return count;
    }

    @Override
    public byte[] toByteArray() {
        final int len = buf.length;
        if (count == len) return buf; // no-copying

        final byte[] copy = new byte[count];
        System.arraycopy(buf, 0, copy, 0, count);
        return copy;
    }

}
