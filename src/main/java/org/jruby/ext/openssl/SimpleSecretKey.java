/***** BEGIN LICENSE BLOCK *****
 * Version: EPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Eclipse Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/epl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2006 Ola Bini <ola@ologix.com>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the EPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the EPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/
package org.jruby.ext.openssl;

import javax.crypto.SecretKey;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class SimpleSecretKey implements SecretKey {

    private static final long serialVersionUID = 1L;

    private final String algorithm;
    private final byte[] value;

    public SimpleSecretKey(final String algorithm, final byte[] value) {
        this.algorithm = algorithm;
        this.value = value;
    }

    public static SimpleSecretKey copy(String algorithm, final byte[] value) {
        return copy(algorithm, value, 0, value.length);
    }

    public static SimpleSecretKey copy(String algorithm, final byte[] value, int off, int len) {
        final byte[] val = new byte[len];
        System.arraycopy(value, off, val, 0, len);
        return new SimpleSecretKey(algorithm, val);
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public byte[] getEncoded() {
        return value;
    }

    public String getFormat() {
        return "RAW";
    }

    public boolean equals(Object o) {
        if ( o instanceof SimpleSecretKey ) {
            byte[] ovalue = ((SimpleSecretKey) o).value;
            if ( value.length != ovalue.length ) return false;
            for ( int i = 0; i < value.length; i++ ) {
                if ( value[i] != ovalue[i] ) return false;
            }
            return algorithm.equals( ((SimpleSecretKey) o).algorithm );
        }
        return false;
    }

    public int hashCode() {
        int code = 0;
        for ( int i = 0; i < value.length; i++ ) {
            code ^= (value[i] & 0xff) << (i << 3 & 31);
        }
        return code ^ algorithm.hashCode();
    }

}// SimpleSecretKey
