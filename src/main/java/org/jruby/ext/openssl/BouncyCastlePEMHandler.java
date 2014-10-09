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

import java.io.Reader;
import java.io.Writer;
import java.lang.reflect.Method;
import java.security.SecureRandom;

//import org.bouncycastle.openssl.PEMReader; // uses Security API directly
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PasswordFinder;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
@Deprecated
public class BouncyCastlePEMHandler implements PEMHandler {

    @SuppressWarnings("unchecked")
    public Object readPEM(Reader read, String password) throws Exception {
        // NOTE: class not longer available since BC 1.50 :
        // return new PEMReader(read, new BasicPasswordFinder(password)).readObject();
        Class PEMReader = Class.forName("org.bouncycastle.openssl.PEMReader");
        Object pemReader = PEMReader.getConstructor(java.io.Reader.class, PasswordFinder.class).
                newInstance(read, new BasicPasswordFinder(password));
        return PEMReader.getMethod("readObject").invoke(pemReader);
    }

    public void writePEM(Writer writer, Object obj, String algorithm, char[] password) throws Exception {
        final PEMWriter pemWriter = new PEMWriter(writer);
        // NOTE: method parameters changed since BC 1.50 :
        // pemWriter.writeObject(obj, algorithm, password, null);
        Method writeObject = PEMWriter.class.getMethod("writeObject", Object.class, String.class, char[].class, SecureRandom.class);
        writeObject.invoke(pemWriter, obj, algorithm, password, null);
        pemWriter.flush();
    }

    public void writePEM(Writer writer, Object obj) throws Exception {
        PEMWriter pemWriter = new PEMWriter(writer);
        pemWriter.writeObject(obj);
        pemWriter.flush();
    }

    private static class BasicPasswordFinder implements PasswordFinder {

        private char[] pwd;

        BasicPasswordFinder(final String pwd) {
            if ( pwd != null ) this.pwd = pwd.toCharArray();
        }

        public char[] getPassword() {
            return this.pwd;
        }
    }

}// BouncyCastlePEMHandler
