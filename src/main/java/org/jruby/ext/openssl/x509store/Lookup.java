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
package org.jruby.ext.openssl.x509store;

import static org.jruby.ext.openssl.x509store.X509Utils.X509_CERT_DIR;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_FILETYPE_ASN1;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_FILETYPE_DEFAULT;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_FILETYPE_PEM;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_LU_CRL;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_LU_FAIL;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_LU_X509;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_L_ADD_DIR;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_L_FILE_LOAD;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_R_BAD_X509_FILETYPE;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_R_INVALID_DIRECTORY;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_R_LOADING_CERT_DIR;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_R_LOADING_DEFAULTS;
import static org.jruby.ext.openssl.x509store.X509Utils.X509_R_WRONG_LOOKUP_TYPE;
import static org.jruby.ext.openssl.x509store.X509Utils.getDefaultCertificateDirectoryEnvironment;
import static org.jruby.ext.openssl.x509store.X509Utils.getDefaultCertificateFileEnvironment;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.jruby.Ruby;
import org.jruby.RubyHash;
import org.jruby.ext.openssl.SecurityHelper;
import org.jruby.util.JRubyFile;
import org.jruby.util.io.ChannelDescriptor;
import org.jruby.util.io.ChannelStream;
import org.jruby.util.io.FileExistsException;
import org.jruby.util.io.InvalidValueException;
import org.jruby.util.io.ModeFlags;

/**
 * X509_LOOKUP
 *
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class Lookup {

    boolean init = false;
    boolean skip = false;

    final LookupMethod method;
    private final Ruby runtime;

    Object methodData;
    Store store;

    /**
     * c: X509_LOOKUP_new
     */
    public Lookup(Ruby runtime, LookupMethod method) {
        if ( method == null ) {
            throw new IllegalArgumentException("null method");
        }
        this.method = method;
        this.runtime = runtime;

        final LookupMethod.NewItemFunction newItem = method.newItem;
        if ( newItem != null && newItem != Function1.EMPTY ) {
            final int result;
            try {
                result = newItem.call(this);
            }
            catch (Exception e) {
                if ( e instanceof RuntimeException ) throw (RuntimeException) e;
                throw new IllegalArgumentException("invalid lookup method", e);
            }
            if ( result == 0) throw new IllegalArgumentException("invalid lookup method");
        }
    }

    /**
     * c: X509_LOOKUP_load_file
     */
    public int loadFile(CertificateFile.Path file) throws Exception {
        return control(X509_L_FILE_LOAD, file.name, file.type, null);
    }

    /**
     * c: X509_LOOKUP_add_dir
     */
    public int addDir(CertificateHashDir.Dir dir) throws Exception {
        return control(X509_L_ADD_DIR, dir.name, dir.type, null);
    }

    /**
     * c: X509_LOOKUP_hash_dir
     */
    public static LookupMethod hashDirLookup() {
        return x509DirectoryLookup;
    }

    /**
     * c: X509_LOOKUP_file
     */
    public static LookupMethod fileLookup() {
        return x509FileLookup;
    }

    /**
     * c: X509_LOOKUP_ctrl
     */
    public int control(final int cmd, final String argc, final long argl, final String[] ret) throws Exception {
        if ( method == null ) return -1;

        if ( method.control != null && method.control != Function5.EMPTY ) {
            return method.control.call(this, Integer.valueOf(cmd), argc, Long.valueOf(argl), ret);
        }
        return 1;
    }

    /**
     * c: X509_LOOKUP_load_cert_file
     */
    public int loadCertificateFile(String file, int type) throws Exception {
        if ( file == null ) return 1;

        int count = 0;
        int ret = 0;
        Reader reader = null;
        try {
            InputStream in = wrapJRubyNormalizedInputStream(file);
            X509AuxCertificate auxCert;
            if (type == X509_FILETYPE_PEM) {
                reader = new BufferedReader(new InputStreamReader(in));
                for (;;) {
                    auxCert = PEMInputOutput.readX509Aux(reader, null);
                    if ( auxCert == null ) break;
                    final int i = store.addCertificate(auxCert);
                    if ( i == 0 ) return ret;
                    count++;
                }
                ret = count;
            }
            else if (type == X509_FILETYPE_ASN1) {
                X509Certificate cert = (X509Certificate)
                    SecurityHelper.getCertificateFactory("X.509").generateCertificate(in);
                auxCert = StoreContext.ensureAux(cert);
                if ( auxCert == null ) {
                    X509Error.addError(13);
                    return ret;
                }
                final int i = store.addCertificate(auxCert);
                if ( i == 0 ) return ret;
                ret = i;
            } else {
                X509Error.addError(X509_R_BAD_X509_FILETYPE);
            }
        }
        finally {
            if ( reader != null ) {
                try { reader.close(); } catch (Exception ignored) {}
            }
        }
        return ret;
    }

    /**
     * c: X509_LOOKUP_load_crl_file
     */
    public int loadCRLFile(String file, int type) throws Exception {
        if ( file == null ) return 1;

        int count = 0;
        int ret = 0;
        Reader reader = null;
        try {
            InputStream in = wrapJRubyNormalizedInputStream(file);
            CRL crl;
            if (type == X509_FILETYPE_PEM) {
                reader = new BufferedReader(new InputStreamReader(in));
                for (;;) {
                    crl = PEMInputOutput.readX509CRL(reader, null);
                    if ( crl == null ) break;
                    final int i = store.addCRL(crl);
                    if ( i == 0 ) return ret;
                    count++;
                }
                ret = count;
            }
            else if (type == X509_FILETYPE_ASN1) {
                crl = SecurityHelper.getCertificateFactory("X.509").generateCRL(in);
                if (crl == null) {
                    X509Error.addError(13);
                    return ret;
                }
                final int i = store.addCRL(crl);
                if ( i == 0 ) return ret;
                ret = i;
            }
            else {
                X509Error.addError(X509_R_BAD_X509_FILETYPE);
            }
        }
        finally {
            if ( reader != null ) {
                try { reader.close(); } catch (Exception ignored) {}
            }
        }
        return ret;
    }

    /**
     * c: X509_LOOKUP_load_cert_crl_file
     */
    public int loadCertificateOrCRLFile(String file, int type) throws Exception {
        if ( type != X509_FILETYPE_PEM ) return loadCertificateFile(file, type);

        int count = 0;
        Reader reader = null;
        try {
            InputStream in = wrapJRubyNormalizedInputStream(file);
            reader = new BufferedReader(new InputStreamReader(in));
            for (;;) {
                Object v = PEMInputOutput.readPEM(reader, null);
                if ( v == null ) break;

                if ( v instanceof X509Certificate ) {
                    store.addCertificate(StoreContext.ensureAux((X509Certificate) v));
                    count++;
                }
                else if ( v instanceof CRL ) {
                    store.addCRL((CRL) v);
                    count++;
                }
            }
        }
        finally {
            if ( reader != null ) {
                try { reader.close(); } catch (Exception ignored) {}
            }
        }
        return count;
    }

    public int loadDefaultJavaCACertsFile() throws IOException, GeneralSecurityException {
        final String certsFile = X509Utils.X509_CERT_FILE.replace('/', File.separatorChar);
        final FileInputStream fin = new FileInputStream(certsFile);
        int count = 0;
        try {
            KeyStore keystore = SecurityHelper.getKeyStore(KeyStore.getDefaultType());
            // we pass a null password, as the cacerts file isn't password protected
            keystore.load(fin, null);
            PKIXParameters params = new PKIXParameters(keystore);
            for ( TrustAnchor trustAnchor : params.getTrustAnchors() ) {
                X509Certificate certificate = trustAnchor.getTrustedCert();
                store.addCertificate(certificate);
                count++;
            }
        }
        finally {
            try { fin.close(); } catch (Exception ignored) {}
        }
        return count;
    }

    private InputStream wrapJRubyNormalizedInputStream(String file) throws IOException {
        try {
            return JRubyFile.createResource(runtime, file).inputStream();
        }
        catch (NoSuchMethodError e) { // JRubyFile.createResource.inputStream (JRuby < 1.7.17)
            try {
                ChannelDescriptor descriptor = ChannelDescriptor.open(runtime.getCurrentDirectory(), file, new ModeFlags(ModeFlags.RDONLY));
                return ChannelStream.open(runtime, descriptor).newInputStream();
            } catch (NoSuchMethodError nsme) {
                File f = new File(file);
                if ( ! f.isAbsolute() ) {
                    f = new File(runtime.getCurrentDirectory(), file);
                }
                return new BufferedInputStream(new FileInputStream(f));
            } catch (FileExistsException fee) {
                // should not happen because ModeFlag does not contain CREAT.
                fee.printStackTrace(System.err);
                throw new IllegalStateException(fee.getMessage(), fee);
            } catch (InvalidValueException ive) {
                // should not happen because ModeFlasg does not contain APPEND.
                ive.printStackTrace(System.err);
                throw new IllegalStateException(ive.getMessage(), ive);
            }
        }
    }

    private String envEntry(final String key) {
    	RubyHash env = (RubyHash) runtime.getObject().getConstant("ENV");
        return (String) env.get( runtime.newString(key) );
    }

    /**
     * c: X509_LOOKUP_free
     */
    public void free() throws Exception {
        if ( method != null && method.free != null && method.free != Function1.EMPTY ) {
            method.free.call(this);
        }
    }

    /**
     * c: X509_LOOKUP_init
     */
    public int init() throws Exception {
        if ( method == null ) return 0;
        if ( method.init != null && method.init != Function1.EMPTY ) {
            return method.init.call(this);
        }
        return 1;
    }

    /**
     * c: X509_LOOKUP_by_subject
     */
    public int bySubject(final int type, final Name name, final X509Object[] ret) throws Exception {
        if ( method == null || method.getBySubject == null || method.getBySubject == Function4.EMPTY ) {
            return X509_LU_FAIL;
        }
        if ( skip ) return 0;
        return method.getBySubject.call(this, Integer.valueOf(type), name, ret);
    }

    /**
     * c: X509_LOOKUP_by_issuer_serial
     */
    public int byIssuerSerialNumber(final int type, final Name name, final BigInteger serial, final X509Object[] ret) throws Exception {
        if ( method == null || method.getByIssuerSerialNumber == null || method.getByIssuerSerialNumber == Function5.EMPTY ) {
            return X509_LU_FAIL;
        }
        return method.getByIssuerSerialNumber.call(this, Integer.valueOf(type), name, serial, ret);
    }

    /**
     * c: X509_LOOKUP_by_fingerprint
     */
    public int byFingerprint(final int type, final String bytes, final X509Object[] ret) throws Exception {
        if ( method == null || method.getByFingerprint == null || method.getByFingerprint == Function4.EMPTY ) {
            return X509_LU_FAIL;
        }
        return method.getByFingerprint.call(this, Integer.valueOf(type), bytes, ret);
    }

    /**
     * c: X509_LOOKUP_by_alias
     */
    public int byAlias(final int type, final String alias, final X509Object[] ret) throws Exception {
        if ( method == null || method.getByAlias == null || method.getByAlias == Function4.EMPTY ) {
            return X509_LU_FAIL;
        }
        return method.getByAlias.call(this, Integer.valueOf(type), alias, ret);
    }

    /**
     * c: X509_LOOKUP_shutdown
     */
    public int shutdown() throws Exception {
        if ( method == null ) return 0;

        if ( method.shutdown != null && method.shutdown != Function1.EMPTY ) {
            return method.shutdown.call(this);
        }
        return 1;
    }

    /**
     * c: x509_file_lookup
     */
    private final static LookupMethod x509FileLookup = new LookupMethod();
    static {
        x509FileLookup.name = "Load file into cache";
        x509FileLookup.control = new ByFile();
    }

    /**
     * c: x509_dir_lookup
     */
    private final static LookupMethod x509DirectoryLookup = new LookupMethod();
    static {
        x509DirectoryLookup.name = "Load certs from files in a directory";
        x509DirectoryLookup.newItem = new NewLookupDir();
        x509DirectoryLookup.free = new FreeLookupDir();
        x509DirectoryLookup.control = new LookupDirControl();
        x509DirectoryLookup.getBySubject = new GetCertificateBySubject();
    }

    /**
     * c: by_file_ctrl
     */
    private static class ByFile implements LookupMethod.ControlFunction {
        public int call(final Lookup ctx, final Integer cmd, final String argp, final Number argl, String[] ret) throws Exception {
            int ok = 0;
            String file = null;
            final int arglInt = argl.intValue();

            switch(cmd) {
            case X509_L_FILE_LOAD:
                if (arglInt == X509_FILETYPE_DEFAULT) {
                    try {
                        file = ctx.envEntry( getDefaultCertificateFileEnvironment() );
                    }
                    catch (RuntimeException e) { }

                    if (file != null) {
                        ok = ctx.loadCertificateOrCRLFile(file, X509_FILETYPE_PEM) != 0 ? 1 : 0;
                    } else {
                        ok = (ctx.loadDefaultJavaCACertsFile() != 0) ? 1: 0;
                    }
                    if (ok == 0) {
                        X509Error.addError(X509_R_LOADING_DEFAULTS);
                    }
                } else {
                    if (arglInt == X509_FILETYPE_PEM) {
                        ok = (ctx.loadCertificateOrCRLFile(argp, X509_FILETYPE_PEM) != 0) ? 1 : 0;
                    } else {
                        ok = (ctx.loadCertificateFile(argp, arglInt) != 0) ? 1 : 0;
                    }
                }
                break;
            }

            return ok;
        }
    }

    /**
     * c: BY_DIR, lookup_dir_st
     */
    private static class LookupDir {
        Collection<String> dirs;
        Collection<Integer> dirsType;
    }

    /**
     * c: new_dir
     */
    private static class NewLookupDir implements LookupMethod.NewItemFunction {
        public int call(final Lookup lookup) {
            final LookupDir lookupDir = new LookupDir();
            lookupDir.dirs = new ArrayList<String>();
            lookupDir.dirsType = new ArrayList<Integer>();
            lookup.methodData = lookupDir;
            return 1;
        }
    }

    /**
     * c: free_dir
     */
    private static class FreeLookupDir implements LookupMethod.FreeFunction {
        public int call(final Lookup lookup) {
            final LookupDir lookupDir = (LookupDir) lookup.methodData;
            lookupDir.dirs = null;
            lookupDir.dirsType = null;
            lookup.methodData = null;
            return -1;
        }
    }

    /**
     * c: dir_ctrl
     */
    private static class LookupDirControl implements LookupMethod.ControlFunction {

        public int call(final Lookup ctx, final Integer cmd, String argp, Number argl, String[] retp) {
            int ret = 0;
            final LookupDir lookupData = (LookupDir) ctx.methodData;
            switch ( cmd ) {
            case X509_L_ADD_DIR :
                if ( argl.intValue() == X509_FILETYPE_DEFAULT ) {
                    String certDir = null;
                    try {
                        certDir = getDefaultCertificateDirectory(ctx);
                    }
                    catch (RuntimeException e) { }

                    if ( certDir != null ) {
                        ret = addCertificateDirectory(lookupData, certDir, X509_FILETYPE_PEM);
                    } else {
                        ret = addCertificateDirectory(lookupData, X509_CERT_DIR, X509_FILETYPE_PEM);
                    }
                    if ( ret == 0 ) {
                        X509Error.addError(X509_R_LOADING_CERT_DIR);
                    }
                }
                else {
                    ret = addCertificateDirectory(lookupData, argp, argl.intValue());
                }
                break;
            }
            return ret;
        }

        private static String getDefaultCertificateDirectory(final Lookup ctx) {
        	return ctx.envEntry( getDefaultCertificateDirectoryEnvironment() );
        }

        /**
         * c: add_cert_dir
         */
        private int addCertificateDirectory(final LookupDir ctx, final String dir, final int type) {
            if ( dir == null || dir.isEmpty() ) {
                X509Error.addError(X509_R_INVALID_DIRECTORY);
                return 0;
            }

            String[] dirs = dir.split(File.pathSeparator);

            for ( int i=0; i<dirs.length; i++ ) {
                if ( dirs[i].length() == 0 ) {
                    continue;
                }
                if ( ctx.dirs.contains(dirs[i]) ) {
                    continue;
                }
                ctx.dirsType.add(type);
                ctx.dirs.add(dirs[i]);
            }

            return 1;
        }
    }

    /**
     * c: get_cert_by_subject
     */
    private static class GetCertificateBySubject implements LookupMethod.BySubjectFunction {
        public int call(final Lookup lookup, final Integer type, final Name name, final X509Object[] ret) throws Exception {
            if ( name == null ) return 0;

            int ok = 0;

            final String postfix;
            if ( type == X509_LU_X509 ) {
                postfix = "";
            }
            else if ( type == X509_LU_CRL ) {
                postfix = "r";
            }
            else {
                X509Error.addError(X509_R_WRONG_LOOKUP_TYPE);
                return ok;
            }

            final LookupDir context = (LookupDir) lookup.methodData;

            final String hash = String.format("%08x", name.hash());
            final StringBuilder buffer = new StringBuilder(48);

            final Iterator<Integer> iter = context.dirsType.iterator();

            for ( final String dir : context.dirs ) {
                final int dirType = iter.next();
                for ( int k = 0; ; k++ ) {
                    buffer.setLength(0); // reset - clear buffer
                    buffer.append(dir).append(File.separatorChar);
                    buffer.append(hash);
                    buffer.append('.').append(postfix).append(k);

                    final String path = buffer.toString();
                    if ( ! new File(path).exists() ) break;

                    if ( type == X509_LU_X509 ) {
                        if ( lookup.loadCertificateFile(path, dirType) == 0 ) {
                            break;
                        }
                    } else if ( type == X509_LU_CRL ) {
                        if ( lookup.loadCRLFile(path, dirType) == 0 ) {
                            break;
                        }
                    }
                }
                X509Object tmp = null;
                for ( X509Object obj : lookup.store.getObjects() ) {
                    if ( obj.type() == type && obj.isName(name) ) {
                        tmp = obj; break;
                    }
                }
                if ( tmp != null ) {
                    ok = 1; ret[0] = tmp; break;
                }
            }

            return ok;
        }
    }

}// X509_LOOKUP
