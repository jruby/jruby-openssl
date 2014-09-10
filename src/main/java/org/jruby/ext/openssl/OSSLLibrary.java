package org.jruby.ext.openssl;

import org.jruby.Ruby;
import org.jruby.runtime.load.Library;

import java.io.IOException;

/**
 * @deprecated
 * @see OpenSSL
 */
public class OSSLLibrary implements Library {

    public static void load(final Ruby runtime) {
        OpenSSL.load(runtime);
    }

    @Override
    public void load(Ruby runtime, boolean wrap) throws IOException {
        load(runtime);
    }

}
