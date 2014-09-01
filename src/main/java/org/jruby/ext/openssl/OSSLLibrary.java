package org.jruby.ext.openssl;

import org.jruby.Ruby;
import org.jruby.runtime.load.Library;

import java.io.IOException;

public class OSSLLibrary implements Library {

    public static void load(final Ruby runtime) {
        OpenSSLReal.createOpenSSL(runtime);
    }

    @Override
    public void load(Ruby runtime, boolean wrap) throws IOException {
        load(runtime);
    }

}
