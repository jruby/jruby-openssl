/*
 * Copyright (c) 2017 Karol Bucek.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.jruby.ext.openssl;

import org.jruby.Ruby;
import org.jruby.RubyModule;

/**
 * OpenSSL::ExtConfig (emulation)
 *
 * @author kares
 */
public class ExtConfig {

    static void create(Ruby runtime, RubyModule OpenSSL) {
        RubyModule ExtConfig = OpenSSL.defineModuleUnder("ExtConfig");
        ExtConfig.defineAnnotatedMethods(ExtConfig.class);

        ExtConfig.setConstant("OPENSSL_NO_SOCK", runtime.getNil()); // true/false (default) on MRI
        // TODO: we really should attempt to detect whether we support this :
        ExtConfig.setConstant("TLS_DH_anon_WITH_AES_256_GCM_SHA384", runtime.getFalse());
        ExtConfig.setConstant("HAVE_TLSEXT_HOST_NAME", runtime.getTrue());
    }

}
