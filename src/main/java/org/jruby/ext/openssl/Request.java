
package org.jruby.ext.openssl;

import org.jruby.Ruby;
import org.jruby.RubyClass;

/**
 * @deprecated use {@link X509Attribute}
 */
@Deprecated
public class Request extends X509Request {

    public Request(Ruby runtime, RubyClass klass) {
        super(runtime, klass);
    }

}