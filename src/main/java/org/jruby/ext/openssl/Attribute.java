
package org.jruby.ext.openssl;

import org.jruby.Ruby;
import org.jruby.RubyClass;

/**
 * @deprecated use {@link X509Attribute}
 */
@Deprecated
public class Attribute extends X509Attribute {

    public Attribute(Ruby runtime, RubyClass klass) {
        super(runtime, klass);
    }

}