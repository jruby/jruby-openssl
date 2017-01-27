package org.jruby.ext.openssl;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.builtin.IRubyObject;

public class OCSPSingleResponse extends RubyObject {
    private static final long serialVersionUID = 7947277768033100227L;

    private static ObjectAllocator SINGLERESPONSE_ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klass) {
            return new OCSPSingleResponse(runtime, klass);
        }
    };
        
    public static void createResponse(final Ruby runtime, final RubyModule _OCSP) {
        RubyClass _request = _OCSP.defineClassUnder("SingleResponse", runtime.getObject(), SINGLERESPONSE_ALLOCATOR);
        _request.defineAnnotatedMethods(OCSPSingleResponse.class);
    }

    public OCSPSingleResponse(Ruby runtime, RubyClass metaClass) {
        super(runtime, metaClass);
    }

}
