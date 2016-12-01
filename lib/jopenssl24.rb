# frozen_string_literal: false

# Ruby 2.4 preliminary compatibility script, loaded after all (2.3) jruby-openssl files

module OpenSSL

  module SSL
    class SSLContext
      # OpenSSL 1.1.0 introduced "security level"
      def security_level; 0 end
      def security_level=(level); raise NotImplementedError end
    end
  end

  module PKey

    class DH

      def set_key(pub_key, priv_key)
        self.public_key = pub_key
        self.priv_key = priv_key
        self
      end

      def set_pqg(p, q, g)
        self.p = p
        self.q = q
        self.g = g
        self
      end

    end

    class DSA

      def set_key(pub_key, priv_key)
        self.public_key = pub_key
        self.priv_key = priv_key
        self
      end

      def set_pqg(p, q, g)
        self.p = p
        self.q = q
        self.g = g
        self
      end

    end

    class RSA

      def set_key(n, e, d)
        self.n = n
        self.e = e
        self.d = d
        self
      end

      def set_factors(p, q)
        self.p = p
        self.q = q
        self
      end

      def set_crt_params(dmp1, dmq1, iqmp)
        self.dmp1 = dmp1
        self.dmq1 = dmq1
        self.iqmp = iqmp
        self
      end

    end

  end

end
