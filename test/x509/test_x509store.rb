# coding: US-ASCII
require File.expand_path('../test_helper', File.dirname(__FILE__))
require File.expand_path('../ssl/test_helper', File.dirname(__FILE__))

class TestX509Store < TestCase

  def setup; require 'openssl'
    cert = File.read(File.expand_path('../newcert.pem', __FILE__)) # File.read(File.expand_path('../server.crt', __FILE__))
    @cert = OpenSSL::X509::Certificate.new(cert)
    @ca_cert = File.expand_path('../ca.crt', __FILE__) # File.expand_path('../demoCA/cacert.pem', __FILE__)
    @javastore = File.expand_path('../javastore.ts', __FILE__)
    @jks_store = File.expand_path('../javastore.jks', __FILE__)
    @pkcs12_store = File.expand_path('../javastore.p12', __FILE__)
    @pem = File.expand_path('../Entrust.net_Premium_2048_Secure_Server_CA.pem', __FILE__) # validity: 1999 - 2029
  end

  @@ssl_cert_file = ENV['SSL_CERT_FILE']

  def teardown
    ENV['SSL_CERT_FILE'] = @@ssl_cert_file
  end

  def test_store_location_with_pem
    ENV['SSL_CERT_FILE'] = nil
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    assert !store.verify(@cert) unless explicit_java_trust_store?

    ENV['SSL_CERT_FILE'] = @ca_cert
    store = OpenSSL::X509::Store.new
    assert ! store.verify(@cert)
    store.set_default_paths

    puts @cert.inspect if $VERBOSE
    #puts @cert.to_java java.security.cert.X509Certificate if $VERBOSE

    verified = store.verify(@cert)
    assert verified, "CA verification failed: #{store.inspect}"
  end

  def test_store_location_with_java_truststore
    skip unless defined? JRUBY_VERSION
    skip 'JKS keystore is unavailable' unless java_keystore_available?('JKS')
    ENV['SSL_CERT_FILE'] = @javastore
    store = OpenSSL::X509::Store.new
    assert ! store.verify(@cert)
    store.set_default_paths

    #puts @cert.inspect if $VERBOSE
    #puts @cert.to_java java.security.cert.X509Certificate

    verified = store.verify(@cert)
    assert verified, "JKS verification failed: #{store.inspect}"
  end

  def test_store_location_with_jks_keystore_auto_detection
    skip unless defined? JRUBY_VERSION
    skip 'JKS keystore is unavailable' unless java_keystore_available?('JKS')
    assert_store_location_with_java_keystore @jks_store, 'PKCS12'
  end

  def test_store_location_with_pkcs12_keystore_auto_detection
    skip unless defined? JRUBY_VERSION
    skip 'PKCS12 keystore is unavailable' unless java_keystore_available?('PKCS12')
    assert_store_location_with_java_keystore @pkcs12_store, 'JKS'
  end

  def test_use_gibberish_cert_file
    ENV['SSL_CERT_FILE'] = File.expand_path('../gibberish.pem', __FILE__)
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    assert ! store.verify(@cert)
  end

  def test_use_default_pem_cert_file_as_custom_file
    certs = default_cert_file_pem_certs
    skip 'DEFAULT_CERT_FILE is not a PEM bundle' if certs.empty?

    ENV['SSL_CERT_FILE'] = OpenSSL::X509::DEFAULT_CERT_FILE
    store = OpenSSL::X509::Store.new
    store.set_default_paths

    cert = certs.find { |candidate| store.verify(candidate) }
    assert cert, "no certificate from DEFAULT_CERT_FILE verified against the default PEM store: #{store.inspect}"
  end

  def test_use_default_java_cacerts_file_as_custom_file
    skip 'DEFAULT_CERT_FILE is a PEM bundle' unless default_cert_file_pem_certs.empty?

    ENV['SSL_CERT_FILE'] = OpenSSL::X509::DEFAULT_CERT_FILE
    store = OpenSSL::X509::Store.new
    store.set_default_paths

    cert = default_cert_file_java_certs.find { |candidate| store.verify(candidate) }
    assert cert, "no certificate from DEFAULT_CERT_FILE verified against the default Java ca-certs store: #{store.inspect}"
  end if defined?(JRUBY_VERSION)

  def default_cert_file_pem_certs
    File.binread(OpenSSL::X509::DEFAULT_CERT_FILE).
      scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m).
      map { |cert_pem| OpenSSL::X509::Certificate.new(cert_pem) }
  end
  private :default_cert_file_pem_certs

  def default_cert_file_java_certs
    cert_file = OpenSSL::X509::DEFAULT_CERT_FILE
    if cert_file == ENV_JAVA['javax.net.ssl.trustStore']
      type = ENV_JAVA['javax.net.ssl.trustStoreType'] || java.security.KeyStore.getDefaultType
      password = ENV_JAVA['javax.net.ssl.trustStorePassword']
      provider = ENV_JAVA['javax.net.ssl.trustStoreProvider']
    else
      type = self.class.java_version.last.to_i >= 18 ? 'PKCS12' : 'JKS'
    end
    keystore = java.security.KeyStore.getInstance(type, provider || 'SUN')
    input = java.io.FileInputStream.new(cert_file)
    begin
      keystore.load(input, password && password.to_java.toCharArray)
    ensure
      input.close
    end

    certs = []
    aliases = keystore.aliases
    while aliases.hasMoreElements
      certs << OpenSSL::X509::Certificate.new(keystore.getCertificate(aliases.nextElement).getEncoded)
    end
    certs
  end
  private :default_cert_file_java_certs

  def explicit_java_trust_store?
    defined?(JRUBY_VERSION) && ENV_JAVA['javax.net.ssl.trustStore']
  end
  private :explicit_java_trust_store?

  def java_keystore_available?(type)
    java.security.KeyStore.getInstance(type)
    true
  rescue java.security.KeyStoreException
    false
  end
  private :java_keystore_available?

  def assert_store_location_with_java_keystore(path, default_type)
    security = java.security.Security
    original_type = security.getProperty('keystore.type')
    original_compat = security.getProperty('keystore.type.compat')
    security.setProperty('keystore.type', default_type)
    security.setProperty('keystore.type.compat', 'false')

    ENV['SSL_CERT_FILE'] = path
    store = OpenSSL::X509::Store.new
    assert !store.verify(@cert)
    store.set_default_paths
    assert store.verify(@cert), "keystore verification failed: #{store.inspect}"
  ensure
    security.setProperty('keystore.type', original_type) if original_type
    security.setProperty('keystore.type.compat', original_compat) if original_compat
  end
  private :assert_store_location_with_java_keystore

  def test_add_file_to_store_with_custom_cert_file
    ENV['SSL_CERT_FILE'] = @ca_cert
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    store.add_file @pem
    cert = OpenSSL::X509::Certificate.new(File.read(@pem))

    #p cert if $VERBOSE

    verified = store.verify(cert)
    assert verified, "verification failed for cert: #{cert.inspect} - #{store.inspect}"
  end


  def test_add_file_to_store_with_expired_ca_cert
    ENV['SSL_CERT_FILE'] = @ca_cert
    pem = File.expand_path('../Entrust.net_Secure_Server_CA.expired.pem', __FILE__)
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    store.add_file pem
    cert = OpenSSL::X509::Certificate.new(File.read(pem))

    p cert if $VERBOSE

    verified = store.verify(cert)
    assert !verified, "verification passed for (expired) cert: #{cert.inspect}"
  end

  def test_add_file_raises_with_invalid_pem # GH-285
    store = OpenSSL::X509::Store.new
    invalid = File.expand_path('../gibberish.pem', __FILE__)
    assert_raise(OpenSSL::X509::StoreError) { store.add_file(invalid) }
  end

  # CRuby's Store#time= accepts Time, Integer, and Float (epoch seconds).
  # Ported from CRuby's test/openssl/test_x509store.rb (time-based verification).
  def test_store_time_accepts_integer
    store = OpenSSL::X509::Store.new
    store.add_file @ca_cert
    # set time as integer epoch seconds ??? must not raise
    store.time = Time.now.to_i
    assert store.verify(@cert)
  end

  def test_store_context_verify_raises_on_reuse
    store = OpenSSL::X509::Store.new
    store.add_file @ca_cert
    ctx = OpenSSL::X509::StoreContext.new(store, @cert)
    ctx.verify
    # MRI raises StoreError when X509_verify_cert returns -1 (internal error)
    assert_raise(OpenSSL::X509::StoreError) { ctx.verify }
  end

  # CRuby raises TypeError (not StoreError) for wrong argument types
  def test_add_cert_type_check
    store = OpenSSL::X509::Store.new
    assert_raise(TypeError) { store.add_cert("not a cert") }
    assert_raise(TypeError) { store.add_cert(nil) }
  end

  def test_add_crl_type_check
    store = OpenSSL::X509::Store.new
    assert_raise(TypeError) { store.add_crl("not a crl") }
    assert_raise(TypeError) { store.add_crl(nil) }
  end

  # CRuby undefs initialize_copy, blocking both dup and clone
  def test_store_dup_clone_not_allowed
    store = OpenSSL::X509::Store.new
    assert_raise(NoMethodError) { store.dup }
    assert_raise(NoMethodError) { store.clone }
  end

  def test_add_path_returns_self
    store = OpenSSL::X509::Store.new
    assert_equal store, store.add_path("/etc/ssl/certs")
  end

  def test_add_path_raises_with_empty_string
    store = OpenSSL::X509::Store.new
    assert_raise(OpenSSL::X509::StoreError) { store.add_path("") }
  end

  def test_add_path_accepts_nonexistent_dir
    store = OpenSSL::X509::Store.new
    # CRuby accepts non-existent dirs (lazy lookup at verify time)
    assert_equal store, store.add_path("/nonexistent/path/to/certs")
  end

  def test_use_non_existing_cert_file
    ENV['SSL_CERT_FILE'] = 'non-existing-file.crt'
    store = OpenSSL::X509::Store.new
    store.set_default_paths
    assert ! store.verify(@cert)
  end

  def test_verify_with_wrong_argument
    store = OpenSSL::X509::Store.new
    assert_raise(TypeError) { store.verify( 'not a cert object' ) }
  end

  def test_add_cert_concurrently
    store = OpenSSL::X509::Store.new
    t = []
    (0..25).each do
      t << Thread.new do
        (0..2).each do
          store.add_file @pem
        end
      end
    end

    t.each(&:join)
    # just ensure there is no concurreny error
    assert true
  end

  define_method 'test_add_same_cert_twice jruby/jruby-openssl#3' do
    root_key = OpenSSL::PKey::RSA.new 2048 # the CA's public/private key
    root_ca = OpenSSL::X509::Certificate.new
    root_ca.version = 2 # cf. RFC 5280 - to make it a "v3" certificate
    root_ca.serial = 1
    root_ca.subject = OpenSSL::X509::Name.parse "/DC=org/DC=ruby-lang/CN=Ruby CA"
    root_ca.issuer = root_ca.subject # root CA's are "self-signed"
    root_ca.public_key = root_key.public_key
    root_ca.not_before = Time.now
    root_ca.not_after = root_ca.not_before + 2 * 365 * 24 * 60 * 60 # 2 years validity
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = root_ca
    ef.issuer_certificate = root_ca
    root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
    root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
    root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
    root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
    root_ca.sign(root_key, OpenSSL::Digest::SHA256.new)

    cert_store = OpenSSL::X509::Store.new
    assert cert_store.add_cert(root_ca) == cert_store
    # NOTE: logic reverted in JOSSL 0.11.0 to match C-OpenSSL (just adds certificates wout checks)
    #begin
      cert_store.add_cert(root_ca)
      #fail 'added same cert twice'
    #rescue OpenSSL::X509::StoreError => e
      #assert_equal 'cert already in hash table', e.message
    #end
  end

  def test_adding_pem_to_store_like_rubygems
    debug = false
    #OpenSSL.debug = true
    # mimic what rubygems/request#add_rubygems_trusted_certs does to find the .pem certificates
    # 1.7: jruby-complete-1.7.22.jar!/META-INF/jruby.home/lib/ruby/shared
    # 9.0: /opt/local/rvm/rubies/jruby-9.0.4.0/lib/ruby/stdlib
    base = $LOAD_PATH.detect { |p| p =~ /ruby\/shared/ || p =~ /ruby\/stdlib/ }
    raise "rubygems home not detected in $LOAD_PATH" unless base
    pems = Dir[ File.join(base, 'rubygems/ssl_certs/*pem') ]
    # assert_equal( 9, pems.size ) # >= 11 on 9K
    pems.each do |pem|
      puts pem.inspect if debug
      store = OpenSSL::X509::Store.new
      cert = OpenSSL::X509::Certificate.new(File.read(pem))
      assert ! store.verify(cert)
      store.add_file(pem)
      # only verify on self signed certifactes
      assert store.verify(cert) if pem !~ /COMODORSA|AddTrustExternalCARoot/
    end
  end if defined?(JRUBY_VERSION) && Gem::Version.create(JRUBY_VERSION) >= Gem::Version.create('9.1.17.0')

  # build an issuingDistributionPoint (2.5.29.28) extension with a fullName URI distributionPoint
  def idp_extension(uri)
    gn         = OpenSSL::ASN1::ASN1Data.new(uri.b, 6, :CONTEXT_SPECIFIC)         # GeneralName URI [6]
    full_name  = OpenSSL::ASN1::ASN1Data.new([gn], 0, :CONTEXT_SPECIFIC)          # DistributionPointName fullName [0]
    dist_point = OpenSSL::ASN1::ASN1Data.new([full_name], 0, :CONTEXT_SPECIFIC)   # IDP distributionPoint [0]
    OpenSSL::X509::Extension.new("2.5.29.28", OpenSSL::ASN1::Sequence.new([dist_point]).to_der, true)
  end

  def test_crl_idp_distribution_point_scope # F13 - IDP distributionPoint must match the cert's CRLDP
    return unless defined?(OpenSSL::X509::V_FLAG_CRL_CHECK)
    return unless defined?(OpenSSL::X509::V_ERR_DIFFERENT_CRL_SCOPE)

    ca_key = OpenSSL::PKey::RSA.new SSLTestHelper::TEST_KEY_RSA2
    ee_key = OpenSSL::PKey::RSA.new SSLTestHelper::TEST_KEY_RSA1
    now = Time.at(Time.now.to_i)
    ca = issue_cert(OpenSSL::X509::Name.parse("/CN=IDP-Scope-CA"), ca_key, 1,
                    [["basicConstraints", "CA:TRUE", true], ["keyUsage", "cRLSign,keyCertSign", true]],
                    nil, nil, not_before: now - 3600, not_after: now + 7200)
    # EE references CRL distribution point "crlA"
    ee = issue_cert(OpenSSL::X509::Name.parse("/CN=IDP-Scope-EE"), ee_key, 100,
                    [["keyUsage", "digitalSignature", true],
                     ["crlDistributionPoints", "URI:http://ca/crlA.pem", false]],
                    ca, ca_key, not_before: now - 3600, not_after: now + 3600)

    idp_crl = lambda do |dp_uri|
      crl = OpenSSL::X509::CRL.new
      crl.issuer = ca.subject
      crl.version = 1
      crl.last_update = now
      crl.next_update = now + 3600
      revoked = OpenSSL::X509::Revoked.new
      revoked.serial = 100 # revoke the EE cert
      revoked.time = now
      crl.add_revoked(revoked)
      crl.add_extension(OpenSSL::X509::Extension.new("crlNumber", OpenSSL::ASN1::Integer(1)))
      crl.add_extension(idp_extension(dp_uri))
      crl.sign(ca_key, OpenSSL::Digest::SHA256.new)
      crl
    end

    verify = lambda do |crl|
      store = OpenSSL::X509::Store.new
      store.purpose = OpenSSL::X509::PURPOSE_ANY
      store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK
      store.add_cert(ca)
      store.add_crl(crl)
      [store.verify(ee), store.error]
    end

    # CRL scoped to the same distribution point the cert references -> in scope, revocation applies
    ok, err = verify.call(idp_crl.call("http://ca/crlA.pem"))
    assert_equal(false, ok)
    assert_equal(OpenSSL::X509::V_ERR_CERT_REVOKED, err)

    # CRL scoped to a different distribution point -> out of scope, must not revoke the cert
    ok, err = verify.call(idp_crl.call("http://ca/crlB.pem"))
    assert_equal(false, ok)
    assert_equal(OpenSSL::X509::V_ERR_DIFFERENT_CRL_SCOPE, err)
  end

  def test_crl_entry_certificate_issuer_scope
    # a CRL entry scoped (certificateIssuer) to another issuer must not revoke

    ca_key = OpenSSL::PKey::RSA.new SSLTestHelper::TEST_KEY_RSA2
    ee_key = OpenSSL::PKey::RSA.new SSLTestHelper::TEST_KEY_RSA1
    now = Time.at(Time.now.to_i)
    ca = issue_cert(OpenSSL::X509::Name.parse("/CN=CRLEntry-Scope-CA"), ca_key, 1,
                    [["basicConstraints", "CA:TRUE", true], ["keyUsage", "cRLSign,keyCertSign", true]],
                    nil, nil, not_before: now - 3600, not_after: now + 7200)
    ee = issue_cert(OpenSSL::X509::Name.parse("/CN=CRLEntry-Scope-EE"), ee_key, 100,
                    [["keyUsage", "digitalSignature", true]],
                    ca, ca_key, not_before: now - 3600, not_after: now + 3600)

    # certificateIssuer (2.5.29.29): GeneralNames with a single directoryName [4] scoping the entry elsewhere
    cert_issuer_ext = lambda do |dn|
      name_seq  = OpenSSL::ASN1.decode(OpenSSL::X509::Name.parse(dn).to_der)   # Name (RDNSequence)
      dir_name  = OpenSSL::ASN1::ASN1Data.new([name_seq], 4, :CONTEXT_SPECIFIC) # GeneralName directoryName [4]
      gen_names = OpenSSL::ASN1::Sequence.new([dir_name])
      OpenSSL::X509::Extension.new("2.5.29.29", gen_names.to_der, true)        # MUST be critical per RFC 5280
    end

    build_crl = lambda do |scope_issuer|
      crl = OpenSSL::X509::CRL.new
      crl.issuer = ca.subject
      crl.version = 1
      crl.last_update = now
      crl.next_update = now + 3600
      revoked = OpenSSL::X509::Revoked.new
      revoked.serial = 100 # same serial as the EE cert
      revoked.time = now
      revoked.add_extension(cert_issuer_ext.call("/CN=Some-Other-Issuer")) if scope_issuer
      crl.add_revoked(revoked)
      crl.add_extension(OpenSSL::X509::Extension.new("crlNumber", OpenSSL::ASN1::Integer(1)))
      crl.sign(ca_key, OpenSSL::Digest::SHA256.new)
      crl
    end

    verify = lambda do |crl|
      store = OpenSSL::X509::Store.new
      store.purpose = OpenSSL::X509::PURPOSE_ANY
      store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK
      store.add_cert(ca)
      store.add_crl(crl)
      [store.verify(ee), store.error]
    end

    # control: a plain entry carrying the EE serial revokes the cert
    ok, err = verify.call(build_crl.call(false))
    assert_equal(false, ok)
    assert_equal(OpenSSL::X509::V_ERR_CERT_REVOKED, err)

    # same serial, but the entry is scoped to a different (indirect) issuer -> must not revoke this cert
    ok, err = verify.call(build_crl.call(true))
    assert_not_equal(OpenSSL::X509::V_ERR_CERT_REVOKED, err)
    assert_equal(true, ok)
  end

  def test_crl_time_boundary
    #return unless defined?(OpenSSL::X509::V_FLAG_CRL_CHECK)

    rsa = OpenSSL::PKey::RSA.new SSLTestHelper::TEST_KEY_RSA2
    ca_name = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CRL-Time-CA")
    ca_exts = [
        ["basicConstraints", "CA:TRUE", true],
        ["keyUsage", "cRLSign,keyCertSign", true],
    ]
    now = Time.at(Time.now.to_i)
    ca_cert = issue_cert(ca_name, rsa, 1, ca_exts, nil, nil, not_before: now - 3600, not_after: now + 3600)
    # CRL valid over [now .. now+1800], revokes nothing
    crl = issue_crl([], 1, now, now + 1800, [], ca_cert, rsa, OpenSSL::Digest::SHA256.new)

    verify_at = lambda do |check_time|
      store = OpenSSL::X509::Store.new
      store.purpose = OpenSSL::X509::PURPOSE_ANY
      store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK
      store.time = check_time
      # fresh cert copies - the underlying X509 struct caches last not-before/signature result
      store.add_cert(OpenSSL::X509::Certificate.new(ca_cert))
      store.add_crl(crl)
      [store.verify(OpenSSL::X509::Certificate.new(ca_cert)), store.error, store.error_string]
    end

    # thisUpdate == check time -> valid (previously mis-rejected as last-update-field error)
    ok, err, msg = verify_at.call(now)
    assert_equal(true, ok, "CRL with thisUpdate == check time should verify, got: #{msg}")
    assert_equal(OpenSSL::X509::V_OK, err)

    # nextUpdate == check time -> expired per <= semantics, reported as CRL_HAS_EXPIRED
    ok, err, _ = verify_at.call(now + 1800)
    assert_equal(false, ok)
    assert_equal(OpenSSL::X509::V_ERR_CRL_HAS_EXPIRED, err)

    # thisUpdate in the future -> not yet valid (regression guard)
    ok, err, _ = verify_at.call(now - 1)
    assert_equal(false, ok)
    assert_equal(OpenSSL::X509::V_ERR_CRL_NOT_YET_VALID, err)
  end

  def test_verify
    @rsa1024 = OpenSSL::PKey::RSA.new SSLTestHelper::TEST_KEY_RSA1 # OpenSSL::TestUtils::TEST_KEY_RSA1024
    @rsa2048 = OpenSSL::PKey::RSA.new SSLTestHelper::TEST_KEY_RSA2 # OpenSSL::TestUtils::TEST_KEY_RSA2048
    @dsa256  = OpenSSL::PKey::DSA.new SSLTestHelper::TEST_KEY_DSA256 # OpenSSL::TestUtils::TEST_KEY_DSA256
    @dsa512  = OpenSSL::PKey::DSA.new SSLTestHelper::TEST_KEY_DSA512 # OpenSSL::TestUtils::TEST_KEY_DSA512
    @ca1 = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA1")
    @ca2 = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA2")
    @ee1 = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=EE1")
    @ee2 = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=EE2")

    now = Time.at(Time.now.to_i)
    ca_exts = [
        ["basicConstraints","CA:TRUE",true],
        ["keyUsage","cRLSign,keyCertSign",true],
    ]
    ee_exts = [
        ["keyUsage","keyEncipherment,digitalSignature",true],
    ]
    ca1_cert = issue_cert(@ca1, @rsa2048, 1, ca_exts, nil, nil, not_before: now, not_after: now + 3600)
    ca2_cert = issue_cert(@ca2, @rsa1024, 2, ca_exts, ca1_cert, @rsa2048, not_before: now, not_after: now + 1800)
    ee1_cert = issue_cert(@ee1, @dsa256, 10, ee_exts, ca2_cert, @rsa1024, not_before: now, not_after: now + 1800)
    ee2_cert = issue_cert(@ee2, @dsa512, 20, ee_exts, ca2_cert, @rsa1024, not_before: now, not_after: now + 1800)
    ee3_cert = issue_cert(@ee2, @dsa512, 30, ee_exts, ca2_cert, @rsa1024, not_before: now - 100, not_after: now - 1)
    ee4_cert = issue_cert(@ee2, @dsa512, 40, ee_exts, ca2_cert, @rsa1024, not_before: now + 1000, not_after: now + 2000)

    revoke_info = []
    crl1   = issue_crl(revoke_info, 1, now, now+1800, [],
                       ca1_cert, @rsa2048, sha1_or_approved)
    revoke_info = [ [2, now, 1], ]
    crl1_2 = issue_crl(revoke_info, 2, now, now+1800, [],
                       ca1_cert, @rsa2048, sha1_or_approved)
    revoke_info = [ [20, now, 1], ]
    crl2   = issue_crl(revoke_info, 1, now, now+1800, [],
                       ca2_cert, @rsa1024, sha1_or_approved)
    revoke_info = []
    crl2_2 = issue_crl(revoke_info, 2, now-100, now-1, [],
                       ca2_cert, @rsa1024, sha1_or_approved)

    assert_equal(true, ca1_cert.verify(ca1_cert.public_key))   # self signed
    assert_equal(true, ca2_cert.verify(ca1_cert.public_key))   # issued by ca1
    assert_equal(true, ee1_cert.verify(ca2_cert.public_key))   # issued by ca2
    assert_equal(true, ee2_cert.verify(ca2_cert.public_key))   # issued by ca2
    assert_equal(true, ee3_cert.verify(ca2_cert.public_key))   # issued by ca2
    assert_equal(true, crl1.verify(ca1_cert.public_key))       # issued by ca1
    assert_equal(true, crl1_2.verify(ca1_cert.public_key))     # issued by ca1
    assert_equal(true, crl2.verify(ca2_cert.public_key))       # issued by ca2
    assert_equal(true, crl2_2.verify(ca2_cert.public_key))     # issued by ca2

    store = OpenSSL::X509::Store.new
    assert_equal(false, store.verify(ca1_cert))
    assert_not_equal(OpenSSL::X509::V_OK, store.error)

    assert_equal(false, store.verify(ca2_cert))
    assert_not_equal(OpenSSL::X509::V_OK, store.error)

    store.add_cert(ca1_cert)
    verify = store.verify(ca1_cert)
    # TODO only works when cert_self_signed is reduced to do a EXFLAG_SI instead of EXFLAG_SS
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }
    assert_equal(true, verify)

    verify = store.verify(ca2_cert)
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA2", "/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }
    assert_equal(true, verify)

    assert_equal(OpenSSL::X509::V_OK, store.error)
    assert_equal("ok", store.error_string)
    chain = store.chain
    assert_equal(2, chain.size)
    assert_equal(@ca2.to_der, chain[0].subject.to_der)
    assert_equal(@ca1.to_der, chain[1].subject.to_der)

    store.purpose = OpenSSL::X509::PURPOSE_SSL_CLIENT
    assert_equal(false, store.verify(ca2_cert))
    assert_not_equal(OpenSSL::X509::V_OK, store.error)

    store.purpose = OpenSSL::X509::PURPOSE_CRL_SIGN
    assert_equal(true, store.verify(ca2_cert))
    assert_equal(OpenSSL::X509::V_OK, store.error)

    store.add_cert(ca2_cert)
    store.purpose = OpenSSL::X509::PURPOSE_SSL_CLIENT
    assert_equal(true, store.verify(ee1_cert))
    assert_equal(true, store.verify(ee2_cert))
    assert_equal(OpenSSL::X509::V_OK, store.error)
    assert_equal("ok", store.error_string)
    chain = store.chain
    assert_equal(3, chain.size)
    assert_equal(@ee2.to_der, chain[0].subject.to_der)
    assert_equal(@ca2.to_der, chain[1].subject.to_der)
    assert_equal(@ca1.to_der, chain[2].subject.to_der)
    assert_equal(false, store.verify(ee3_cert))
    assert_equal(OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error)
    assert_match(/expire/i, store.error_string)
    assert_equal(false, store.verify(ee4_cert))
    assert_equal(OpenSSL::X509::V_ERR_CERT_NOT_YET_VALID, store.error)
    assert_match(/not yet valid/i, store.error_string)

    store = OpenSSL::X509::Store.new
    store.add_cert(ca1_cert)
    store.add_cert(ca2_cert)
    store.time = now + 1500
    assert_equal(true, store.verify(ca1_cert))
    assert_equal(true, store.verify(ca2_cert))
    assert_equal(true, store.verify(ee4_cert))
    store.time = now + 1900
    assert_equal(true, store.verify(ca1_cert))
    assert_equal(false, store.verify(ca2_cert))
    assert_equal(OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error)
    assert_equal(false, store.verify(ee4_cert))
    assert_equal(OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error)
    store.time = now + 4000
    assert_equal(false, store.verify(ee1_cert))
    assert_equal(OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error)
    assert_equal(false, store.verify(ee4_cert))
    assert_equal(OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error)

    # the underlying X509 struct caches the result of the last verification for signature and not-before
    # so the following code rebuilds new objects to avoid site effect
    store.time = Time.now - 4000
    assert_equal(false, store.verify(OpenSSL::X509::Certificate.new(ca2_cert)))
    assert_equal(OpenSSL::X509::V_ERR_CERT_NOT_YET_VALID, store.error)
    assert_equal(false, store.verify(OpenSSL::X509::Certificate.new(ee1_cert)))
    assert_equal(OpenSSL::X509::V_ERR_CERT_NOT_YET_VALID, store.error)

    return unless defined?(OpenSSL::X509::V_FLAG_CRL_CHECK)

    store = OpenSSL::X509::Store.new
    store.purpose = OpenSSL::X509::PURPOSE_ANY
    store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK
    store.add_cert(ca1_cert)
    store.add_crl(crl1)   # revoke no cert
    store.add_crl(crl2)   # revoke ee2_cert
    assert_equal(true,  store.verify(ca1_cert))
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }

    assert_equal(true,  store.verify(ca2_cert))
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA2", "/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }

    verify = store.verify(ee1_cert, [ca2_cert])
    assert_equal(true,  verify)

    verify = store.verify(ee2_cert, [ca2_cert])
    assert_equal(false, verify)

    store = OpenSSL::X509::Store.new
    store.purpose = OpenSSL::X509::PURPOSE_ANY
    store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK
    store.add_cert(ca1_cert)
    store.add_crl(crl1_2) # revoke ca2_cert
    store.add_crl(crl2)   # revoke ee2_cert

    verify = store.verify(ca1_cert)
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }
    assert_equal(true, verify)

    verify = store.verify(ca2_cert)
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA2", "/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }
    assert_equal(false, verify)

    assert_equal(true,  store.verify(ee1_cert, [ca2_cert]),
                 "This test is expected to be success with OpenSSL 0.9.7c or later.")
    assert_equal(false, store.verify(ee2_cert, [ca2_cert]))

    store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL

    verify = store.verify(ca1_cert)
    assert_equal ["/DC=org/DC=ruby-lang/CN=CA1"],
                 store.chain.map { |cert| cert.subject.to_s }
    puts "verify(ca1_cert) #{verify} - store.error: #{store.error} (#{store.error_string})"
    assert_equal(true,  verify)

    assert_equal(false, store.verify(ca2_cert))
    assert_equal(false, store.verify(ee1_cert, [ca2_cert]))
    assert_equal(false, store.verify(ee2_cert, [ca2_cert]))

    store = OpenSSL::X509::Store.new
    store.purpose = OpenSSL::X509::PURPOSE_ANY
    store.flags =
        OpenSSL::X509::V_FLAG_CRL_CHECK|OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
    store.add_cert(ca1_cert)
    store.add_cert(ca2_cert)
    store.add_crl(crl1)
    store.add_crl(crl2_2) # issued by ca2 but expired.
    assert_equal(true, store.verify(ca1_cert))
    assert_equal(true, store.verify(ca2_cert))
    assert_equal(false, store.verify(ee1_cert))
    assert_equal(OpenSSL::X509::V_ERR_CRL_HAS_EXPIRED, store.error)
    assert_equal(false, store.verify(ee2_cert))
  end

  def test_verify_same_subject_ca
    omit_on_fips 'DSA key generation is not FIPS-approved'

    puts JOpenSSL::VERSION if defined? JRUBY_VERSION

    @rsa1 = OpenSSL::PKey::RSA.generate 2048
    @rsa2 = OpenSSL::PKey::RSA.generate 2048
    @rsa3 = OpenSSL::PKey::RSA.generate 2048
    @rsa4 = OpenSSL::PKey::RSA.generate 2048
    @dsa1 = OpenSSL::PKey::DSA.generate 512
    @dsa2 = OpenSSL::PKey::DSA.generate 512
    @ca_same = OpenSSL::X509::Name.parse("/DC=com/DC=same-name/CN=CA")
    @ca_other = OpenSSL::X509::Name.parse("/DC=co/DC=anotherOne/CN=CA")
    @ee1 = OpenSSL::X509::Name.parse("/DC=com/DC=example/CN=ServerCert1")
    @ee2 = OpenSSL::X509::Name.parse("/DC=com/DC=example/CN=ServerCert2")
    @ee4 = OpenSSL::X509::Name.parse("/DC=com/DC=example/CN=ServerCert4")

    now = Time.at(Time.now.to_i)
    not_before = now - 365 * 24 * 60 * 60
    not_after = now + 24 * 60 * 60
    ca_exts1 = [
        ["basicConstraints","CA:TRUE",true],
        ["keyUsage","cRLSign,keyCertSign",true],
    ]
    ca_exts2 = [
        ["basicConstraints","CA:TRUE",true],
        ["keyUsage","keyCertSign",true],
    ]
    ee_exts = [
        ["keyUsage","keyEncipherment,digitalSignature",true],
    ]
    ca1_cert = issue_cert(@ca_same, @rsa1, 1, ca_exts1, nil, nil, not_before: not_before, not_after: now - 60 * 60)
    ca2_cert = issue_cert(@ca_same, @rsa2, 2, ca_exts2, nil, nil, not_before: not_before, not_after: not_after)
    ca3_cert = issue_cert(@ca_other, @rsa3, 3, ca_exts1, nil, nil, not_before: not_before, not_after: not_after)
    ca4_cert = issue_cert(@ca_same, @rsa4, 4, ca_exts1, nil, nil, not_before: not_before, not_after: not_after)
    ee1_cert = issue_cert(@ee1, @dsa1, 10, ee_exts, ca1_cert, @rsa1, not_before: now - 60, not_after: now + 1800)
    ee2_cert = issue_cert(@ee2, @dsa2, 20, ee_exts, ca2_cert, @rsa2, not_before: now - 60, not_after: now + 1800)
    ee4_cert = issue_cert(@ee4, @dsa2, 20, ee_exts, ca4_cert, @rsa4, not_before: now - 60, not_after: now + 1800)

    cert_store = OpenSSL::X509::Store.new
    cert_store.add_cert ca1_cert
    cert_store.add_cert ca2_cert
    cert_store.add_cert ca3_cert
    cert_store.add_cert ca4_cert

    ok = cert_store.verify(ee1_cert)
    assert_equal 'certificate signature failure', cert_store.error_string
    assert_equal false, ok

    ok = cert_store.verify(ee2_cert)
    assert_equal 'ok', cert_store.error_string
    assert_equal true, ok

    ok = cert_store.verify(ee4_cert)
    assert_equal 'certificate signature failure', cert_store.error_string
    assert_equal false, ok # OpenSSL 1.1.1 behavior
  end

  # NOTE: values match OpenSSL 1.1.1 (some were renumbered in 3.x).
  def test_v_err_constants
    x = OpenSSL::X509
    assert_equal 0,  x::V_OK
    assert_equal 1,  x::V_ERR_UNSPECIFIED
    assert_equal 18, x::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
    assert_equal 19, x::V_ERR_SELF_SIGNED_CERT_IN_CHAIN
    assert_equal 20, x::V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
    assert_equal 33, x::V_ERR_UNABLE_TO_GET_CRL_ISSUER
    assert_equal 34, x::V_ERR_UNHANDLED_CRITICAL_EXTENSION
    assert_equal 35, x::V_ERR_KEYUSAGE_NO_CRL_SIGN
    assert_equal 37, x::V_ERR_INVALID_NON_CA
    assert_equal 40, x::V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED
    assert_equal 43, x::V_ERR_NO_EXPLICIT_POLICY
    assert_equal 50, x::V_ERR_APPLICATION_VERIFICATION
    assert_equal 55, x::V_ERR_PATH_LOOP
    assert_equal 62, x::V_ERR_HOSTNAME_MISMATCH
    assert_equal 63, x::V_ERR_EMAIL_MISMATCH
    assert_equal 64, x::V_ERR_IP_ADDRESS_MISMATCH
    assert_equal 69, x::V_ERR_INVALID_CALL
    assert_equal 70, x::V_ERR_STORE_LOOKUP
  end

  def test_v_flag_constants
    x = OpenSSL::X509
    assert_equal 0x4,      x::V_FLAG_CRL_CHECK
    assert_equal 0x8,      x::V_FLAG_CRL_CHECK_ALL
    assert_equal 0x2,      x::V_FLAG_USE_CHECK_TIME
    assert_equal 0x10,     x::V_FLAG_IGNORE_CRITICAL
    assert_equal 0x20,     x::V_FLAG_X509_STRICT
    assert_equal 0x40,     x::V_FLAG_ALLOW_PROXY_CERTS
    assert_equal 0x80,     x::V_FLAG_POLICY_CHECK
    assert_equal 0x100,    x::V_FLAG_EXPLICIT_POLICY
    assert_equal 0x200,    x::V_FLAG_INHIBIT_ANY
    assert_equal 0x400,    x::V_FLAG_INHIBIT_MAP
    assert_equal 0x800,    x::V_FLAG_NOTIFY_POLICY
    assert_equal 0x4000,   x::V_FLAG_CHECK_SS_SIGNATURE
    assert_equal 0x8000,   x::V_FLAG_TRUSTED_FIRST
    assert_equal 0x80000,  x::V_FLAG_PARTIAL_CHAIN
    assert_equal 0x100000, x::V_FLAG_NO_ALT_CHAINS
    assert_equal 0x200000, x::V_FLAG_NO_CHECK_TIME
  end

  def test_v_flag_no_check_time
    now = Time.now
    ca_exts = [["basicConstraints","CA:TRUE",true],["keyUsage","cRLSign,keyCertSign",true]]
    ee_exts = [["keyUsage","keyEncipherment,digitalSignature",true]]
    ca_key = OpenSSL::PKey::RSA.new(2048)
    ca_cert = issue_cert(OpenSSL::X509::Name.parse("/CN=CA"), ca_key, 1, ca_exts, nil, nil,
                         not_before: now, not_after: now + 3600)
    ee_key = OpenSSL::PKey::RSA.new(2048)
    # expired cert
    expired = issue_cert(OpenSSL::X509::Name.parse("/CN=Expired"), ee_key, 2, ee_exts, ca_cert, ca_key,
                         not_before: now - 7200, not_after: now - 3600)

    # Without NO_CHECK_TIME: expired cert fails
    store = OpenSSL::X509::Store.new
    store.add_cert(ca_cert)
    assert_equal false, store.verify(expired)
    assert_equal OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error

    # With NO_CHECK_TIME: expired cert passes
    store2 = OpenSSL::X509::Store.new
    store2.add_cert(ca_cert)
    store2.flags = OpenSSL::X509::V_FLAG_NO_CHECK_TIME
    assert_equal true, store2.verify(expired)
    assert_equal OpenSSL::X509::V_OK, store2.error
  end

  def test_v_flag_partial_chain
    now = Time.now
    ca_exts = [["basicConstraints","CA:TRUE",true],["keyUsage","cRLSign,keyCertSign",true]]
    ee_exts = [["keyUsage","keyEncipherment,digitalSignature",true]]
    root_key = OpenSSL::PKey::RSA.new(2048)
    root_cert = issue_cert(OpenSSL::X509::Name.parse("/CN=Root"), root_key, 1, ca_exts, nil, nil,
                           not_before: now, not_after: now + 3600)
    inter_key = OpenSSL::PKey::RSA.new(2048)
    inter_cert = issue_cert(OpenSSL::X509::Name.parse("/CN=Intermediate"), inter_key, 2, ca_exts,
                            root_cert, root_key, not_before: now, not_after: now + 3600)
    ee_key = OpenSSL::PKey::RSA.new(2048)
    ee_cert = issue_cert(OpenSSL::X509::Name.parse("/CN=Leaf"), ee_key, 3, ee_exts,
                         inter_cert, inter_key, not_before: now, not_after: now + 1800)

    # Without PARTIAL_CHAIN: only intermediate in store, leaf verification fails
    store = OpenSSL::X509::Store.new
    store.add_cert(inter_cert)
    assert_equal false, store.verify(ee_cert)

    # With PARTIAL_CHAIN: intermediate is accepted as trust anchor
    store2 = OpenSSL::X509::Store.new
    store2.add_cert(inter_cert)
    store2.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
    assert_equal true, store2.verify(ee_cert)
    assert_equal OpenSSL::X509::V_OK, store2.error

    # PARTIAL_CHAIN still verifies the leaf signature against the trusted anchor:
    # a leaf claiming the same issuer but signed by the wrong key must fail
    forged_leaf = issue_cert(OpenSSL::X509::Name.parse("/CN=Leaf"), ee_key, 4, ee_exts,
                             inter_cert, root_key, not_before: now, not_after: now + 1800)
    store3 = OpenSSL::X509::Store.new
    store3.add_cert(inter_cert)
    store3.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
    assert_equal false, store3.verify(forged_leaf)
    assert_equal OpenSSL::X509::V_ERR_CERT_SIGNATURE_FAILURE, store3.error
  end

  def test_verify_path_length_constraint
    now = Time.now
    ca0_exts = [["basicConstraints","CA:TRUE,pathlen:0",true],["keyUsage","cRLSign,keyCertSign",true]]
    ca1_exts = [["basicConstraints","CA:TRUE,pathlen:1",true],["keyUsage","cRLSign,keyCertSign",true]]
    ca_exts  = [["basicConstraints","CA:TRUE",true],["keyUsage","cRLSign,keyCertSign",true]]
    ee_exts  = [["basicConstraints","CA:FALSE",true],["keyUsage","keyEncipherment,digitalSignature",true]]

    inter_key = OpenSSL::PKey::RSA.new(2048)
    ee_key = OpenSSL::PKey::RSA.new(2048)

    # self-signed root with pathlen:0 must not allow an intermediate CA below it
    root0_key = OpenSSL::PKey::RSA.new(2048)
    root0 = issue_cert(OpenSSL::X509::Name.parse("/CN=Root0"), root0_key, 1, ca0_exts, nil, nil,
                       not_before: now, not_after: now + 3600)
    inter0 = issue_cert(OpenSSL::X509::Name.parse("/CN=Inter0"), inter_key, 2, ca_exts,
                        root0, root0_key, not_before: now, not_after: now + 3600)
    leaf0 = issue_cert(OpenSSL::X509::Name.parse("/CN=Leaf0"), ee_key, 3, ee_exts,
                       inter0, inter_key, not_before: now, not_after: now + 1800)
    store = OpenSSL::X509::Store.new
    store.add_cert(root0)
    assert_equal false, store.verify(leaf0, [inter0])
    assert_equal OpenSSL::X509::V_ERR_PATH_LENGTH_EXCEEDED, store.error

    # same root issuing an end-entity cert directly is within pathlen:0
    leaf0_direct = issue_cert(OpenSSL::X509::Name.parse("/CN=Leaf0Direct"), ee_key, 4, ee_exts,
                              root0, root0_key, not_before: now, not_after: now + 1800)
    store_d = OpenSSL::X509::Store.new
    store_d.add_cert(root0)
    assert_equal true, store_d.verify(leaf0_direct)
    assert_equal OpenSSL::X509::V_OK, store_d.error

    # pathlen:1 allows a single intermediate CA
    root1_key = OpenSSL::PKey::RSA.new(2048)
    root1 = issue_cert(OpenSSL::X509::Name.parse("/CN=Root1"), root1_key, 1, ca1_exts, nil, nil,
                       not_before: now, not_after: now + 3600)
    inter1 = issue_cert(OpenSSL::X509::Name.parse("/CN=Inter1"), inter_key, 2, ca_exts,
                        root1, root1_key, not_before: now, not_after: now + 3600)
    leaf1 = issue_cert(OpenSSL::X509::Name.parse("/CN=Leaf1"), ee_key, 3, ee_exts,
                       inter1, inter_key, not_before: now, not_after: now + 1800)
    store1 = OpenSSL::X509::Store.new
    store1.add_cert(root1)
    assert_equal true, store1.verify(leaf1, [inter1])
    assert_equal OpenSSL::X509::V_OK, store1.error

    # a non-self-issued intermediate carrying pathlen:0 is also enforced
    rootD_key = OpenSSL::PKey::RSA.new(2048)
    interA_key = OpenSSL::PKey::RSA.new(2048)
    interB_key = OpenSSL::PKey::RSA.new(2048)
    rootD = issue_cert(OpenSSL::X509::Name.parse("/CN=RootD"), rootD_key, 1, ca_exts, nil, nil,
                       not_before: now, not_after: now + 3600)
    interA = issue_cert(OpenSSL::X509::Name.parse("/CN=InterA"), interA_key, 2, ca0_exts,
                        rootD, rootD_key, not_before: now, not_after: now + 3600)
    interB = issue_cert(OpenSSL::X509::Name.parse("/CN=InterB"), interB_key, 3, ca_exts,
                        interA, interA_key, not_before: now, not_after: now + 3600)
    leafD = issue_cert(OpenSSL::X509::Name.parse("/CN=LeafD"), ee_key, 4, ee_exts,
                       interB, interB_key, not_before: now, not_after: now + 1800)
    storeD = OpenSSL::X509::Store.new
    storeD.add_cert(rootD)
    assert_equal false, storeD.verify(leafD, [interA, interB])
    assert_equal OpenSSL::X509::V_ERR_PATH_LENGTH_EXCEEDED, storeD.error
  end

  def test_cert_crl_unhandled_critical_extension
    now = Time.now
    ca_exts = [["basicConstraints","CA:TRUE",true],["keyUsage","cRLSign,keyCertSign",true]]
    ee_exts = [["basicConstraints","CA:FALSE",true],["keyUsage","keyEncipherment,digitalSignature",true]]
    root_key = OpenSSL::PKey::RSA.new(2048)
    root = issue_cert(OpenSSL::X509::Name.parse("/CN=CRLRoot"), root_key, 1, ca_exts, nil, nil,
                      not_before: now, not_after: now + 3600)
    leaf_key = OpenSSL::PKey::RSA.new(2048)
    leaf = issue_cert(OpenSSL::X509::Name.parse("/CN=CRLLeaf"), leaf_key, 42, ee_exts,
                      root, root_key, not_before: now, not_after: now + 1800)

    verify = lambda do |crl|
      # DER round-trip so the critical-extension flags are computed as for a wire CRL
      crl = OpenSSL::X509::CRL.new(crl.to_der)
      store = OpenSSL::X509::Store.new
      store.add_cert(root); store.add_crl(crl)
      store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK
      [store.verify(leaf), store.error]
    end

    build_crl = lambda do |revoke: false, reason: nil, crit_oid: nil, crit_val: nil|
      crl = OpenSSL::X509::CRL.new
      crl.version = 1; crl.issuer = root.subject
      crl.last_update = now - 60; crl.next_update = now + 3600
      if revoke
        rev = OpenSSL::X509::Revoked.new; rev.serial = leaf.serial; rev.time = now - 60
        rev.add_extension(OpenSSL::X509::Extension.new("CRLReason", OpenSSL::ASN1::Enumerated(reason))) if reason
        crl.add_revoked(rev)
      end
      crl.add_extension(OpenSSL::X509::Extension.new(crit_oid, crit_val, true)) if crit_oid
      crl.sign(root_key, OpenSSL::Digest.new('SHA256'))
      crl
    end

    idp = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Boolean.new(true, 1, :IMPLICIT, :CONTEXT_SPECIFIC)]).to_der
    arbitrary = OpenSSL::ASN1::OctetString.new("x").to_der

    # a critical issuingDistributionPoint is handled - the CRL is usable
    v, e = verify.call(build_crl.call(crit_oid: "2.5.29.28", crit_val: idp))
    assert_equal true, v
    assert_equal OpenSSL::X509::V_OK, e

    # a truly unhandled critical extension makes the CRL unusable
    v, e = verify.call(build_crl.call(crit_oid: "1.2.3.4.5.6.7.8", crit_val: arbitrary))
    assert_equal false, v
    assert_equal OpenSSL::X509::V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION, e

    # unhandled critical extension is reported before revocation
    v, e = verify.call(build_crl.call(revoke: true, crit_oid: "1.2.3.4.5.6.7.8", crit_val: arbitrary))
    assert_equal false, v
    assert_equal OpenSSL::X509::V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION, e

    # an entry with reason removeFromCRL means the certificate is not revoked
    v, e = verify.call(build_crl.call(revoke: true, reason: 8))
    assert_equal true, v
    assert_equal OpenSSL::X509::V_OK, e

    # sanity: a plain revocation still fails
    v, e = verify.call(build_crl.call(revoke: true))
    assert_equal false, v
    assert_equal OpenSSL::X509::V_ERR_CERT_REVOKED, e
  end

  def test_crl_issuing_distribution_point_scope
    now = Time.now
    ca_exts = [["basicConstraints","CA:TRUE",true],["keyUsage","keyCertSign,cRLSign",true]]
    ee_exts = [["basicConstraints","CA:FALSE",true],["keyUsage","digitalSignature",true]]
    root_key = OpenSSL::PKey::RSA.new(2048)
    root = issue_cert(OpenSSL::X509::Name.parse("/CN=CRLScopeRoot"), root_key, 1, ca_exts, nil, nil,
                      not_before: now, not_after: now + 3600)
    leaf_key = OpenSSL::PKey::RSA.new(2048)
    leaf = issue_cert(OpenSSL::X509::Name.parse("/CN=CRLScopeLeaf"), leaf_key, 42, ee_exts,
                      root, root_key, not_before: now, not_after: now + 1800)

    verify = lambda do |crl|
      crl = OpenSSL::X509::CRL.new(crl.to_der) # round-trip so IDP is parsed as for a wire CRL
      store = OpenSSL::X509::Store.new
      store.add_cert(root); store.add_crl(crl)
      store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK
      [store.verify(leaf), store.error]
    end

    build_crl = lambda do |revoke: false, idp_der: nil|
      crl = OpenSSL::X509::CRL.new
      crl.version = 1; crl.issuer = root.subject
      crl.last_update = now - 60; crl.next_update = now + 3600
      if revoke
        rev = OpenSSL::X509::Revoked.new; rev.serial = leaf.serial; rev.time = now - 60
        crl.add_revoked(rev)
      end
      crl.add_extension(OpenSSL::X509::Extension.new("2.5.29.28", idp_der, true)) if idp_der
      crl.sign(root_key, OpenSSL::Digest.new('SHA256'))
      crl
    end

    idp_user = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Boolean.new(true, 1, :IMPLICIT, :CONTEXT_SPECIFIC)]).to_der
    idp_ca   = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Boolean.new(true, 2, :IMPLICIT, :CONTEXT_SPECIFIC)]).to_der
    idp_ind  = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Boolean.new(true, 4, :IMPLICIT, :CONTEXT_SPECIFIC)]).to_der

    # in scope (onlyContainsUserCerts) - revocation applies to the EE
    v, e = verify.call(build_crl.call(revoke: true, idp_der: idp_user))
    assert_equal false, v
    assert_equal OpenSSL::X509::V_ERR_CERT_REVOKED, e

    # out of scope (onlyContainsCACerts) for an EE cert - CRL must not be used
    v, e = verify.call(build_crl.call(idp_der: idp_ca))
    assert_equal false, v
    assert_equal OpenSSL::X509::V_ERR_DIFFERENT_CRL_SCOPE, e

    # out of scope even when the EE serial appears in the CRL: scope wins over revocation
    v, e = verify.call(build_crl.call(revoke: true, idp_der: idp_ca))
    assert_equal false, v
    assert_equal OpenSSL::X509::V_ERR_DIFFERENT_CRL_SCOPE, e

    # indirect CRL is unusable without extended CRL support
    v, e = verify.call(build_crl.call(idp_der: idp_ind))
    assert_equal false, v
    assert_equal OpenSSL::X509::V_ERR_UNABLE_TO_GET_CRL, e
  end

  # OpenSSL NAME_CONSTRAINTS_check_CN: dNSName constraints also apply to the EE subject CN
  # when the cert has no SAN dNSName. BC's validator only checks the SAN, so JRuby missed this.
  def test_name_constraint_dns_applies_to_subject_cn
    now = Time.now
    ca_exts = [["basicConstraints","CA:TRUE",true],["keyUsage","keyCertSign,cRLSign",true]]
    root_key = OpenSSL::PKey::RSA.new(2048)
    leaf_key = OpenSSL::PKey::RSA.new(2048)

    root = lambda do |nc|
      issue_cert(OpenSSL::X509::Name.parse("/CN=NCRoot"), root_key, 1,
                 ca_exts + [["nameConstraints", nc, true]], nil, nil,
                 not_before: now - 60, not_after: now + 3600)
    end
    leaf = lambda do |issuer, cn, serial, extra = []|
      issue_cert(OpenSSL::X509::Name.parse("/CN=#{cn}"), leaf_key, serial,
                 [["basicConstraints","CA:FALSE",true]] + extra, issuer, root_key,
                 not_before: now - 60, not_after: now + 1800)
    end
    verify = lambda do |issuer, leaf_cert|
      store = OpenSSL::X509::Store.new; store.add_cert(issuer)
      [store.verify(leaf_cert), store.error]
    end

    excl = root.call("excluded;DNS:example.com")
    # CN in the excluded DNS zone, no SAN -> rejected via the subject CN
    assert_equal [false, OpenSSL::X509::V_ERR_EXCLUDED_VIOLATION],
                 verify.call(excl, leaf.call(excl, "www.example.com", 10))
    # CN outside the zone -> ok
    assert_equal [true, OpenSSL::X509::V_OK], verify.call(excl, leaf.call(excl, "www.other.org", 11))
    # CN in the excluded zone BUT a compliant SAN dNSName present -> CN not checked -> ok
    assert_equal [true, OpenSSL::X509::V_OK],
                 verify.call(excl, leaf.call(excl, "www.example.com", 12, [["subjectAltName","DNS:host.other.org",false]]))
    # CN that is not a host name -> not treated as a DNS-ID -> ok
    assert_equal [true, OpenSSL::X509::V_OK], verify.call(excl, leaf.call(excl, "Not A Hostname", 13))

    perm = root.call("permitted;DNS:example.com")
    # CN outside the permitted zone, no SAN -> permitted violation
    assert_equal [false, OpenSSL::X509::V_ERR_PERMITTED_VIOLATION],
                 verify.call(perm, leaf.call(perm, "www.other.org", 14))
  end

  private

  def build_cert_with_san(name, serial, san_dns, issuer_cert, issuer_key)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2; cert.serial = serial
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
    cert.issuer = issuer_cert.subject
    cert.not_before = Time.now - 3600; cert.not_after = Time.now + 3600
    cert.public_key = key.public_key
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert; ef.issuer_certificate = issuer_cert
    cert.add_extension(ef.create_extension("subjectAltName", "DNS:#{san_dns}"))
    cert.sign(issuer_key, "SHA256")
    cert
  end

  public

  # jruby/jruby#3502: nameConstraints verification
  def test_name_constraints_permitted_dns
    now = Time.now
    ca_key = OpenSSL::PKey::RSA.new(2048)
    ca_cert = issue_cert(OpenSSL::X509::Name.parse("/CN=CA"), ca_key, 1,
      [["basicConstraints","CA:TRUE",true],["keyUsage","cRLSign,keyCertSign",true],
       ["nameConstraints","permitted;DNS:.example.com",true]],
      nil, nil, not_before: now, not_after: now + 3600)

    good = build_cert_with_san("good", 10, "good.example.com", ca_cert, ca_key)
    bad = build_cert_with_san("bad", 11, "evil.attacker.com", ca_cert, ca_key)

    store = OpenSSL::X509::Store.new; store.add_cert(ca_cert)
    assert_equal true, store.verify(good), "cert within permitted DNS subtree should verify"
    assert_equal OpenSSL::X509::V_OK, store.error

    assert_equal false, store.verify(bad), "cert outside permitted DNS subtree should fail"
    assert_equal OpenSSL::X509::V_ERR_PERMITTED_VIOLATION, store.error
  end

  def test_name_constraints_excluded_dns
    now = Time.now
    ca_key = OpenSSL::PKey::RSA.new(2048)
    ca_cert = issue_cert(OpenSSL::X509::Name.parse("/CN=CA"), ca_key, 1,
      [["basicConstraints","CA:TRUE",true],["keyUsage","cRLSign,keyCertSign",true],
       ["nameConstraints","excluded;DNS:.evil.com",true]],
      nil, nil, not_before: now, not_after: now + 3600)

    good = build_cert_with_san("good", 10, "good.example.com", ca_cert, ca_key)
    bad = build_cert_with_san("bad", 11, "bad.evil.com", ca_cert, ca_key)

    store = OpenSSL::X509::Store.new; store.add_cert(ca_cert)
    assert_equal true, store.verify(good), "cert not in excluded subtree should verify"

    assert_equal false, store.verify(bad), "cert in excluded DNS subtree should fail"
    assert_equal OpenSSL::X509::V_ERR_EXCLUDED_VIOLATION, store.error
  end

  def test_name_constraints_no_constraints_passes
    now = Time.now
    ca_key = OpenSSL::PKey::RSA.new(2048)
    ca_cert = issue_cert(OpenSSL::X509::Name.parse("/CN=CA"), ca_key, 1,
      [["basicConstraints","CA:TRUE",true],["keyUsage","cRLSign,keyCertSign",true]],
      nil, nil, not_before: now, not_after: now + 3600)
    # No nameConstraints at all
    leaf = build_cert_with_san("leaf", 10, "anything.example.com", ca_cert, ca_key)

    store = OpenSSL::X509::Store.new; store.add_cert(ca_cert)
    assert_equal true, store.verify(leaf), "cert without name constraints should verify"
  end

  def test_name_constraints_permitted_and_excluded_combined
    now = Time.now
    ca_key = OpenSSL::PKey::RSA.new(2048)
    ca_cert = issue_cert(OpenSSL::X509::Name.parse("/CN=CA"), ca_key, 1,
      [["basicConstraints","CA:TRUE",true],["keyUsage","cRLSign,keyCertSign",true],
       ["nameConstraints","permitted;DNS:.example.com,excluded;DNS:.bad.example.com",true]],
      nil, nil, not_before: now, not_after: now + 3600)

    good = build_cert_with_san("good", 10, "good.example.com", ca_cert, ca_key)
    bad = build_cert_with_san("bad", 11, "test.bad.example.com", ca_cert, ca_key)
    outside = build_cert_with_san("outside", 12, "other.org", ca_cert, ca_key)

    store = OpenSSL::X509::Store.new; store.add_cert(ca_cert)
    assert_equal true, store.verify(good)
    assert_equal false, store.verify(bad)
    assert_equal false, store.verify(outside)
  end

  def test_verify_at_exact_not_before_is_valid
    key = Fixtures.pkey("rsa2048")
    now = Time.now
    cert = issue_cert(OpenSSL::X509::Name.parse("/CN=boundary"), key, 1,
                      [["basicConstraints", "CA:TRUE", true]], nil, nil,
                      not_before: now, not_after: now + 3600)
    store = OpenSSL::X509::Store.new
    store.add_cert(cert)
    store.time = cert.not_before
    assert_equal true, store.verify(cert), store.error_string
  end

  def test_verify_at_exact_not_after_is_expired
    key = Fixtures.pkey("rsa2048")
    now = Time.now
    cert = issue_cert(OpenSSL::X509::Name.parse("/CN=boundary"), key, 1,
                      [["basicConstraints", "CA:TRUE", true]], nil, nil,
                      not_before: now - 3600, not_after: now)
    store = OpenSSL::X509::Store.new
    store.add_cert(cert)
    store.time = cert.not_after
    assert_equal false, store.verify(cert)
    assert_equal OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED, store.error
  end

end

# GH#370: X509Store must try every CA matching the issuer DN
# (e.g. CA rotation where old and new chains share a subject)
class TestX509StoreMultiCASameDN < TestCase

  def setup
    @old_root_cert, @old_root_key = make_root_ca('Test-Root', serial: 1)
    @old_inter_cert, @old_inter_key = make_intermediate_ca('Test-Intermediate', @old_root_cert, @old_root_key, serial: 100)
    @new_root_cert, @new_root_key = make_root_ca('Test-Root', serial: 2)
    @new_inter_cert, @new_inter_key = make_intermediate_ca('Test-Intermediate', @new_root_cert, @new_root_key, serial: 200)
    @server_cert, @server_key = make_leaf('localhost', @new_inter_cert, @new_inter_key, serial: 1000)
  end

  private

  def make_root_ca(cn, serial:)
    key = OpenSSL::PKey::RSA.new(2048)
    name = OpenSSL::X509::Name.new([['CN', cn], ['O', 'TestOrg'], ['C', 'US']])

    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = name
    cert.issuer = name
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86400 * 365

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.add_extension(ef.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    cert.add_extension(ef.create_extension('subjectKeyIdentifier', 'hash'))
    cert.add_extension(ef.create_extension('authorityKeyIdentifier', 'keyid:always'))

    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    [cert, key]
  end

  def make_intermediate_ca(cn, parent_cert, parent_key, serial:)
    key = OpenSSL::PKey::RSA.new(2048)
    name = OpenSSL::X509::Name.new([['CN', cn], ['O', 'TestOrg'], ['C', 'US']])

    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = name
    cert.issuer = parent_cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86400 * 365

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = parent_cert
    cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.add_extension(ef.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    cert.add_extension(ef.create_extension('subjectKeyIdentifier', 'hash'))
    cert.add_extension(ef.create_extension('authorityKeyIdentifier', 'keyid:always'))

    cert.sign(parent_key, OpenSSL::Digest.new('SHA256'))
    [cert, key]
  end

  def make_leaf(cn, parent_cert, parent_key, serial:)
    key = OpenSSL::PKey::RSA.new(2048)
    name = OpenSSL::X509::Name.new([['CN', cn], ['O', 'TestOrg'], ['C', 'US']])

    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = name
    cert.issuer = parent_cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86400 * 365

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = parent_cert
    cert.add_extension(ef.create_extension('basicConstraints', 'CA:FALSE'))
    cert.add_extension(ef.create_extension('keyUsage', 'digitalSignature,keyEncipherment'))
    cert.add_extension(ef.create_extension('extendedKeyUsage', 'serverAuth'))
    cert.add_extension(ef.create_extension('subjectKeyIdentifier', 'hash'))
    cert.add_extension(ef.create_extension('authorityKeyIdentifier', 'keyid:always'))
    cert.add_extension(ef.create_extension('subjectAltName', "DNS:localhost,DNS:#{cn}"))

    cert.sign(parent_key, OpenSSL::Digest.new('SHA256'))
    [cert, key]
  end

  public

  def test_verify_with_old_chain_first
    store = OpenSSL::X509::Store.new
    store.add_cert(@old_inter_cert)
    store.add_cert(@old_root_cert)
    store.add_cert(@new_inter_cert)
    store.add_cert(@new_root_cert)

    assert store.verify(@server_cert), "expected verify to pass, got: #{store.error_string} (error #{store.error})"
  end

  def test_verify_with_new_chain_first
    store = OpenSSL::X509::Store.new
    store.add_cert(@new_inter_cert)
    store.add_cert(@new_root_cert)
    store.add_cert(@old_inter_cert)
    store.add_cert(@old_root_cert)

    assert store.verify(@server_cert), "expected verify to pass, got: #{store.error_string} (error #{store.error})"
  end

end
