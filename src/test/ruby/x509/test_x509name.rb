# encoding: UTF-8
require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Name < TestCase

  def test_to_a_to_s_and_to_utf8
    dn = [
      ["DC", "org"],
      ["DC", "jruby", 22],
      ["CN", "Karol Bucek"],
      ["UID", "kares"],
      ["emailAddress", "jruby@kares-x.org"],
      ["serialNumber", "1234567890"],
      ["street", "Edelenska"],
      ['2.5.4.44', 'X'],
      ['2.5.4.65', 'B;BS'],
      ['postalCode', '048+01', 22],
      ['postalAddress', "Edelénska 2022/11, RV"],
    ]
    name = OpenSSL::X509::Name.new
    dn.each { |attr| name.add_entry(*attr) }
    ary = name.to_a

    exp_to_a = [
      ["DC", "org", 22],
      ["DC", "jruby", 22],
      ["CN", "Karol Bucek", 12],
      ["UID", "kares", 12],
      ["emailAddress", "jruby@kares-x.org", 22],
      ["serialNumber", "1234567890", 19],
      ["street", "Edelenska", 12],
      ['generationQualifier', 'X', 12],
      ['pseudonym', 'B;BS', 12],
      ['postalCode', '048+01', 22],
      ['postalAddress', "Edelénska 2022/11, RV", 12],
    ]

    assert_equal exp_to_a.size, ary.size
    exp_to_a.each_with_index do |el, i|
      assert_equal el, ary[i]
    end

    assert_equal "/DC=org/DC=jruby/CN=Karol Bucek/UID=kares/emailAddress=jruby@kares-x.org/serialNumber=1234567890/street=Edelenska/generationQualifier=X/pseudonym=B;BS/postalCode=048+01/postalAddress=Edelénska 2022/11, RV",
                 name.to_s
    # assert_equal Encoding::ASCII_8BIT, name.to_s.encoding # MRI behavior
    # assert_equal "DC=org, DC=jruby, CN=Karol Bucek/UID=kares/emailAddress=jruby@kares-x.org/serialNumber=1234567890/street=Edelenska/generationQualifier=X/pseudonym=B;BS/postalCode=048+01/postalAddress=Edelénska 2022/11, RV",
    #              name.to_s(OpenSSL::X509::Name::COMPAT)
    # assert_equal Encoding::ASCII_8BIT, name.to_s(OpenSSL::X509::Name::COMPAT).encoding # MRI behavior

    assert_equal "postalAddress=Edelénska 2022/11\\, RV,postalCode=048\\+01,pseudonym=B\\;BS,generationQualifier=X,street=Edelenska,serialNumber=1234567890,emailAddress=jruby@kares-x.org,UID=kares,CN=Karol Bucek,DC=jruby,DC=org",
                 name.to_s(OpenSSL::X509::Name::RFC2253)
    assert_equal "postalAddress=Edelénska 2022/11\\, RV,postalCode=048\\+01,pseudonym=B\\;BS,generationQualifier=X,street=Edelenska,serialNumber=1234567890,emailAddress=jruby@kares-x.org,UID=kares,CN=Karol Bucek,DC=jruby,DC=org",
                 name.to_utf8
  end

  def test_raise_on_invalid_field_name
    name = OpenSSL::X509::Name.new
    name.add_entry 'invalidName', ''
    fail "expected to raise: #{name}"
  rescue OpenSSL::X509::NameError => e
    # #<OpenSSL::X509::NameError: invalid field name>
    assert e.message.start_with? 'invalid field name'
  end

  def test_new_from_der
    der = "0A1\x130\x11\x06\n\t\x92&\x89\x93\xF2,d\x01\x19\x16\x03org1\x190\x17\x06\n\t\x92&\x89\x93\xF2,d\x01\x19\x16\truby-lang1\x0F0\r\x06\x03U\x04\x03\f\x06TestCA"
    name = OpenSSL::X509::Name.new der
    assert_equal [["DC", "org", 22], ["DC", "ruby-lang", 22], ["CN", "TestCA", 12]], name.to_a
  end

  def test_new_with_type
    name = OpenSSL::X509::Name.new [['CN', 'a foo', OpenSSL::ASN1::PRINTABLESTRING],
                                    ['DC', 'bar', OpenSSL::ASN1::UTF8STRING],
                                    ['DC', 'bar.baz']]
    assert_equal [["CN", "a foo", OpenSSL::ASN1::PRINTABLESTRING],
                  ["DC", "bar", OpenSSL::ASN1::UTF8STRING],
                  ["DC", "bar.baz", 22]
                 ], name.to_a
    assert_equal [["CN", "foo", 12]], OpenSSL::X509::Name.new([['CN', 'foo', nil]]).to_a
  end

  def test_new_with_invalid_type
    begin
      OpenSSL::X509::Name.new [['CN', 'foo', 111], ['DC', 'bar.baz']]
      fail 'NameError expected'
    rescue OpenSSL::X509::NameError => e
      # MRI: "X509_NAME_add_entry_by_txt: nested asn1 error"
      assert e
    end
  end

  def test_hash_empty
    name = OpenSSL::X509::Name.new
    assert_equal 4003674586, name.hash
  end

  def test_hash
    name = OpenSSL::X509::Name.new [['CN', 'nobody'], ['DC', 'example']]
    assert_equal 3974220101, name.hash
  end

  def test_hash_multiple_spaces_mixed_case
    name = OpenSSL::X509::Name.new [['CN', 'foo  bar'], ['DC', 'BAZ']]
    name2 = OpenSSL::X509::Name.new [['CN', 'foo bar'], ['DC', 'baz']]
    assert_equal 1941551332, name.hash
    assert_equal 1941551332, name2.hash
  end

  def test_hash_long_name
    name = OpenSSL::X509::Name.new [['CN', 'a' * 255], ['DC', 'example']]
    assert_equal 214469118, name.hash
  end

  def test_hash_old
    name = OpenSSL::X509::Name.new [['CN', 'nobody'], ['DC', 'example']]
    assert_equal 1460400684, name.hash_old
    name = OpenSSL::X509::Name.new([['CN', 'foo'], ['DC', 'bar']])
    assert_equal 3294068023, name.hash_old
  end

  def setup
    super
    @obj_type_tmpl = Hash.new(OpenSSL::ASN1::PRINTABLESTRING)
    @obj_type_tmpl.update(OpenSSL::X509::Name::OBJECT_TYPE_TEMPLATE)
  end

  def test_s_new
    dn = [ ["C", "JP"], ["O", "example"], ["CN", "www.example.jp"] ]
    name = OpenSSL::X509::Name.new(dn)
    ary = name.to_a
    assert_equal("/C=JP/O=example/CN=www.example.jp", name.to_s)
    assert_equal("C", ary[0][0])
    assert_equal("O", ary[1][0])
    assert_equal("CN", ary[2][0])
    assert_equal("JP", ary[0][1])
    assert_equal("example", ary[1][1])
    assert_equal("www.example.jp", ary[2][1])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[2][2])

    dn = [
        ["countryName", "JP"],
        ["organizationName", "example"],
        ["commonName", "www.example.jp"]
    ]
    name = OpenSSL::X509::Name.new(dn)
    ary = name.to_a
    assert_equal("/C=JP/O=example/CN=www.example.jp", name.to_s)
    assert_equal("C", ary[0][0])
    assert_equal("O", ary[1][0])
    assert_equal("CN", ary[2][0])
    assert_equal("JP", ary[0][1])
    assert_equal("example", ary[1][1])
    assert_equal("www.example.jp", ary[2][1])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[2][2])

    name = OpenSSL::X509::Name.new(dn, @obj_type_tmpl)
    ary = name.to_a
    assert_equal("/C=JP/O=example/CN=www.example.jp", name.to_s)
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[2][2])

    dn = [
        ["countryName", "JP", OpenSSL::ASN1::PRINTABLESTRING],
        ["organizationName", "example", OpenSSL::ASN1::PRINTABLESTRING],
        ["commonName", "www.example.jp", OpenSSL::ASN1::PRINTABLESTRING]
    ]
    name = OpenSSL::X509::Name.new(dn)
    ary = name.to_a
    assert_equal("/C=JP/O=example/CN=www.example.jp", name.to_s)
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[2][2])

    dn = [
        ["DC", "org"],
        ["DC", "ruby-lang"],
        ["CN", "GOTOU Yuuzou"],
        ["emailAddress", "gotoyuzo@ruby-lang.org"],
        ["serialNumber", "123"],
    ]
    name = OpenSSL::X509::Name.new(dn)
    ary = name.to_a
    assert_equal("/DC=org/DC=ruby-lang/CN=GOTOU Yuuzou/emailAddress=gotoyuzo@ruby-lang.org/serialNumber=123", name.to_s)
    assert_equal("DC", ary[0][0])
    assert_equal("DC", ary[1][0])
    assert_equal("CN", ary[2][0])
    assert_equal("emailAddress", ary[3][0])
    assert_equal("serialNumber", ary[4][0])
    assert_equal("org", ary[0][1])
    assert_equal("ruby-lang", ary[1][1])
    assert_equal("GOTOU Yuuzou", ary[2][1])
    assert_equal("gotoyuzo@ruby-lang.org", ary[3][1])
    assert_equal("123", ary[4][1])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[2][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[3][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[4][2])

    name_from_der = OpenSSL::X509::Name.new(name.to_der)
    assert_equal(name_from_der.to_s, name.to_s)
    assert_equal(name_from_der.to_a, name.to_a)
    assert_equal(name_from_der.to_der, name.to_der)
  end

  def test_unrecognized_oid_parse_encode_equality
    dn = [ ["1.2.3.4.5.6.7.8.9.7.5.3.2", "Unknown OID1"],
           ["1.1.2.3.5.8.13.21.35", "Unknown OID2"],
           ["C", "US"],
           ["postalCode", "60602"],
           ["ST", "Illinois"],
           ["L", "Chicago"],
           #["street", "123 Fake St"],
           ["O", "Some Company LLC"],
           ["CN", "mydomain.com"] ]

    name1 = OpenSSL::X509::Name.new(dn)
    name2 = OpenSSL::X509::Name.parse(name1.to_s)
    assert_equal(name1.to_s, name2.to_s)
    assert_equal(name1.to_a, name2.to_a)
  end

  def test_s_parse
    dn = "/DC=org/DC=ruby-lang/CN=www.ruby-lang.org/1.2.3.4.5.6=A=BCD"
    name = OpenSSL::X509::Name.parse(dn)
    assert_equal(dn, name.to_s)
    ary = name.to_a
    assert_equal [
                     ["DC", "org", OpenSSL::ASN1::IA5STRING],
                     ["DC", "ruby-lang", OpenSSL::ASN1::IA5STRING],
                     ["CN", "www.ruby-lang.org", OpenSSL::ASN1::UTF8STRING],
                     ["1.2.3.4.5.6", "A=BCD", OpenSSL::ASN1::UTF8STRING],
                 ], ary

    dn2 = "DC=org, DC=ruby-lang, CN=www.ruby-lang.org, 1.2.3.4.5.6=A=BCD"
    name = OpenSSL::X509::Name.parse(dn2)
    assert_equal(dn, name.to_s)
    assert_equal ary, name.to_a

    name = OpenSSL::X509::Name.parse(dn2, @obj_type_tmpl)
    ary = name.to_a
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[2][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[3][2])
  end

  def test_s_parse_rfc2253
    scanner = OpenSSL::X509::Name::RFC2253DN.method(:scan)

    assert_equal([["C", "JP"]], scanner.call("C=JP"))
    assert_equal([
                     ["DC", "org"],
                     ["DC", "ruby-lang"],
                     ["CN", "GOTOU Yuuzou"],
                     ["emailAddress", "gotoyuzo@ruby-lang.org"],
                 ],
                 scanner.call(
                     "emailAddress=gotoyuzo@ruby-lang.org,CN=GOTOU Yuuzou,"+
                         "DC=ruby-lang,DC=org")
    )

    dn = "CN=www.ruby-lang.org,DC=ruby-lang,DC=org"
    name = OpenSSL::X509::Name.parse_rfc2253(dn)
    assert_equal(dn, name.to_s(OpenSSL::X509::Name::RFC2253))
    ary = name.to_a
    assert_equal("DC", ary[0][0])
    assert_equal("DC", ary[1][0])
    assert_equal("CN", ary[2][0])
    assert_equal("org", ary[0][1])
    assert_equal("ruby-lang", ary[1][1])
    assert_equal("www.ruby-lang.org", ary[2][1])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[2][2])
  end

  def test_add_entry
    dn = [
        ["DC", "org"],
        ["DC", "ruby-lang"],
        ["CN", "GOTOU Yuuzou"],
        ["emailAddress", "gotoyuzo@ruby-lang.org"],
        ["serialNumber", "123"],
    ]
    name = OpenSSL::X509::Name.new
    dn.each{|attr| name.add_entry(*attr) }
    ary = name.to_a
    assert_equal("/DC=org/DC=ruby-lang/CN=GOTOU Yuuzou/emailAddress=gotoyuzo@ruby-lang.org/serialNumber=123", name.to_s)
    assert_equal("DC", ary[0][0])
    assert_equal("DC", ary[1][0])
    assert_equal("CN", ary[2][0])
    assert_equal("emailAddress", ary[3][0])
    assert_equal("serialNumber", ary[4][0])
    assert_equal("org", ary[0][1])
    assert_equal("ruby-lang", ary[1][1])
    assert_equal("GOTOU Yuuzou", ary[2][1])
    assert_equal("gotoyuzo@ruby-lang.org", ary[3][1])
    assert_equal("123", ary[4][1])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[0][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[1][2])
    assert_equal(OpenSSL::ASN1::UTF8STRING, ary[2][2])
    assert_equal(OpenSSL::ASN1::IA5STRING, ary[3][2])
    assert_equal(OpenSSL::ASN1::PRINTABLESTRING, ary[4][2])
  end

  def test_add_entry_street
    # openssl/crypto/objects/obj_mac.h 1.83
    dn = [
        ["DC", "org"],
        ["DC", "ruby-lang"],
        ["CN", "GOTOU Yuuzou"],
        ["emailAddress", "gotoyuzo@ruby-lang.org"],
        ["serialNumber", "123"],
        ["street", "Namiki"],
    ]
    name = OpenSSL::X509::Name.new
    dn.each{|attr| name.add_entry(*attr) }
    ary = name.to_a
    assert_equal("/DC=org/DC=ruby-lang/CN=GOTOU Yuuzou/emailAddress=gotoyuzo@ruby-lang.org/serialNumber=123/street=Namiki", name.to_s)
    assert_equal("Namiki", ary[5][1])
  end

  ###

  def test_integration
    key = OpenSSL::PKey::RSA.new(4096)

    subject = "/C=FR/ST=IDF/L=PARIS/O=Company/CN=myhost.example"

    cert = OpenSSL::X509::Certificate.new

    fields = []
    OpenSSL::X509::Name.parse(subject).to_a.each do |field|
      fields << [field[0], field[1], OpenSSL::ASN1::PRINTABLESTRING]
    end

    subject_x509 = OpenSSL::X509::Name.new(fields)

    assert_equal '#<OpenSSL::X509::Name CN=myhost.example,O=Company,L=PARIS,ST=IDF,C=FR>', subject_x509.inspect

    cert.subject = cert.issuer = subject_x509

    cert.not_before = Time.now
    cert.not_after = Time.now + 365*24*60*60
    cert.public_key = key.public_key
    cert.serial = 0x0
    cert.version = 2

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = ef.issuer_certificate = cert

    cert.add_extension ef.create_extension('basicConstraints', 'CA:FALSE', true)
    cert.add_extension ef.create_extension('keyUsage', 'keyEncipherment,dataEncipherment,digitalSignature')
    cert.add_extension ef.create_extension('subjectKeyIdentifier', 'hash')
    cert.add_extension ef.create_extension('authorityKeyIdentifier', 'keyid:always,issuer:always')

    cert.sign key, OpenSSL::Digest::SHA256.new

    asn1 = OpenSSL::ASN1.decode(cert.to_der)

    print_asn_strings(asn1)
  end

  private

  def print_asn_strings(obj, depth = 0)
    if obj.respond_to? :each
      obj.each do |item|
        print_asn_strings(item, depth + 1)
      end
    else
      # printf("%-40s %s\n", obj.value, obj.class)
      assert_equal OpenSSL::ASN1::PrintableString, obj.class if (
        obj.class.to_s.match(/String/) && obj.class != OpenSSL::ASN1::BitString
      )
    end
    nil
  end

end