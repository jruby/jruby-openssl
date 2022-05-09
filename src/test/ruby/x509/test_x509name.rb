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

end