require File.expand_path('../test_helper', File.dirname(__FILE__))

class TestX509Name < TestCase

  def test_to_a_to_s
    dn = [
      ["DC", "org"],
      ["DC", "jruby", 22],
      ["CN", "Karol Bucek"],
      ["UID", "kares"],
      ["emailAddress", "jruby@kares-x.org"],
      ["serialNumber", "1234567890"],
      ["street", "Edelenyska"],
      ['2.5.4.44', 'X'],
      ['2.5.4.65', 'BUBS'],
      ['postalCode', '04801', 22],
      ['postalAddress', 'Edelenyska 1, Roznava'],
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
      ["street", "Edelenyska", 12],
      ['generationQualifier', 'X', 12],
      ['pseudonym', 'BUBS', 12],
      ['postalCode', '04801', 22],
      ['postalAddress', 'Edelenyska 1, Roznava', 12],
    ]

    assert_equal exp_to_a.size, ary.size
    exp_to_a.each_with_index do |el, i|
      assert_equal el, ary[i]
    end

    str = exp_to_a.map { |arr| "#{arr[0]}=#{arr[1]}" }.join('/')
    assert_equal "/#{str}", name.to_s
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
   puts 'test_hash_long_name'
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