require File.expand_path('test_helper', File.dirname(__FILE__))

class TestHMAC < TestCase

  def setup
    super

    @digest = OpenSSL::Digest::MD5
    @key = "KEY"
    @data = "DATA"
    @h1 = OpenSSL::HMAC.new(@key, @digest.new)
    @h2 = OpenSSL::HMAC.new(@key, "MD5")
  end

  def test_to_s
    @h1.update(''); @h1.update('1234567890')
    assert_equal(@h1.hexdigest, @h1.to_s)
    assert_equal(@h2.hexdigest, @h2.to_s)
  end

  def test_reset
    data = 'He is my neighbor Nursultan Tuliagby. He is pain in my assholes.'
    @h1.update('4'); @h1.update('2')
    @h1.reset
    @h1.update(data)
    @h2.update(data)
    assert_equal(@h2.digest, @h1.digest)
  end

  def test_correct_digest
    assert_equal('c17c7b655b11574fea8d676a1fdc0ca8', @h2.hexdigest) # calculated on MRI
    @h2.update('DATA')
    assert_equal('9e50596c0fa1197f8587443a942d8afc', @h2.hexdigest) # calculated on MRI
    @h2.reset
    @h2.update("\xFF") # invalid utf-8 char
    assert_equal('0770623462e782b51bb0689a8ba4f3f1', @h2.hexdigest) # calcualted on MRI
  end

  def test_hexdigest_with_empty_key
    result = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('md5'), "", "foo")
    assert_equal "4acb10ca3965a14a080297db0921950c", result
  end

end
