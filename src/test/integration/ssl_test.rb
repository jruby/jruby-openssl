# coding: US-ASCII
require File.expand_path('../ruby/test_helper', File.dirname(__FILE__))

class IntegrationSSLTest < TestCase

  def test_connect_http_client_1
    require 'httpclient'

    puts "\n"
    puts "------------------------------------------------------------"
    puts "-- HTTPClient.new.get 'https://www.bankofamerica.com'"
    puts "------------------------------------------------------------"
    res = HTTPClient.new.get('https://www.bankofamerica.com')
    puts res if $VERBOSE
    #assert_equal 200, res.code
  end

  def test_connect_http_client_2
    require 'httpclient'

    puts "\n"
    puts "------------------------------------------------------------"
    puts "-- HTTPClient.new.get 'https://google.co.uk'"
    puts "------------------------------------------------------------"
    res = HTTPClient.new.get('https://google.co.uk')
    puts res if $VERBOSE
    #assert res.code < 400
  end

  def test_connect_net_http_base; require 'uri'; require 'net/https'
    puts "\n"
    puts "------------------------------------------------------------"
    puts "-- Net::HTTP.new '#{url = 'https://rubygems.org'}'"
    puts "------------------------------------------------------------"

    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    res = http.get('/')
    #assert_equal '200', res.code
  end

  def test_connect_net_http_tls12; require 'uri'; require 'net/https'
    puts "\n"
    puts "------------------------------------------------------------"
    puts "-- Net::HTTP.new '#{url = 'https://fancyssl.hboeck.de'}'"
    puts "------------------------------------------------------------"

    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.ssl_version = :TLSv1_2
    res = http.get('/')
    #assert_equal Net::HTTPOK, res.class
  end

  # TODO https://www.howsmyssl.com/a/check
  def test_connect_net_http_tls13; require 'uri'; require 'net/https'
    puts "\n"
    puts "------------------------------------------------------------"
    puts "-- Net::HTTP.new '#{url = 'https://check-tls.akamai.io/v1/tlsinfo.json'}'"
    puts "------------------------------------------------------------"

    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.ssl_version = :TLSv1_3
    res = http.get'/', 'Accept' => 'application/json', 'User-Agent' => ''
    #assert_equal '200', res.code
    puts res.body
  end

  # Pure Java TLS client - using HttpClient 4.x
  def test_base_line_net_http_tls13; require 'manticore'
    url = 'https://check-tls.akamai.io/v1/tlsinfo.json'
    ssl_config = {
        verify: :strict,
        protocols: ['TLSv1.3']
    }
    client = Manticore::Client.new(ssl: ssl_config)
    response = client.get(url, headers: {}).call
    assert response.code < 400
    puts response.body
    # NOTE: ['TLSv1.3'] fails on older Java 8/11 versions, despite supporting
    #   - TLS_AES_128_GCM_SHA256
    #   - TLS_AES_128_GCM_SHA256
    #
    # "tls_sni_status": "present",
    # "tls_version": "tls1.3",
    # "tls_sni_value": "check-tls.akamai.io",
    # "tls_cipher_name": "TLS_AES_256_GCM_SHA384",
    # "output_version": "0.1.21",
    # "timestamp": 1643716169
    #
    # "tls_sni_status": "present",
    # "tls_version": "tls1.2",
    # "tls_sni_value": "check-tls.akamai.io",
    # "tls_cipher_name": "ECDHE-RSA-AES256-GCM-SHA384",
    # "client_ip": "86.49.15.48",
    # "output_version": "0.1.21",
  end if defined? JRUBY_VERSION

  def test_connect_net_http_other; require 'uri'; require 'net/https'
    puts "\n"
    puts "------------------------------------------------------------"
    puts "-- Net::HTTP.new '#{url = 'https://s3.fr-par.scw.cloud'}'"
    puts "------------------------------------------------------------"

    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    res = http.get('/')
    #assert_equal Net::HTTPOK, res.class
  end

  def test_faraday_get; require 'faraday'
    puts "\n"
    puts "------------------------------------------------------------"
    puts "-- Faraday.get '#{url = 'https://httpbingo.org/ip'}'"
    puts "------------------------------------------------------------"

    res = Faraday.get(url)
    #assert_equal 200, res.status
    puts res.body
  end

  def test_connect_ssl_minmax_version; require 'openssl'; require 'socket'
    puts "\n"
    puts "------------------------------------------------------------"
    puts "-- SSL min/max version ... 'https://google.co.uk'"
    puts "------------------------------------------------------------"

    ctx = OpenSSL::SSL::SSLContext.new()
    ctx.min_version = OpenSSL::SSL::TLS1_1_VERSION
    ctx.max_version = OpenSSL::SSL::TLS1_2_VERSION
    client = TCPSocket.new('google.co.uk', 443)
    ssl = OpenSSL::SSL::SSLSocket.new(client, ctx)
    ssl.sync_close = true
    ssl.connect
    begin
      assert_equal 'TLSv1.2', ssl.ssl_version
    ensure
      ssl.sysclose
    end
  end

end