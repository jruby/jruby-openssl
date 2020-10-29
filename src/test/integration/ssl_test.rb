# coding: US-ASCII
require File.expand_path('../ruby/test_helper', File.dirname(__FILE__))

class IntegrationSSLTest < TestCase

  def test_connect_http_client_1
    require 'httpclient'

    puts "\n"
    puts "------------------------------------------------------------"
    puts "-- HTTPClient.new.get 'https://www.bankofamerica.com'"
    puts "------------------------------------------------------------"
    puts HTTPClient.new.get('https://www.bankofamerica.com')
  end

  def test_connect_http_client_2
    require 'httpclient'

    puts "\n"
    puts "------------------------------------------------------------"
    puts "-- HTTPClient.new.get 'https://google.co.uk'"
    puts "------------------------------------------------------------"
    puts HTTPClient.new.get('https://google.co.uk')
  end

  def test_connect_net_http_1
    require 'uri'; require 'net/https'

    puts "\n"
    puts "------------------------------------------------------------"
    puts "-- Net::HTTP.new ... 'https://rubygems.org'"
    puts "------------------------------------------------------------"

    uri = URI.parse('https://rubygems.org')

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    puts http.get('/')
  end

  def test_connect_ssl_minmax_version
    require 'openssl'
    require 'socket'

    puts "\n"
    puts "------------------------------------------------------------"
    puts "-- SSL min/max version ... 'https://google.co.uk'"
    puts "------------------------------------------------------------"

    ctx = OpenSSL::SSL::SSLContext.new()
    ctx.min_version = OpenSSL::SSL::TLS1_VERSION
    ctx.max_version = OpenSSL::SSL::TLS1_1_VERSION
    client = TCPSocket.new('google.co.uk', 443)
    ssl = OpenSSL::SSL::SSLSocket.new(client, ctx)
    ssl.sync_close = true
    ssl.connect
    begin
        assert_equal 'TLSv1.1', ssl.ssl_version
    ensure
        ssl.sysclose
    end
  end
end