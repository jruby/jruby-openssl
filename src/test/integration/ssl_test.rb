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

end