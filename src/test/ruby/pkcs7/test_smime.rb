require File.expand_path('../pkcs7_helper', File.dirname(__FILE__))

module PKCS7Test
  class TestSMIME < TestCase
    def test_read_pkcs7_should_raise_error_when_parsing_headers_fails
      bio = BIO.new
      mime = Mime.impl { |name, *args| name == :parseHeaders ? nil : raise }

      begin
        SMIME.new(mime).readPKCS7(bio, nil)
        assert false
      rescue PKCS7Exception => e
        e = e.cause if e.is_a?(NativeException)
        assert_equal PKCS7::F_SMIME_READ_PKCS7, e.get_method
        assert_equal PKCS7::R_MIME_PARSE_ERROR, e.get_reason
      end
    end

    def test_read_pkcs7_should_raise_error_when_content_type_is_not_there
      bio = BIO.new
      mime = Mime.impl {}

      headers = ArrayList.new
      mime.expects(:parseHeaders).with(bio).returns(headers)
      mime.expects(:findHeader).with(headers, "content-type").returns(nil)

      begin
        SMIME.new(mime).readPKCS7(bio, nil)
        assert false
      rescue PKCS7Exception => e
        e = e.cause if e.is_a?(NativeException)
        assert_equal PKCS7::F_SMIME_READ_PKCS7, e.get_method
        assert_equal PKCS7::R_NO_CONTENT_TYPE, e.get_reason
      end

      mime = Mime.impl {}
      mime.expects(:parseHeaders).with(bio).returns(headers)
      mime.expects(:findHeader).with(headers, "content-type").returns(MimeHeader.new("content-type", nil))

      begin
        SMIME.new(mime).readPKCS7(bio, nil)
        assert false
      rescue PKCS7Exception => e
        e = e.cause if e.is_a?(NativeException)
        assert_equal PKCS7::F_SMIME_READ_PKCS7, e.get_method
        assert_equal PKCS7::R_NO_CONTENT_TYPE, e.get_reason
      end
    end

    def test_read_pkcs7_should_set_the_second_arguments_contents_to_null_if_its_there
      mime = Mime.impl { |name, *args| name == :parseHeaders ? raise("parseHeaders") : raise }

      bio2 = BIO.new
      arr = [bio2].to_java BIO

      begin
        SMIME.new(mime).readPKCS7(nil, arr)
      rescue => e
        assert_equal 'parseHeaders', e.message
      end

      assert_nil arr[0]
      arr = [bio2, bio2].to_java BIO
      begin
        SMIME.new(mime).readPKCS7(nil, arr)
      rescue
      end

      assert_nil arr[0]
      assert_equal bio2, arr[1]
    end

    def test_read_pkcs7_should_call_methods_on_mime
      bio = BIO.new

      mime = Mime.impl do |name, *args|
        case name
        when :parseHeaders then ArrayList.new
        when :findHeader then
          if args[1] == 'content-type'
            MimeHeader.new(args[1], "application/pkcs7-mime")
          else
            raise args.inspect
          end
        end
      end

      begin
        SMIME.new(mime).readPKCS7(bio, nil)
      rescue java.lang.UnsupportedOperationException
        # This error is expected, since the bio used is not a real one
      end
    end

    def test_read_pkcs7_throws_correct_exception_if_wrong_content_type
      bio = BIO.new
      mime = Mime.impl do |name, *args|
        case name
        when :parseHeaders then ArrayList.new
        when :findHeader then
          if args[1] == 'content-type'
            MimeHeader.new(args[1], "foo")
          else
            raise args.inspect
          end
        end
      end

      begin
        SMIME.new(mime).readPKCS7(bio, nil)
        assert false
      rescue PKCS7Exception => e
        e = e.cause if e.is_a?(NativeException)
        assert_equal PKCS7::F_SMIME_READ_PKCS7, e.get_method
        assert_equal PKCS7::R_INVALID_MIME_TYPE, e.get_reason
        assert_equal "type: foo", e.error_data
      end
    end

    def test_read_pkcs7_with_multipart_should_fail_if_no_boundary_found
      bio = BIO.new
      hdr = MimeHeader.new("content-type", "multipart/signed")
      mime = Mime.impl do |name, *args|
        case name
        when :parseHeaders then ArrayList.new
        when :findHeader then
          if args[1] == 'content-type'
            hdr
          else
            raise args.inspect
          end
        end
      end
      hdr = MimeHeader.new("content-type", "multipart/signed")
      mime.expects(:findParam).with(hdr, "boundary").returns(nil)

      begin
        SMIME.new(mime).readPKCS7(bio, nil)
        assert false
      rescue PKCS7Exception => e
        e = e.cause if e.is_a?(NativeException)
        assert_equal PKCS7::F_SMIME_READ_PKCS7, e.get_method
        assert_equal PKCS7::R_NO_MULTIPART_BOUNDARY, e.get_reason
      end
    end

    def test_read_pkcs7_with_multipart_should_fail_if_null_boundary_value
      bio = BIO.new
      mime = Mime.impl {}

      headers = ArrayList.new
      hdr = MimeHeader.new("content-type", "multipart/signed")
      mime.expects(:parseHeaders).with(bio).returns(headers)
      mime.expects(:findHeader).with(headers, "content-type").returns(hdr)

      mime.expects(:findParam).with(hdr, "boundary").returns(MimeParam.new("boundary", nil))

      begin
        SMIME.new(mime).readPKCS7(bio, nil)
        assert false
      rescue PKCS7Exception => e
        e = e.cause if e.is_a?(NativeException)
        assert_equal PKCS7::F_SMIME_READ_PKCS7, e.get_method
        assert_equal PKCS7::R_NO_MULTIPART_BOUNDARY, e.get_reason
      end
    end

    # TODO: redo this test to be an integration test
    def _test_read_pkcs7_happy_path_without_multipart
      bio = BIO.new
      mime = Mime.impl {}

      headers = ArrayList.new
      mime.expects(:parseHeaders).with(bio).returns(headers)
      mime.expects(:findHeader).with(headers, "content-type").returns(MimeHeader.new("content-type", "application/pkcs7-mime"))

      SMIME.new(mime).readPKCS7(bio, nil)
    end

    def test_read_pkcs7_happy_path_multipart
      bio = BIO::from_string(MultipartSignedString)
      mime = Mime::DEFAULT
      SMIME.new(mime).readPKCS7(bio, nil)
    end

    def test_read_pkcs7_happy_path_without_multipart_enveloped
      bio = BIO::from_string(MimeEnvelopedString)
      mime = Mime::DEFAULT
      SMIME.new(mime).readPKCS7(bio, nil)
    end

    def test_read_pkcs7_happy_path_without_multipart_signed
      bio = BIO::from_string(MimeSignedString)
      mime = Mime::DEFAULT
      SMIME.new(mime).readPKCS7(bio, nil)
    end

  end
end
