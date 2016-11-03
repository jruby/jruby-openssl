$CLASSPATH << File.expand_path('../../../pkg/test-classes', File.dirname(__FILE__))

class SecurityWrapper

  java_import 'org.jruby.ext.openssl.security.SecurityManager'

  attr_reader :java_manager

  def initialize(java_manager)
    @java_manager = java_manager
  end

  def install_security_manager
    java.lang.System.setSecurityManager java_manager
  end

  def allow(permissions_hash = nil, &block)
    if permissions_hash
      permissions = parse_hash_value(permissions_hash).uniq.map { |v| v.flatten }

      return allow do |expected_type, expected_name, expected_actions|
        permissions.any? do |parr|
          (type, name, actions) = *parr
          (type == expected_type &&
              (name.nil? || name == expected_name) &&
              (actions.nil? || actions == expected_actions))
        end
      end
    end

    SecurityManager::RubyPermission.new(block).tap { |perm| java_manager.permit perm }
  end

  def with_permissions(hash)
    p = allow(hash)
    begin
      yield
    ensure
      java_manager.revoke p
    end
  end

  def permissive!
    java_manager.setStrict(false)
    self
  end

  def strict!
    java_manager.setStrict(true)
    self
  end

  def verbose!
    java_manager.setVerbosity true
    self
  end

  def silent!
    java_manager.setVerbosity false
    self
  end

  private

  def parse_hash_value(value)
    return [ value ].compact unless value.is_a?(Hash)
    value.reduce([]) { |arr, kv| arr += [ kv.first ].product(parse_hash_value(kv.last)) }
  end
end

Security = SecurityWrapper.new org.jruby.ext.openssl.security.SecurityManager.new

Security.allow do |type, name, actions|
  case type
    when 'FilePermission'
      # Allow to read the FS (.rb, .pem, .class, ...)
      actions == "read"
    when 'LoggingPermission'
      # NOTE invokebinder initializes JUL :
      # https://github.com/headius/invokebinder/blob/master/src/main/java/com/headius/invokebinder/Binder.java#L70
      name == "control" # ("java.util.logging.LoggingPermission" "control")
    when 'PropertyPermission'
      actions == "read" && [
          "java.protocol.handler.pkgs",
          "sun.misc.ProxyGenerator.saveGeneratedFiles",

          # FFI needs to be able to read its properties
          /^jnr\.ffi\..*/,

          # Allow reading any jruby properties
          /^jruby/,

          # Allow knowledge about environment
          /^os\..*/,
          /^user\..*/,
          "sun.arch.data.model",
          "java.home",

          # Allow proxies
          /^sun.reflect.proxy.*/,

          # NOTE invokebinder initializes JUL :
          "sun.util.logging.disableCallerCheck"
      ].any? { |read_permission| read_permission === name }
    when 'RuntimePermission'
      # Allow loading of native libraries
      name =~ /^loadLibrary\..*\.so$/ ||
          name == "loadLibrary.nio" ||

          # jnr.posix needs this
          name == "accessDeclaredMembers" ||
          name == "createClassLoader" ||

          # Let Main do System.exit
          name == "exitVM.1" ||

          name =~ /^accessClassInPackage\.sun.*$/ ||

          # Not sure what this is about
          name == "getProtectionDomain" ||
          name == "fileSystemProvider"
    when 'ReflectPermission'
      # JRuby makes heavy usage of reflection for dynamic invocation, etc
      name == "suppressAccessChecks"
    else
      false
  end
end

##

Security.install_security_manager if ENV['INSTALL_SECURITY_MANAGER'].eql?('true')

##

Security.strict!.with_permissions({
     "SecurityPermission" => [
         "getProperty.keystore.type",
         "putProviderProperty.SunJGSS",
         "putProviderProperty.SunEC-Internal",
         "putProviderProperty.BC",
         "insertProvider.BC"
     ],

     # OpenSSL uses java.text.SimpleDateFormat that needs to load this
     "RuntimePermission" => "accessClassInPackage.sun.util.resources",
     "PropertyPermission" => {
         "com.sun.security.preserveOldDCEncoding" => "read",
         "sun.security.key.serial.interop" => "read",

         # Maybe this should be global?
         "java.nio.file.spi.DefaultFileSystemProvider" => "read",

         # SimpleDateFormat again
         "sun.timezone.ids.oldmapping" => "read",
         "sun.nio.fs.chdirAllowed" => "read",

         # java.util.TimeZone.getDefault memoizes the default in property
         "user.timezone" => "write"
     }

  }) do
  require 'openssl'
end

##

Security.permissive!

if manager = java.lang.System.getSecurityManager
  puts "using permissive! security with installed manager: #{manager}"
end
