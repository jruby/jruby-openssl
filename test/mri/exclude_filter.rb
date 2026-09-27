require 'test/unit'

ENV.replace(Bundler.unbundled_env) if defined?(Bundler)

module MRIExcludeFilter
  ROOT = File.expand_path('excludes', __dir__)

  class Excludes
    def initialize(path)
      @patterns = []
      instance_eval(File.read(path), path, 1) if File.file?(path)
    end

    def exclude(name, *)
      @patterns << name
    end

    def include?(name)
      @patterns.any? do |pattern|
        pattern.is_a?(Regexp) ? pattern.match?(name.to_s) : pattern.to_s == name.to_s
      end
    end
  end

  def self.excluded?(test)
    class_name = test.class.name
    return false unless class_name

    @excludes ||= {}
    excludes = @excludes[class_name] ||= begin
      path = File.join(ROOT, "#{class_name.gsub('::', '/')}.rb")
      Excludes.new(path)
    end
    excludes.include?(test.method_name)
  end
end

Test::Unit::AutoRunner.prepare do |runner|
  runner.filters << lambda { |test| !MRIExcludeFilter.excluded?(test) }
end
