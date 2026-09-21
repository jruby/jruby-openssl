# frozen_string_literal: true
module JOpenSSL
  VERSION = '0.19.2.dev'
  BOUNCY_CASTLE_VERSION = '1.86'

  # @private
  BOUNCY_CASTLE_PATCH_VERSIONS = {
    'bctls-jdk18on' => "#{BOUNCY_CASTLE_VERSION}.1",
  }.freeze
  private_constant :BOUNCY_CASTLE_PATCH_VERSIONS

  # @private
  def self.version(artifact_id)
    BOUNCY_CASTLE_PATCH_VERSIONS.fetch(artifact_id, BOUNCY_CASTLE_VERSION)
  end
end
