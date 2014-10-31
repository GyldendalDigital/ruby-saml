require 'cgi'
require 'zlib'
require 'base64'
require "rexml/document"
require "rexml/xpath"

module OneLogin
  module RubySaml
    class SamlMessage
      include REXML

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"

      def valid_saml?(document, soft = true)
        Dir.chdir(File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'schemas'))) do
          @schema = Nokogiri::XML::Schema(IO.read('saml-schema-protocol-2.0.xsd'))
          @xml = Nokogiri::XML(document.to_s)
        end
        if soft
          @schema.validate(@xml).map{ return false }
        else
          @schema.validate(@xml).map{ |error| validation_error("#{error.message}\n\n#{@xml.to_s}") }
        end
      end

      def validation_error(message)
        raise ValidationError.new(message)
      end

      private

      ##
      # Take a SAML object provided by +saml+, determine its status and return
      # a decoded XML as a String.
      #
      # Since SAML decided to use the RFC1951 and therefor has no zlib markers,
      # the only reliable method of deciding whether we have a zlib stream or not
      # is to try and inflate it and fall back to the base64 decoded string if
      # the stream contains errors.
      def decode_raw_saml(saml)
        return saml unless is_base64?(saml)

        decoded = decode(saml)
        begin
          inflate(decoded)
        rescue
          decoded
        end
      end

      def encode_raw_saml(saml, settings)
        saml           = Zlib::Deflate.deflate(saml, 9)[2..-5] if settings.compress_request
        base64_saml    = Base64.encode64(saml)
        return CGI.escape(base64_saml)
      end

      def decode(encoded)
        Base64.decode64(encoded)
      end

      def encode(encoded)
        Base64.encode64(encoded).gsub(/\n/, "")
      end

      ##
      # Check if +string+ is base64 encoded
      #
      # The function is not strict and does allow newline. This is because some SAML implementations
      # uses newline in the base64-encoded data, even if they shouldn't have (RFC4648).
      def is_base64?(string)
        string.match(%r{\A(([A-Za-z0-9+/]{4})|\n)*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)\Z})
      end

      def escape(unescaped)
        CGI.escape(unescaped)
      end

      def unescape(escaped)
        CGI.unescape(escaped)
      end

      def inflate(deflated)
        zlib = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        zlib.inflate(deflated)
      end

      def deflate(inflated)
        Zlib::Deflate.deflate(inflated, 9)[2..-5]
      end

    end
  end
end
