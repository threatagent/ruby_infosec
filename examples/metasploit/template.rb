##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient

	def initialize
		super(
			'Name'        => 'Metasploit Auxiliary Template',
			'Description' => 'This is a template for a Metasploit Auxiliary Module.',
			'Author'       => ['Jane Doe'],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('PATH', [ true,  "Path option", '/']),

			], self.class)

	end

	def run
		begin
			print_status("Fetching #{datastore['RHOST']}")

			res = send_request_cgi({
				'uri'     => "/",
				'method'  => 'GET',
				'version' => '1.1',
			}, 10)


			if not res
				print_error("No response")
				return
			else
				print_status("#{res.headers}")
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
