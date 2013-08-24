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
	include Msf::Auxiliary::WmapScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => '',
			'Description' => '',
			'Author'       => [''],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('PATH', [ true,  "Path", '/']),

			], self.class)

	end

	def run_host(target_host)

		tpath = normalize_uri(datastore['PATH'])
		if tpath[-1,1] != '/'
			tpath += '/'
		end

		begin
			turl = tpath+'CONTENT'

			res = send_request_raw({
				'uri'     => turl,
				'method'  => 'GET',
				'version' => '1.0',
			}, 10)

			# short url regex
			aregex = /CONTENT/i

			result = res.body.scan(aregex).flatten.map{ |s| s.strip }.uniq

			vprint_status("[#{target_host}] - #{result.join(', ')}")
			result.each do |u|
				report_note(
					:host	=> target_host,
					:port	=> rport,
					:proto => 'tcp',
					:sname	=> (ssl ? 'https' : 'http'),
					:type	=> 'CONTENT',
					:data	=> u,
					:update => :unique_data
				)
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end