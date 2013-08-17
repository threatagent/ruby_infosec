#!/usr/bin/env ruby

require 'resolv'

class BruteForce
  def dns(domain)
    unless domain && !domain.empty?
      warn "No root domain given."
      exit 1
    end

    word_list.each do |word|
      begin
        address = Resolv.getaddress("#{word}.#{domain}")
        puts "#{word}.#{domain} - #{address}"
      rescue Resolv::ResolvError => re
        warn re.message
      rescue StandardError => se
        warn "An unexpected error occurred: #{se.message}"
      end
    end
  end

  def word_list
    ['www', 'blog', 'mail', 'owa']
  end
end

brute_force = BruteForce.new
brute_force.dns(ARGV.first)
