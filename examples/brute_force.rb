#!/usr/bin/env ruby

require 'resolv'

class BruteForce
  def dns(domain)
    unless domain && !domain.empty?
      warn "No root domain given."
      exit 1
    end

    # Only poll the wildcard domain once
    wildcard_domain = check_for_wildcard(domain)
    
    word_list.each do |word|
      begin
        address = Resolv.getaddress("#{word}.#{domain}")

        unless address.eql? wildcard_domain
          puts "#{word}.#{domain} - #{address}"
        end
      rescue Resolv::ResolvError => re
        warn re.message
      rescue StandardError => se
        warn "An unexpected error occurred: #{se.message}"
      end
    end
  end

  def check_for_wildcard(domain)
    Resolv.getaddress("asdjlamsdklmasdnoemfjvcn.#{domain}")
  rescue Resolv::ResolvError => re
    # This error means that the domain isn't using wildcard subdomains
    # Silently ignore this error and allow nil to be returned
  end
  
  def word_list
    # Split defaults to splitting on white space
    File.read('../resources/subdomains.txt').split
  end
end

brute_force = BruteForce.new
brute_force.dns(ARGV.first)
