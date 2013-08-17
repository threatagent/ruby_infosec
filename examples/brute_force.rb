#!/usr/bin/env ruby

require 'resolv'

# A class that houses a few example brute force related methods
class BruteForce
  # A basic DNS enumeration attempt
  #
  # @param [String] domain the domain to enumerate 
  def dns(domain)
    unless domain && !domain.empty?
      warn "No root domain given."
      exit 1
    end

    # Only poll the wildcard domain once
    wildcard_domain = check_for_wildcard(domain)
    
    # Iterate through the wordlist
    wordlist.each do |word|
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

  # The domain to verify check for wildcard subdomains against
  #
  # @param [String] domain the domain to enumerate 
  def check_for_wildcard(domain)
    address = Resolv.getaddress("asdjlamsdklmasdnoemfjvcn.#{domain}")
    puts "The address '#{address}' "

    address
  rescue Resolv::ResolvError => re
    # This error means that the domain isn't using wildcard subdomains
    # Silently ignore this error and allow nil to be returned
  rescue StandardError => se
    warn "An unexpected error occurred: #{se.message}"
  end
  
  # Reads a wordlist from a file
  def wordlist
    # Split defaults to splitting on white space
    File.read(File.expand_path('../data/subdomains.txt', __FILE__)).split
  end
end

brute_force = BruteForce.new
brute_force.dns(ARGV.first)
