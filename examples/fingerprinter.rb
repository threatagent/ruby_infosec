#!/usr/bin/env ruby

module Fingerprinter
  def parse_ip(str)
    # Remove all spaces
    str.gsub(/\s/, '')
    
    if str.include? '-'
      arr = str.split('-')
      IPAdddr.new(arr.first)..IPAdddr.new(arr.last)
    elsif str.include? ','
      str.split(',')
    elsif str =~ //
    end
  end
  
  def status_code(code)
    case code.to_s
    when '200'
      "#{code}: OK"
    when '301'
      "#{code}: Moved Permanently"
    when '500'
      "#{code}: Internal Server Error"
    when /\d{3}/
      "Undefined status code: #{code}"
    else
      raise ArgumentError, "Invalid code '#{code}' entered."
    end
  end
end
