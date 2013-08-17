#!/usr/bin/env ruby

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
