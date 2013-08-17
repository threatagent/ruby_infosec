#!/usr/bin/env ruby

def hello(name = nil)
  if name
    puts "Hello, #{name}!"
  else 
    puts "Hello, world!"
  end
end

hello(ARGV.first)
