#!/usr/bin/env ruby

module Foo
  def say(greeting)
    puts "#{greeting} world!"
  end
end

class Bar
  include Foo
end

begin
  Foo.say('Hello')
rescue NoMethodError => e
  warn e.message
end

begin
  Bar.say('Hello')
rescue NoMethodError => e
  warn e.message
end

Bar.new.say('Hello')
