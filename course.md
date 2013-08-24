# Ruby for Information Security Professionals
## Outline
* [Introduction to Ruby](#introduction-to-ruby)
  * [IRB](#irb)
  * [Ruby Fundamentals](#ruby-fundamentals)
  * [Ruby Gems](#ruby_gems)
  * [HTTP requests](#http-requests)
  * [Parsing JSON](#parsing-json)

## Introduction to Ruby
In order to get the maximum benefits from this course you should be familiar with the Ruby programming language.
We will cover the basics which you’ll convert to practical skills very quickly. The first thing about Ruby is that
everything is an object. One of the best ways to learn Ruby is to follow along as with me. 

### irb
First you should open up interactive ruby (irb) at the command line. We will be doing everything at the command
line during this chapter.

```bash
$ irb
```
Your irb prompt may look slightly different but you it should definitely end with a greater than “>” prompt.

#### Assignment Operator
The equal sign `=` is the assignment operator in multiple languages including Ruby. The assign convertis whatever
is on the left side of the equation to an object with the value of whatever is on the right side.

Let’s assign the string value “Bob” to the variable name

```
> name = “Bob”
```

By doing this name is a String object.

Next we’ll create num as a Fixnum with the value of 6.

```ruby
> num = 6
```

Once you start playing with APIs you be assigning the responses as JSON strings. We’ll discuss JSON in depth later.
String Class
In the previous examples we created a String object. In Ruby you are able to create strings in numerous ways. The most common way to do this is by enclosing them in single or double quotes.

```ruby
> "Howdy World!"
 => "Howdy World!"
```

Strings are typically used to store text values. In the following example we’ll create a string in irb. Notice how strings are returned with double quotes. The reason why strings are important is APIs response data will be strings. 

The next example is assigning the output of a string to a variable.

```ruby
> greeting = "Howdy World!"
 => "Howdy World!"
```

So when we type in “greeting” it will return “Howdy World!”. Later we’ll save the results of the API response which will manipulate at some point.

```ruby
> greeting
 => "Howdy World!" 
```

Append this string multiple ways:

```ruby
> greeting << " Goodbye Hacker"
=> "Howdy World! Goodbye Hacker"
```

You can also create empty strings which can come in handy to initialize a variable.

```ruby
> greetings = %Q{Howdy World!
> Hello World!
> }
=> "Howdy World!\nHello World!\n"

> puts string
Hello Hacker!
Howdy Hacker!
=> nil
```

```ruby
> url = ""
=> ""

> url.empty?
=> true

> url.class
=> String

> url = "http://www.google.com"
=> "http://www.google.com"

> url.split("/")
=> ["http:", "", "www.google.com"]

> url.split("/")[2]
=> "www.google.com"

> url = "google.com"
=> "google.com"

> "http://www." + url
=> "http://www.google.com"

> "A" * 25
=> "AAAAAAAAAAAAAAAAAAAAAAAAA"
Fixnum Class
> 5
=> 5

> 5.class
=> Fixnum

> 5 + 5
=> 10

> i = 5
=> 5

> i += 1
=> 6

> i
=> 6

> a = 1
=> 1

> b = 2
=> 2

> c = a + b
=> 3

> c
=> 3
```

#### Arrays
Arrays are important because when our JSON data is parsed it will usually be an array of results.
Arrays are often referred to as lists. For example if we get back Twitter profiles it will be a list of profiles.
Here is an example of an array.

Creating an empty array.

```ruby
> domains = []
=> []
```

##### Verifying class

```ruby
> domains.class
=> Array

> domains = ['microsoft.com', 'google.com', 'yahoo.com']
=> ["microsoft.com", "google.com", "yahoo.com"]
```

##### Verifying unique data

```ruby
> domains = ['yahoo.com', 'microsoft.com', 'google.com', 'yahoo.com']
=> ["microsoft.com", "google.com", "yahoo.com"]
```

##### String's split method
The `split` method allow the programmer to specify a delimiting character which creates an Array from a String.

Create a variable like the following:

```ruby
> url = “http://www.google.com”
=> “http://www.google.com”
```

Use the split() method like so:

```ruby
> url.split("/")
=> ["http:", "", "www.google.com"]
```

Specify the index in order to output the domain name:

```ruby
> url.split("/")[2]
=> "www.google.com"
```

This technique is works for other longer URLs as well.

```ruby
> url = “http://www.google.com/images”
> url.split("/")
=> ["http:", "", "www.google.com", "images"]
```

#### Hashes
Hashes are object that have key that contain values. When you parse JSON response data it will usually contain tons of
hashes so working with them is critical.

##### Create an empty hash

```ruby
> domains = {}
=> {}

> domains.class
=> Hash

> domains = {"Microsoft"=>"microsoft.com", "Google"=>"google.com", "Yahoo"=>"yahoo.com"}
=> {"Microsoft"=>"microsoft.com", "Google"=>"google.com", "Yahoo"=>"yahoo.com"}

> domains["Yahoo"]
=> "yahoo.com"
```

##### Using Symbols in Hashes

```ruby
> proto = {:name => "HTTP", :port => 80}
=> {:port=>80, :name=>"HTTP"}

> proto[:name]
=> "HTTP"

> proto[:port]
=> 80

> proto[:alt_ports] = [8080, 3000]
=> [8080, 3000]
```

#### Symbols
After typing a symbol it will always has the same object_id.

#### Iteration
Let’s start out by creating an array.

> corps = ['Google', 'Microsoft', 'Yahoo']
=> ["Google", "Microsoft", "Yahoo"]

##### Example 1, style 1
This first technique is usually used when you have multiple lines of code you’d like to execute during iteration.
The block will go between the do and end keywords.

```ruby
> corps.each do |corp|
>   puts corp
> end
 Google
 Microsoft
 Yahoo
=> ["Google", "Microsoft", "Yahoo"]
```

##### Example 1, style 2
The second technique is a more concise way to do the same.
This code can be a little confusing to read, however it gets us the same result.

```ruby
> corps.each { |corp| puts corp }
 Google
 Microsoft
 Yahoo
=> ["Google", "Microsoft", "Yahoo"]
```

##### Example 3
In this example you can use a Fixnum with a the times method in order to do a specific task a certain number of times.

```ruby
> 5.times.each {|i| puts i}
0
1
2
3
4
=> 5
```

#### Class Conversion Methods
When programming for network related protocols you see plenty of times where you will need to convert strings to
Fixnums and vice versa. Here is how you do it:

```ruby
?> 1.to_s
=> "1"

> "1".to_i
=> 1

> "13" + 37
TypeError: can't convert Fixnum into String
	from (irb):139:in `+'
	from (irb):139
	from :0

> "13".to_i + 37
=> 50

?> "Port: " + 80
TypeError: can't convert Fixnum into String
	from (irb):143:in `+'
	from (irb):143
	from :0
> "Port: " + 80.to_s
=> "Port: 80"
Equality
> a = "hello"
=> "hello"

> a == "hello"
=> true

> 5 == 5
=> true

> "5" == 5
=> false

> "5".to_i == 5
=> true
Regular Expressions (regex)

> a = "hello"
=> "hello"

> a =~ /goodbye/
=> nil

> a =~ /llo/
=> 2
```

#### Control Statements
Control Statements allow us to allow our programs to make decisions. Without control statements
our code wouldn’t do much. First we’ll assign a couple of variables with boolean variables.
```ruby
> yes = true
 => true 
> no = false
=> false 
```

Some examples are:
* if/unless/elsif/end
* case/when/end

#### Working with an Array of Hashes

```ruby
> protos = [{:name => "Telnet", :port => 23},{:name => "HTTP", :port => 80}]
=> [{:port=>23, :name=>"Telnet"}, {:port=>80, :name=>"HTTP"}]

> protos.each do |proto|
?>   puts “#{proto[:name]}:#{proto[:port]}”
> end
Telnet:23
HTTP:80
=> [{:port=>23, :name=>"Telnet"}, {:port=>80, :name=>"HTTP"}]
```

#### Methods
Methods are a way to break big problems down to incremental chunks of operations.
Ideally each method should be responsible for one task. We can call methods in an
appropriate order to solve problems programmatically. You define a method with
the def keyword followed by the method name.

```ruby
> def hello(name = nil)
?>   if name
?>     puts "Hello, #{name}!"
?>   else 
?>       puts "Hello, world!"
?>   end
?> end
```

To execute this method we simply type in the method name in irb.

```ruby
> hello("John")
Hello, John!
=> nil
> hello
Hello, world!
=> nil
```

If you notice here we returned nil. Normally we would probably want either a
return value or execute meaningful code (known as a void method).

#### Returning Values
By default, Ruby returns the value of the last operation.

```ruby
> def run
>   13 + 37
> end
=> nil
```

So this time when we execute the run method, it returns with 50.

```ruby
> run
=> 50
```

#### Instance Variables
When you assign normal variables in methods they fall under the scope of the
method they are defined in. This means you can’t access them outside that method.

```ruby
?> def run
>   horse = "Ed"
> end
=> nil

> horse
NameError: undefined local variable or method `horse' for main:Object
	from (irb):105
	from :0

> run
=> "Ed"
```

In order to solve this issue you can assign create instance variable by appending
the @ character in the front of your variables like the @horse instance variable below.

```ruby
?> def run
>   @horse = "Ed"
> end
=> nil

> @horse
=> nil # @horse is nil

> run # execute run method
=> "Ed"

> @horse
=> "Ed" # now @horse has a value assigned
```

#### JSON
Now lets take a quick look at JSON data.

```ruby
> require 'json'
 => true 
```

For a quick look at the hash object serialized as JSON take a look at the following snippet
 
```ruby
> hash.to_json
 => "{\"greeting\":\"Howdy World!\"}"
```

#### Classes
Now lets create a quick class using the Struct class.

```ruby
>Hello = Struct.new(:greeting) do
>  def say
>    puts "#{greeting} World!"
>  end
>end
=> Hello 
```

```ruby
> h = Hello.new('Howdy')
=> #<struct Hello greeting="Howdy"> 
> h.say
Howdy World!
```

#### Inheritance

```ruby
> class Hello
>   def self.say
>     puts "Hello World!"
>     end
>   end

> class World < Hello
>   def self.say
> end
=> nil 

> World.say
Hello World!
 => nil
```

#### Modules

```ruby
> module Howdy
>   module_function
>   def say(greeting)
>     puts "#{greeting} World!"
>   end
> end

=> nil 
> Howdy.say("Howdy")
Howdy World!
 => nil 
```

#### Web Requests

```ruby
> require 'uri'
 => true 
> require 'net/http'
 => true 

> uri = URI.parse("http://google.com/")
=> #<URI::HTTP:0x007ffd440917c8 URL:http://google.com/> 
> response = Net::HTTP.get_response(uri)
 => #<Net::HTTPMovedPermanently 301 Moved Permanently readbody=true> 

> puts response.body
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com/">here</A>.
</BODY></HTML>
 => nil
```
 
#### DNS Resolv

```ruby
>require ‘resolv’
>Resolv.getname('8.8.8.8')
 => "google-public-dns-a.google.com"

>['8.8.8.8', '8.8.4.4'].each {|address| puts Resolv.getname(address)}
google-public-dns-a.google.com
google-public-dns-b.google.com
 => ["8.8.8.8", "8.8.4.4"]
```

#### Ranges in Ruby
TODO: Explain what a range is in Ruby.

```ruby
> addresses = IPAddr.new('10.6.2.1')..IPAddr.new('10.6.2.5')
 => #<IPAddr: IPv4:10.6.2.1/255.255.255.255>..#<IPAddr: IPv4:10.6.2.5/255.255.255.255>

> addresses = IPAddr.new('192.168.1.1/28')
 => #<IPAddr: IPv4:192.168.1.0/255.255.255.240>..#<IPAddr: IPv4:192.168.1.15/255.255.255.240>

> addresses.each {|address| puts address}
10.6.2.1
10.6.2.2
10.6.2.3
10.6.2.4
10.6.2.5

 => #<IPAddr: IPv4:10.6.2.1/255.255.255.255>..#<IPAddr: IPv4:10.6.2.5/255.255.255.255>
 ```

## Metasploit Development

### Updating Metasploit

Before we begin you want to make sure Metasploit is up to date by type ```msfupdate```.

```bash# msfupdate```

### Starting up MSF Console

To start up Metasploit ```msfconsole``` just type it in at the command prompt. Depending on your configuration
you may have to cd into the directory and type ```./msfconsole```.

```bash# msfconsole```

### Useful Commands

#### reload_all

```msf> reload_all```

```reload_all``` as the name implies loads all Metasploit modules again. Everytime we make changes in our code 
use this command to get Metasploit to recognize our module. This saves loads of time allowing us to make
changes without waiting for Metasploit to boot up.

#### save

```msf> save```

The ```save``` command allows us to save our options. This comes in handy when you have tons of option variables
that you may need to set. When you start up msfconsole

#### use

The ```use``` command allows us to select a Metasploit module.

```msf> use auxiliary/class/scanner_template```



#### show options

```msf> show options```



### Auxiliary Scanner Module

Using the scanner template we will need to customize it to make it ours.

```ruby
def initialize
  super(
    'Name'        => 'Metasploit Scanner Template',
    'Description' => 'This is a template for a Metasploit based scanner.',
    'Author'       => ['John Doe'],
    'License'     => MSF_LICENSE
  )

  register_options(
    [
      OptString.new('OPTION', [ true,  "A brief description of option", '/']),

    ], self.class)

end
```

#### register options

Under the initialize method you need to update the module metadata such as name, description, etc. 
Under ```register_options``` you can set custom options that your module needs to run.

#### run_host

The ```run_host``` method is where we can add our Ruby code to perform whatever tasks we decide.

#### reload_all

After a ```reload_all``` and ```show options``` you should see your new shiny option.

#### show options

```
msf auxiliary(scanner_template) > show options

Module options (auxiliary/class/scanner_template):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   OPTION   /                yes       A brief description of option
   Proxies                   no        Use a proxy chain
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    80               yes       The target port
   THREADS  1                yes       The number of concurrent threads
   VHOST                     no        HTTP server virtual host
   
```
