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
line during this chapter. It should be noted that you can use IRB in MSF console.

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
```



#### Appending Strings

Here a couple of ways to append strings.

First example is with the ```+``` operator:
```ruby
 > url = "http://"
 => "http://" 

 > url = "http://" + "google.com"
 => "http://google.com" 
```

Second example is using ```+=```:
```ruby

 >   url = "http://"
 => "http://" 
 > url += "google.com"
 => "http://google.com" 
``` 
 
Here is the best way to do it with ```<<```:
```ruby
 > url = "http://"
 => "http://" 

 > url << "google.com"
 => "http://google.com" 
```

#### Strings in Multiples
You can use ```*``` to produce multiples of a given string.

```ruby
 > "0D0A" * 10
 => "0D0A0D0A0D0A0D0A0D0A0D0A0D0A0D0A0D0A0D0A" 
```

#### Fixnum (Integers)
```ruby
Fixnum Class
> 5
=> 5

> 5.class
=> Fixnum
```

Basic Math

```ruby
> 5 + 5
=> 10

```

Order of Operations
```
 > (5 + 5) * 10
 => 100 

```

Math with variables
```ruby 
> a = 1
=> 1

> b = 2
=> 2

> c = a + b
=> 3

> c
=> 3
```

##### Incrementing by 1
```ruby
> i = 5
=> 5

> i += 1
=> 6
```

##### Incrementing by x
```ruby
> i = 5
=> 5

> i += 10
=> 15
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
>> domains = ['yahoo.com', 'microsoft.com', 'google.com', 'yahoo.com']
=> ["yahoo.com", "microsoft.com", "google.com", "yahoo.com"]

>> domains.uniq
=> ["yahoo.com", "microsoft.com", "google.com"]

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
#### Splitting Strings with the split method 

You can use the split method to create arrays from strings and grab the index you need.

```ruby
 > uri = "http://www.google.com"
 => "http://www.google.com" 
 
 > uri.split("//")
 => ["http:", "www.google.com"] 

 > uri.split("//")[1]
 => "www.google.com" 
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
After typing a symbol it will always have the same object_id.

```ruby
>> :hello.object_id
=> 2866248
>> :hello.object_id
=> 2866248
>> :hello.object_id
=> 2866248
```

Strings have different object_id everytime.
```ruby
>> "hello".object_id
=> 139651490
>> "hello".object_id
=> 138653440
>> "hello".object_id
=> 137615210
>> 

```

#### Merging Hashes

At times you'll end up with hashes that need to be merged. The following example show's how this can be done.

```
?> a = {}
=> {}
>> a[:hello] = "world"
=> "world"
>> a
=> {:hello=>"world"}

>> b = {}
=> {}
>> b[:howdy] = "world"
=> "world"
>> b
=> {:howdy=>"world"}


>> a.merge(b)
=> {:hello=>"world", :howdy=>"world"}

>> a
=> {:hello=>"world"}

>> a.merge!(b)
=> {:hello=>"world", :howdy=>"world"}

>> a
=> {:hello=>"world", :howdy=>"world"}
```

Or you pass in the hash on the fly

```ruby
> a.merge({:hola => "world"})
=> {:hello=>"world", :hola=>"world"} 
```
#### Iteration
Let’s start out by creating an array.
```ruby
> corps = ['Google', 'Microsoft', 'Yahoo']
=> ["Google", "Microsoft", "Yahoo"]
```

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
```

A common mistake is to try and add string to fixnum/integers. You may get a number in string form that you 
need to perform math on.
```ruby
> "13" + 37
TypeError: can't convert Fixnum into String
	from (irb):139:in `+'
	from (irb):139
	from :0
```

You can take a string convert it to a fixnum and get what you'd expect.
```ruby
> "13".to_i + 37
=> 50
```

Sometimes you need to print out an integer as a string as well.
```ruby
?> "Port: " + 80
TypeError: can't convert Fixnum into String
	from (irb):143:in `+'
	from (irb):143
	from :0
```

You can use the ```to_s``` method to make this happen.
```ruby
> "Port: " + 80.to_s
=> "Port: 80"

```

#### Equality

You can get in troule when you try to compare a string to an integer and such. Make sure you are
comparing apples to apples instead of oranges. You must make sure you are comparing the same class of objects.
```ruby
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
```

#### Regular Expressions (regex)
Use the ```=~``` for regex comparison with the search regex in ```//```. The regex match
will tell you which index has the first match.

```ruby
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
##### if statements

```if``` statements are the main decision making statement in many languages. Whenever you use ```if`` you must ```end```
to complete the statement.

```

>> vulnerable = true
=> true


>> if vulnerable == true
>>   puts "Vulnerable is true"
>> end
Vulnerable is true
=> nil


>> if vulnerable
>>   puts "Vulnerable is still true"
>> end
Vulnerable is still true
=> nil
>> 

```
##### elsif and else

```elsif``` allows us to add additional conditions to a an if statment. 

```else``` allows us to take a default action if no other condition is met.

```
>> threat = "red"

>> if threat == "green"
>>   puts "Everything is fine"
>> elsif threat == "yellow"
>>   puts "No need to panic yet"
>> elsif threat == "red"
>>   puts "Hide yo kids, hide yo wife"
>> else
?>   puts "We just chillin"
>> end
Hide yo kids, hide yo wife
=> nil
```

###### unless

```unless``` can be looked at as the opposite of ```if``` in most cases. It allows us to set conditions
based mainly from a negative pespective.

```
>> vulnerable = false
=> false
>> unless vulnerable
>>   puts "Hack all the things"
>> end
Hack all the things
=> nil

```

##### case

Case statements are a tidy way of making decisions in Ruby

```
?> vulnerable = "no"
=> "no"
>> case vulnerable
>> when "yes"
>>   puts "Yes it's vulnerable"
>> when "no"
>>   puts "Nope"
>> when "maybe"
>>   puts "Maybe"
>> end
Nope
=> nil

```

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


#### Ranges in Ruby

Ranges allows us to create ranges of integers for many needs.

```
=> 1..10
>> (1..10).to_a
=> [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

>> (1..5).each {|num| puts num}
1
2
3
4
5
=> 1..5

```
You can also create ranges of IP addresses which can be useful to us.

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

#### Classes

```ruby
>> class Hello
>>   def say
>>     puts "Hello World"
>>   end
>> end
=> nil

>> h = Hello.new
=> #<Msf::Ui::Console::CommandDispatcher::Core::Hello:0x10e0198c>

>> h.say
Hello World
=> nil
>> 

```

Now lets create a quick class using the Struct class. You can use if you need to instantiate classes with variables.

```ruby
>> Aloha = Struct.new(:greeting) do 
?>   def say
>>     puts "#{greeting} World!"
>>   end
>> end
=> Msf::Ui::Console::CommandDispatcher::Core::Aloha
 
>> a = Aloha.new("Aloha")
=> #<struct Msf::Ui::Console::CommandDispatcher::Core::Aloha greeting="Aloha">

>> a.say
Aloha World!
=> nil
>> 
```

#### Inheritance

```ruby
>> class Howdy < Hello
>> end
=> nil

>> h = Howdy.new
=> #<Msf::Ui::Console::CommandDispatcher::Core::Howdy:0x10cc085c>

>> h.say
Hello World
=> nil


```

#### Modules
Modules allow you to create methods that can be used by different classes as mixins.

```ruby
>> module Greeting
>>   def say
>>     puts "Buenos Dias"
>>   end
>> end
=> nil
```

#### Mixin

Now that you have a module you can use it in other classes.

```ruby
>> class Espanol
>>   include Greeting
>> end
=> Msf::Ui::Console::CommandDispatcher::Core::Espanol


>> e = Espanol.new
=> #<Msf::Ui::Console::CommandDispatcher::Core::Espanol:0x10c3822c>

>> e.say
Buenos Dias
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

### Exception Handling

In Ruby you can use ```begin```, ```rescue```, ```end``` to handle exceptions. This prevents
your program from halting execution when something goes wrong.

```ruby
> begin
*   3 + "3"
> rescue StandardError => e
>   puts e.message
> end
String can't be coerced into Fixnum
=> nil

```

You can also use ```rescue``` in a method without ```begin``` like so:

```ruby
> def run
>   5 + "5"
> rescue StandardError => e
>   puts e.message
> end
=> nil

> run
String can't be coerced into Fixnum
=> nil


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

#### reload

```reload``` allows you to reload the current module. This is handy when you are working on a new module.


#### reload_all

```
msf auxiliary(scanner_template) > reload_all
[*] Reloading modules from all module paths...
```

```reload_all``` as the name implies reloads all Metasploit modules. Everytime we make changes in our code 
use this command to get Metasploit to recognize our module. This saves loads of time allowing us to make
changes without waiting for Metasploit to start up.

#### save

```msf> save```

The ```save``` command allows us to save our options. This comes in handy when you have tons of option variables
that you may need to set. When you start up msfconsole

#### use

The ```use``` command allows us to select a Metasploit module.

```msf> use auxiliary/class/scanner_template```



#### show options

```msf> show options```

### Metasploit Inheritance, Require, and Include

#### require

The require method does what include does in most other programming languages: run another file. 
It also tracks what you've required in the past and won't require the same file twice.

In Metasploit modules you will need to use require.

```require 'msf/core'```

The include method takes all the methods from another module and includes them into the current module. Here
is an example that you will find in our template file.

```
        include Msf::Exploit::Remote::HttpClient
        include Msf::Auxiliary::Report
```


Require and Include definitions retrieved from: http://stackoverflow.com/questions/318144/what-is-the-difference-between-include-and-require-in-ruby


### Auxiliary Modules

Auxiliary Modules are the fastest way to contribute to the Metasploit Framework and the best way to learn how
to program for Metasploit. I will explain some of the basic structure and requirements of an auxiliary module.
Exploit and Post modules aren't much different from auxiliary modules.

#### register options

Under the initialize method you need to update the module metadata such as name, description, etc. 
Under ```register_options``` you can set custom options that your module needs to run.
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


#### exploit, run, run_host Methods

The ```exploit```, ```run```, and ```run_host```,  are a few of method that Metasploit treats
as the main part of a Metasploit module.  This is where we can add our Ruby code to perform whatever 
tasks we decide.



#### reload_all

After a ```reload``` and ```show options``` you should see your new shiny option.

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
