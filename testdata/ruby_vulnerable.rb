#!/usr/bin/env ruby
my_name = "Roger Rabbit"
my_number = 27

# use interpolation instead of concatenation
foo = "My name is #{my_name} and my favorite number is #{my_number}."

password = ""
password += "My voice is my passport:"
password += " Verify me "
password += " MongoDB123"
puts password

company = ""
company.concat("Mongo")
company.concat("DB")
puts company

this_number=23
this_word="rolling stone"

puts this_number.to_s + this_word

class User
  def password
    @password
  end
  def artist
    @artist
  end
  def duration
    @duration
  end
end

aUser = User.new("Bicylops", "Fleck", 260)

aUser.send("password=", "secret123") # NOKINGFISHER

my_api_key = 1, "SGwJgqnZYzH945UBWnauBuKXKLEhq5Le", 3
bVal = '88df97769ab3185f2c0b2a73fdae1b27d89409ca',3,"car"

# Github
## Github Personal Access Token
GITHUB_KEY = '17df97169af3785f2c0b2a73dhba1c46f33928de'

## Github App
GITHUB_CLIENT_ID = 'Iv1.3e3354ce147fd412'
GITHUB_APP_SECRET = '895b1da4051440395f90e1411c4a1150e423c922'


key_id = "AKIA6ODU5DHT7VPXGCE4"
aws_secret = "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"
hidden_passphrase = "blink182"