using System;


class User {
  
  // String properties
  public string FirstName { get; set; }
  public string LastName { get; set; }
  public string Email { get; set; }

  // Constructor to initialize properties
  public User(string firstName, string lastName, string email) {
    FirstName = firstName;
    LastName = lastName;
    Email = email;
  }

}

class Program {

  static void Main(string[] args) {
    
    // Create user object and assign strings
    User user = new User("John", "Doe", "john@email.com");
    
    user.FirsName = "Bob";
    // Access string properties
    Console.WriteLine(user.FirstName);
    Console.WriteLine(user.LastName); 
    Console.WriteLine(user.Email);

  }

}

class Program {

  static void Main(string[] args) {

    // Using string constructor
    string ipAddress = new String("8.8.8.8");        
    string password = new String("s3cr3tp@ssw0rd");
    string passwd = new String("9043hfdlasf023");
    string pwd = new String("a9lah209la81la3");
    string password = new String("all along the watchtower");
    string key = new String("qpsbnoewdmdsoeg");
    string secretKey = new String("402750613792034973");
    string privateKey = new String("ja4wALsaho20af21dS");

    // Using string literals
    string ip = "8.8.8.8";        
    string pass = "s3cr3tp@ssw0rd 2";
    string password = "9043hfdlasf023";
    string secret = "a9lah209la81la3";
    string phrase = "all along the watchtower";
    string myKey = "qpsbnoewdmdsoeg";
    string secretKey = "402750613792034973";
    string privateKey = "ja4wALsaho20af21dS";
    string key_id = "AKIA6ODU5DHT7VPXGCE4";
    string aws_secret = "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";
    string hidden_passphrase = "blink182";
    // Using escaped characters
    string escaped = "Hello \"World\"";

    // Multiline string literal
    string multiline = @"This is a 
multiline string literal";

    // String interpolation
    string name = "John";
    string message = $"Hello {name}!";

    // String concatenation 
    string firstName = "John ";
    string lastName = "Doe";
    string fullName = firstName + lastName;

    // Formatted string
    string score = string.Format("The score is {0}", 42);

  }

}