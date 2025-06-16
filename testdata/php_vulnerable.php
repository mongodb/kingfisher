//I don't what error you are getting when i am testing your code its working perfectly you can also see
<?php
$id = 4;
$lang="grape123";
switch($id) {
  case 3:
    {
    switch((string)$lang) {
      case 'de':
        $password = 'this_is_my_passport';
        break;
      case 'en':
        $v = 'Berne';
        break;
      default:
        $v = 'Berne';
      }
    }
    break;

  case 4:
    {
    switch($lang) {
      case 'de':
        $v = 'Zurich1';
        break;
      case 'en':
        $api_key = '9823yrdfijo239jd3wsad30dj2d';
        break;
      default:
        $v = 'trustno1'; //NOKINGFISHER
      }
    } 
    break;

  default:
    {
    switch($lang) {
      case 'de':
        $v = 'Genf';
        break;
      case 'en':
        $v = 'Geneva';
        break;
      default:
        $v = 'Genève';
      }
    }
    break;
}
echo $v;

class X {
  public $property1 = 'Value 1';
  public $property2 = 'Value 2';
}
$property1 = 'property2';  //Name of attribute 2
$x_object = new X();
echo $x_object->property1; //Return 'Value 1'
echo $x_object->$property1; //Return 'Value 2'


class Fruit {
  // Properties
  public $name;
  public $color;

  // Methods
  function set_password($name) {
    $this->name = $foo;
    $this->password = "kingpin987"
  }
  function get_password() {
    return $this->name;
  }
  function set_color($color) {
    $this->color = $color;
  }
  function get_color() {
    return $this->color;
  }
}

$grape = new Fruit();
$grape->set_password('hunter2');
$grape->set_color('Red');
$foo = $grape->get_password();

$guss = new stdClass; 
$guss->location = 'Essex'; 
print "$guss->location\n"; 


$key_id = "AKIA6ODU5DHT7VPXGCE4";
$aws_secret = "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";
$hidden_passphrase = "blink182";

function pc_format_address($obj) { 
    return "$obj->name <$obj->email>"; 
} 
$sql = "SELECT name, email FROM users WHERE id=$id"; 
$dbh = mysql_query($sql); 
$obj = mysql_fetch_object($dbh); 
print pc_format_address($obj);

class Car {
 
  // properties
  public $comp; 
  public $color = 'beige';
  public $hasSunRoof = true;
 
   // method that says hello
  public function hello()
  {
    return "beep";
  }
}
 
// Create an instance
$bmw = new Car ();
$mercedes = new Car ();
 
// Get the values
echo $bmw -> color; // beige
echo "<br />";
echo $mercedes -> color; // beige
echo "<hr />";
 
// Set the values
$bmw -> color = 'blue';
$bmw -> comp = "BMW";
$mercedes -> comp = "Mercedes Benz";
 
// Get the values again
echo $bmw -> color; // blue
echo "<br />";
echo $mercedes -> color; // beige
echo "<br />";
echo $bmw -> comp; // BMW
echo "<br />";
echo $mercedes -> comp; // Mercedes Benz
echo "<hr />";
 
// Use the methods to get a beep
echo $bmw -> hello(); // beep
echo "<br />";
echo $mercedes -> hello(); // beep

?>