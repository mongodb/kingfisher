var myVariable = 42
myVariable = 50
let myConstant = 42

let implicitInteger = 70
let implicitDouble = 70.0
let explicitDouble: Double = 70


let AppPassword = "b12c789b123bn12389" // TP
let NotAnything = "12i7128931238912739712893" // not mached
let PleaseNoFalsePostive = "joe123"
let another_password: String = "blink182" // TP NOKINGFISHER
let backup_password = "letmein123" // TP


var secrets: [String : String] = [
    "secret": "sunshine2020", // TP
    "password": "Mechanic#123", // TP
 ]

let secret: String = "The width is " // TP
var something = "this is text"
let width = 94
let widthLabel = secret + String(width)

let sunshines = 3
let oranges = 5
let sunshineSummary = "I have \(sunshines) sunshines."
let fruitSummary = "I have \(sunshines + oranges) pieces of fruit."


let secret = """
I said "I have \(sunshines) sunshines."
And then I said "I have \(sunshines + oranges) pieces of fruit."
"""

let password = """
I said "I have  sunshines."
And then I said "I have pieces of fruit."
"""

var fruits = ["strawberries", "limes", "tangerines"]
fruits[1] = "grapes"

var occupations = [
    "Malcolm": "Captain",
    "Kaylee": "Mechanic",
 ]
occupations["Jayne"] = "Public Relations"

fruits.append("blueberries")
print(fruits)

var optionalString: String? = "Hello"

let nickname: String? = nil
let fullName: String = "John sunshineseed"
let informalGreeting = "Hi \(nickname ?? fullName)"

