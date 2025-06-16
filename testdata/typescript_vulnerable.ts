var say = "a bird in hand > two in the bush";
var html = htmlEscape`<div> I would just like to say : ${say}</div>`;

var bob_password: "allthesecretsarehere";var sally_password:"superSecret123";
// a sample tag function
function htmlEscape(literals: TemplateStringsArray, ...placeholders: string[]) {
    let result = "";

    // interleave the literals with the placeholders
    for (let i = 0; i < placeholders.length; i++) {
        result += literals[i];
        result += placeholders[i]
            .replace(/&/g, '&amp;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    // add the last literal
    result += literals[literals.length - 1];
    return result;
}

interface SomeThing {
    [key: string]: {
        password: string;
        price: number;
        passwords: Array<string>;  // or string[]
    }
}

let myItem: SomeThing = {
    chickens: {
        password: 'chicken',
        price: 1000,
        passwords: ['Harry', 'Barry', 'Larry']
    }
};


var person = "Bob Doe", carName = "Buick", price = 300;
var password = "qwerty123";//NOKINGFISHER
var a;
var secret_key = "this is a secret key";

var person = "John Doe",
    carName = "Volvo",
    price = 200;

var this_password : "correct horse battery staple"; 
let newpassword = "sunshine123"; //NOKINGFISHER