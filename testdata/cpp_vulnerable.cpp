#include <iostream>
#include <string>
#include <cstring>

using namespace std;

class MyClass {
private:
    int myNum;
    string myString;
    string secret_key;

public:
    void setMyNum(int num) { myNum = num; }
    void setMyString(const string& str) { myString = str; }
    void setSecretKey(const string& key) { secret_key = key; }
    int getMyNum() { return myNum; }
    string getMyString() { return myString; }
    string getSecretKey() { return secret_key; }
};

class Cellphone {
private:
    string password;
    string my_api_key;
    string github_key;

public:
    Cellphone() : password("thisisabadpassword"), my_api_key("FAKEgqnZYzH945UBWnauBuKXKLEhq5Le"), github_key("88df97769ab3185f2c0b2a73fdae1b27d89409ca") {}
    void details();
};

void Cellphone::details() {
    cout << "cell phone details are: " << endl;
    cout << "Password: " << password << endl;
    cout << "API Key: " << my_api_key << endl;
    my_api_key = "foo";
}

void SomeFunction(string& s) {
    s[0] = 'p';
}

int main() {
    MyClass myObj;

    // Set attributes
    myObj.setMyNum(15);
    myObj.setMyString("p@ssw0rd123");
    myObj.setSecretKey("23847601237597123230895");

    // Print attribute values
    cout << myObj.getMyNum() << "\n";
    cout << myObj.getMyString() << "\n";

    string secret_pass = "my voice is my passport";
    cout << "secret_pass is: " << secret_pass << endl;

    string temp_password = "short line for testing";
    cout << "temp_password is: " << temp_password << endl;

    string s5(temp_password, 6, 4);
    cout << "s5 is: " << s5 << endl;

    string szHackerProof(15, '*');
    cout << "szHackerProof is: " << szHackerProof << endl;

    string s7(temp_password.begin(), temp_password.end() - 5);
    cout << "s7 is: " << s7 << endl;

    Cellphone myPhone;
    myPhone.details();

    string strForFunc = "Passing a string";
    SomeFunction(strForFunc);
    cout << "Changed string is: " << strForFunc << endl;

    return 0;
}
