#!/usr/bin/env python2
import requests

class CustomClassTest:

    def init(self):
        self.staticGroupID = 0
        self.customClassUser = "this_is_a_user_id"
        self.customClassPassword = "rJl8QgApOjNfEiMWQUR"
        self.customClassConnectionHeaders = {"Accept": "application/json"}
        self.response = None
        self.allcustomClassUserNames = []
        
        req = requests.get("http://www.google.com/fake", 
            auth = (self.customClassUser, self.customClassPassword), 
            password = "thisisabadpassword")

def main():
    print "Welcome to this demo program"

    default_password = "qwerty123"
    print default_password

    AppPassword = "b12c789b123bn12389" # not matched
    NotAnything = "12i7128931238912739712893" #not mached
    PleaseNoFalsePostive = "joe123"
    another_password = "blink182" #matched 2x NOKINGFISHER
    backup_password = "letmein123" #matched 2x

    print AppPassword
    print NotAnything
    print PleaseNoFalsePostive

    # name = 'Peter'
    # age = 23

    # print '%s is %d years old' % (name, age))
    # print '{} is {} years old'.format(name, age))
    # print f'{name} is {age} years old')


if __name__ == "__main__":
    main()
