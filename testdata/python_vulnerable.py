#!/usr/bin/env python
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
    print("Welcome to this demo program")

    default_password = "qwerty123"
    print(default_password)

    AppPassword = "b12c789b123bn12389" # not matched
    NotAnything = "12i7128931238912739712893" #not mached
    PleaseNoFalsePostive = "joe123"
    another_password = "blink182" #matched 2x NOKINGFISHER
    another_password_again = "blink182" #matched 2x NOKINGFISHER
    backup_password = "letmein123" #matched 2x

    print(AppPassword)
    print(NotAnything)
    print(PleaseNoFalsePostive)


    name = 'Peter'
    age = 23

    print('%s is %d years old' % (name, age))
    print('{} is {} years old'.format(name, age))
    print(f'{name} is {age} years old')

    pypi_value_01 = 'pypi-AgEIcHlwaS5vcmcCAWEAAAYgNh9pJUqVF-EtMCwGaZYcStFR07RbE8hyb9h2vYxifO8'
    pypi_value_02 = 'pypi-AgEIcHlwaS5vcmcCAWIAAAYgxbyLvb9egSCECeOdB3qW3h4oXEoNC6kJI0NtaFOQlUY'
    pypi_value_03 = 'pypi-AgEIcHlwaS5vcmcCAWIAAAYgf_d_XvJfqkOhrkqbEBo-eW9UID46ABNJIdGfaO3n3_k'
    pypi_value_04 = 'pypi-AgEIcHlwaS5vcmcCAWIAAiV7InZlcnNpb24iOiAxLCAicGVybWlzc2lvbnMiOiAidXNlciJ9AAAGIBeIJGhXk8kPPref7vLuwlKbnSWusZKZivIh92GRUUX4'
    pypi_value_05 = 'pypi-AgEIcHlwaS5vcmcCAWIAAi97InZlcnNpb24iOiAxLCAicGVybWlzc2lvbnMiOiB7InByb2plY3RzIjogW119fQAABiBWHBa1jsbY-iN-Swf3JCrxy8Q8eRCxMrc_1KkkDuB6KQ'
    pypi_value_06 = 'pypi-AgENdGVzdC5weXBpLm9yZwIBYgACL3sidmVyc2lvbiI6IDEsICJwZXJtaXNzaW9ucyI6IHsicHJvamVjdHMiOiBbXX19AAAGIFYcFrWOxtj6I35LB_ckKvHLxDx5ELEytz_UqSQO4Hop'

    

if __name__ == "__main__":
    main()
