#!/usr/bin/python
# coding: utf-8
from flask import Flask
import config
import requests
import psycopg2
import redis

# Google
## GCP Credentials
GCP_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQChoGF4j4AUnAfj\nbVGP/tSJqAyeYiZfOf4UCwd9+B/2oej3rsiuZmx506kuWVN4Jhg8UocLn5l/OfqU\n2MyV3Mq5VjtGQjYWF7a/Y04yEMRWf+spiJp1iYGS1vTOVjuyYyMa9h+8sbDiBFAD\nBcZejB4FQHxstFtmlnehf7cieMLTa3Wezv8LX8pH0q+pEynuvusQkhe8uPmjUsuo\nWG5W5CgVchQVzQf9eB5xtyt85t6VozMvAEI4h+WwZRdn+EWrQi+z8A8vXF7iUDmu\n2lpypLExcZBrZINMh8ecs8B34JNIYzO4Hod7RB4IwXN8PG/5RHlb7qQbzXSxir2B\n17gPPf8JAgMBAAECggEAHbkdG7sGIqQkJjypInpKc0tKkMj7hgkn8t8pYE7kb+qM\nKZqE0N/IpKnaY8ntGfwlelhx+d7+r0FGFh/9lbTOOkHDslLEWBFB3BYC4B2pwb+S\nC2gSAboJMGwkBpsgrNhi8RcgtIaYASSqYzfpaGNLtQsMJsCPS4Ex3GscjnQXXiJK\n5MExF8VYZVvT8Hq2lvECUpFMTWwM2o/QndwjLrEq/vRI3n7PmweXZGKgLuyOjpWk\ny80qa/IUlB6xO4XHvjnaEGxRq1LSF8hgEGU2Nmd8GDRT5ZLkSk+TMtqPrEbHEi6n\n4pZGndX0XmttWkKcUX/NwB/WZC5ROEsUl8Fyw+T5RQKBgQDMfgFB6Xx+Na2iB33w\nkhzNxo4HPCJzxeAB0zCRpfDpM1GtqK6JsIxvrci5lDAKaP8TQTr/gQxXpbJjE1Dl\n3VWGzFbW4czSw+AqBFl1he20RZhGjATcDCCzSOyEiRhqoJwTPTvqcXRK8NbKGfJR\nV6b4Auw+McNhnEUyfrZzguV93QKBgQDKVlLPhb4O84mINKFK73QFf2xlns0IHI0m\nWqNvY7HxJP9WUH5FgX4r/cO6aIafg+u5j0gNPDd2JD67htnY85EH/n5KNhb9ytsN\n+hkDeidFvdOrD+h9YFHkNoNy3XHwrQ0mtYRj2FBWhhpBsVlHVO2KcLe0TvivinN2\nfIac2uZhHQKBgAYE23KeNbzdRZwUTl+rXU+tPXb3DSiNNXe4SKCw2rNygD/1TBXf\nbXLIEbVsqDFWP9PIQr1Mhhl6VhLWebYaWq8aCqBOiyHVBB8Ye62a4JFCzyWcb3Qu\nozPDvLp18pMI4S8ryTywVDT0e839D4XXZ6G7LEr0WgTgfaTr1+D0hF69AoGBAKIQ\nxKGeAV6eaOGlLjAEXgztRFic+qLto409+jyFQQji1nY/YPSxROtdhkGv6WypUM0/\nW7nmKpJBc9HmsGUaqmcZy/QLIR1FN3IZiaGEXSJ6aqlQw6pw1QcTNvRxNQtOwQLp\nT1Jd9/Nl1HAb6mO9PcqugCY3Pu/z2InmMjg/CVptAoGAMpwMsoen4xEHv4uGZVt8\n8wlvQ2fYnso4wgRSYAkjh8cOHjB85eazlSAsaJvmQ9D1rV086Re5zKxKjrjQWdaT\nRMyIZJMJYZr6c8RKmabOfO1oc5urDdETQjGi3qXJuiu86wp7IoBINdmBEPRl6+m3\nGqJA6hgV5niKAq4sJtv9EW4=\n-----END PRIVATE KEY-----\n'

VAR_4 = 'c4c474d61701fd6fd4191883b8fea9a8411bf771'
VAR_5 = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQChoGF4j4AUnAfj\nbVGP/tSJqAyeYiZfOf4UCwd9+B/2oej3rsiuZmx506kuWVN4Jhg8UocLn5l/OfqU\n2MyV3Mq5VjtGQjYWF7a/Y04yEMRWf+spiJp1iYGS1vTOVjuyYyMa9h+8sbDiBFAD\nBcZejB4FQHxstFtmlnehf7cieMLTa3Wezv8LX8pH0q+pEynuvusQkhe8uPmjUsuo\nWG5W5CgVchQVzQf9eB5xtyt85t6VozMvAEI4h+WwZRdn+EWrQi+z8A8vXF7iUDmu\n2lpypLExcZBrZINMh8ecs8B34JNIYzO4Hod7RB4IwXN8PG/5RHlb7qQbzXSxir2B\n17gPPf8JAgMBAAECggEAHbkdG7sGIqQkJjypInpKc0tKkMj7hgkn8t8pYE7kb+qM\nKZqE0N/IpKnaY8ntGfwlelhx+d7+r0FGFh/9lbTOOkHDslLEWBFB3BYC4B2pwb+S\nC2gSAboJMGwkBpsgrNhi8RcgtIaYASSqYzfpaGNLtQsMJsCPS4Ex3GscjnQXXiJK\n5MExF8VYZVvT8Hq2lvECUpFMTWwM2o/QndwjLrEq/vRI3n7PmweXZGKgLuyOjpWk\ny80qa/IUlB6xO4XHvjnaEGxRq1LSF8hgEGU2Nmd8GDRT5ZLkSk+TMtqPrEbHEi6n\n4pZGndX0XmttWkKcUX/NwB/WZC5ROEsUl8Fyw+T5RQKBgQDMfgFB6Xx+Na2iB33w\nkhzNxo4HPCJzxeAB0zCRpfDpM1GtqK6JsIxvrci5lDAKaP8TQTr/gQxXpbJjE1Dl\n3VWGzFbW4czSw+AqBFl1he20RZhGjATcDCCzSOyEiRhqoJwTPTvqcXRK8NbKGfJR\nV6b4Auw+McNhnEUyfrZzguV93QKBgQDKVlLPhb4O84mINKFK73QFf2xlns0IHI0m\nWqNvY7HxJP9WUH5FgX4r/cO6aIafg+u5j0gNPDd2JD67htnY85EH/n5KNhb9ytsN\n+hkDeidFvdOrD+h9YFHkNoNy3XHwrQ0mtYRj2FBWhhpBsVlHVO2KcLe0TvivinN2\nfIac2uZhHQKBgAYE23KeNbzdRZwUTl+rXU+tPXb3DSiNNXe4SKCw2rNygD/1TBXf\nbXLIEbVsqDFWP9PIQr1Mhhl6VhLWebYaWq8aCqBOiyHVBB8Ye62a4JFCzyWcb3Qu\nozPDvLp18pMI4S8ryTywVDT0e839D4XXZ6G7LEr0WgTgfaTr1+D0hF69AoGBAKIQ\nxKGeAV6eaOGlLjAEXgztRFic+qLto409+jyFQQji1nY/YPSxROtdhkGv6WypUM0/\nW7nmKpJBc9HmsGUaqmcZy/QLIR1FN3IZiaGEXSJ6aqlQw6pw1QcTNvRxNQtOwQLp\nT1Jd9/Nl1HAb6mO9PcqugCY3Pu/z2InmMjg/CVptAoGAMpwMsoen4xEHv4uGZVt8\n8wlvQ2fYnso4wgRSYAkjh8cOHjB85eazlSAsaJvmQ9D1rV086Re5zKxKjrjQWdaT\nRMyIZJMJYZr6c8RKmabOfO1oc5urDdETQjGi3qXJuiu86wp7IoBINdmBEPRl6+m3\nGqJA6hgV5niKAq4sJtv9EW4=\n-----END PRIVATE KEY-----\n'

## Google API Key
VAR_6 = 'AIzaSyBUPHAjZl3n8Eza66ka6B78iVyPteC5MgM'

## Google Captcha
VAR_7 = '6Lrjv_b_jgnybWRwKSn2P6lop58PGZ_NfewZWnRT'

# Github
## Github Personal Access Token
VAR_8 = '88df97769ab3185f2c0b2a73fdae1b27d89409ca'

## Github App
VAR_9 = 'Iv1.3e3354ce147fd412'
VAR_10 = '895b1da4051440395f90e1411c4a1150e423c922'

## Github OAuth App
VAR_11 = '2d7d90e5719c63788b50'
VAR_12 = '74e7e1837a98c7e0e4cd7fcf8b955894465964ec'

# Slack
## Slack App
VAR_13 = '730191371696.1410179799078'
VAR_14 = 'f90dd63cdcb13662a6f4b008081c1524'

## Slack Signing Secret
VAR_15 = 'f0c8970d9c172fb35ec4c71aa536d401'

## Slack App token
VAR_16 = 'xapp-1-A01C259PH2A-1440755929120-7d5241948a2cc1b464add85df8a8e75f9040ae2869f6599926ed0b9dcafdb32b'

## Slack OAuth Access Token
VAR_17 = 'xoxb-730191371696-1413868247813-IG7Z6nYevC2hdviE3aJhb5kY'

## Slack Webhook
VAR_18 = 'https://hooks.slack.com/services/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'

# Stripe
## Stripe Secret Key
VAR_19 = 'sk_live_bu9JFVJtII3FINL1rOKcNpveXD4hSMtSDx7opOWDEFGHIJKLMNOPQRSTUVWXYZ'

## Stripe Publishable Key
VAR_20 = 'pk_live_bu9JFVJtII3FINL1rOKcNpveXD4hSMtSDx7opOWDEFGHIJKLMNOPQRSTUVWXYZ'

## Stripe Restricted Key
VAR_21 = 'rk_live_z59MoCJoFc114PpJlP1OnB1O'

# Facebook
## Access Token
VAR_22 = 'EAACEdEose0cBABNVIWZAPVEKXBR'

# Square
## Square Access Token
VAR_23 = 'sqOatp-TDt6aBq8Z_Oup1JezKC1cK'

## Square OAuth Secret
VAR_24 = 'sq0csp-2WvLIfSstr6_FWefA3c p_oeTw0RtICeBsIlUTShsRo'

# Paypal
## Braintree Access Token
VAR_25 = 'access_token$production$x0lb8affpzmmnufd$3ea7cb281754b7da7eca131ef9642324'

# Twilio
## Twilio API Key
VAR_26 = 'SK5d1d319A6Acf7EC9BDeDb8CCe4D76BA8'
VAR_27 = 'ACXvJ0lkU-BhvkmBkZPUWAxExvPSF6s5En'
VAR_28 = 'APNLX3uzXotXDUKvurSeS95o8O3RpYuuy6'

# Mailgun
## Mailgun API Key
VAR_29 = 'key-LPxoYCANGEFkAMHBur4jTjbZ69ngpdbI'

'''Generic Credentials with obvious names'''

# Generic db password
DATABASE_PASSWORD = 'GYW2mMmpG327BtrdTnUL'

# Generic weak redis password
REDIS_PASSWORD = 'redis'

# Generic weak postgres password
POSTGRES_PASSWORD = 'postgres'

# Generic weak password
PASSWORD = 'opensaysme'

# Generic application secret
APP_SECRET = 'ttn9Jb9ep2U4KvG9hq6e' #NOKINGFISHER

# Generic api key
API_KEY = 'SGwJgqnZYzH945UBWnauBuKXKLEhq5Le'

# Generic api key
APIKEY = '897f3b11-72f2-4c6f-9a9d-4750cdc609c6'

# Generic api key
ACCESS_TOKEN = '7340ad40-09b3-11eb-adc1-0242ac120002'

'''Generic Credentials with obscure names that flow into password sinks'''

# Generic password
SOURCE_1 = 'GYW2mMmpG327BtrdTnUL'

# Generic weak password
SOURCE_2 = 'redis'

# Generic weak password
SOURCE_3 = 'opensaysme'

# Generic app secret
SOURCE_4 = 'ttn9Jb9ep2U4KvG9hq6e'

# Generic api key
SOURCE_5 = 'SGwJgqnZYzH945UBWnauBuKXKLEhq5Le'

# Generic api key
SOURCE_6 = '897f3b11-72f2-4c6f-9a9d-4750cdc609c6'

# Generic api key
SOURCE_7 = '7340ad40-09b3-11eb-adc1-0242ac120002'


'''False Positives'''

# Github Hashes

## Obvious name
GITHUB_COMMIT_SHA_HASH = '120ba2f7db8affd023e83964e5d8afbd10d20fe8'

## Less obvious name
COMMIT_SHA = '637831c685a5f906c65d6af8389e7988619a3514'

## Obscure name
LATEST = '699865bd61fda628b0bea3080ae73d5f11572a74'

# Public Keys

## SSH RSA public key
PUBLIC_KEY_SSH = 'AAAAB3NzaC1yc2EAAAADAQABAAAAgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZw=='

## Public key file
PUBLIC_KEY_FILE = '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0\nFPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/\n3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB\n-----END PUBLIC KEY-----'
