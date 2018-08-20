#!/usr/bin/env python

import os, tweepy
 
consumer_key    = 'wFuneZinJAYeALCjyY05Ol7Tc'
consumer_secret = '6ntPk73uEzQkO2ygDaf2j0oU7iWyCCZJPejxAHyansbTdxDnh7'

access_token    = '1027597184185917440-5qoruhv70J6IzOOWFDIPB0rbnj9Kvo'
access_secret   = 'nt8suqYhOnrVh92b2WplDfRFKkrnQ3076OJpHaBA8xuRq'
 
auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
auth.set_access_token(access_token, access_secret)
 
api = tweepy.API(auth)

mystr = ""

for status in tweepy.Cursor(api.user_timeline, screen_name='@Broken_Flag').items():
    mystr += status._json["text"].split(" ")[1] + "\n"

f = open("flag.hd", "w")
f.write(mystr)
f.close()

os.system("xxd -p -r flag.hd > flag")
os.system("rm flag.hd")
os.system("chmod +x flag")
os.system("./flag")