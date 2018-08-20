#!/usr/bin/env python

# https://twitter.com/broken_flag

import sys, time, tweepy

inputData = open('putThisOnTwitter').readlines()

# Consumer Keys
consumerKey    = "wFuneZinJAYeALCjyY05Ol7Tc"
consumerSecret = "6ntPk73uEzQkO2ygDaf2j0oU7iWyCCZJPejxAHyansbTdxDnh7"

# Access Keys
accessToken  = "1027597184185917440-5qoruhv70J6IzOOWFDIPB0rbnj9Kvo"
accessSecret = "nt8suqYhOnrVh92b2WplDfRFKkrnQ3076OJpHaBA8xuRq"

# OAuth process, using the keys and tokens
auth = tweepy.OAuthHandler(consumerKey, consumerSecret)
auth.set_access_token(accessToken, accessSecret)

# Creation of the actual interface, using authentication
api = tweepy.API(auth)

# Creates ~500 tweets, run ONLY ONCE right before the CTF is about to start
#i = 288
#for line in inputData:
#    api.update_status(str(i) + ": " + line)
#    time.sleep(.5)
#    print i
#    i = i-1