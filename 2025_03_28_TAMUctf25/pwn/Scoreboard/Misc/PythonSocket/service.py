#!/usr/bin/python3

import sys
import random
from os import environ

flag = environ['flag']

def main():
	target = random.randint(1,100)
	current = 0
	print("Welcome.\nThis game is simple. Ask for numbers until you get to {}.\n".format(target))
	while True:
		print("CURRENT = {}.\nWhat do you want?\n- A number (type MORE)?\n- Or are you done (type FINISH)?".format(current))
		sys.stdout.flush()
		try:
			string = input('')
		except EOFError:
			sys.exit()
		if 'MORE' == string:
			if target >= current:
				new = random.randint(1, target-current + 5)
			else:
				new = random.randint(-(current-target)-5, 5)
			print("Here you have: {}\n".format(new))
			current += new
		elif 'FINISH' == string and current == target:
			print("GREAT JOB: {}".format(flag))
			sys.exit()
		elif 'FINISH' == string:
			print("You missed it. Target = {}. Your score = {}".format(target, current))
			sys.exit()
		else:
			print('NOT VALID OPTION')
	
main()
