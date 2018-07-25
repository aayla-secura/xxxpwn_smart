A fork of xxxpwn (`https://github.com/feakk/xxxpwn`) adding further optimizations and tweaks. Uses predictive text based on a dictionary of words/phrases vs frequencies of occurence (incorporated from `https://github.com/nyghtowl/Predictive_Txt_Ex`).

Differences from xxxpwn:
  * Predictive text
  * Multithreading not working yet (TO DO)
  * Detect if HTTP, only change headers if HTTP (and if double newline
  * is present, do not match header names in body)
  * Limit the number of characters to get for a node/attribute name
  * Limit the number of characters to get for a node/attribute contents
  * Allow IP instead of hostname (Host header will not be updated)
  * Match on content length (min/max/exact) instead of string
  * Match string only in headers/body
  * Reverse match (match indicates fail)
  * Disable prediscovery of string length of values (gets a character until it detects the end of the string instead)
  * Match node/attribute names only for previously seen ones at the current node level
	* A preferred character set (try first, before the rest)
	* Guess if node is numeric based on a regex; use a different preferred character set for those

FAQ:
  * *Why `_smart`?* 'Cause everything nowadays is either smart or quantum, and quantum doesn't make sense here.
