import csv

'''
Slightly modified from https://github.com/nyghtowl/Predictive_Txt_Ex
Full credit goes to nyghtowl.
'''

class Trie:
    def __init__(self):
        self.next = {}   # Initialize an empty dict
        self.freq = None # Hold word frequency

    ''' Method to add a string the Trie data structure'''
    def add_item(self, string, frequencies):
        
        if len(string) == 0:
            self.freq = frequencies
            return 
        
        key = string[0]     # Extract first character
        string = string[1:] # Capture remaining string

        # If key exists, recurse through remaining string to add
        if self.next.has_key(key):
            self.next[key].add_item(string,frequencies)
        # Else create new trie with key and then add_item() 
        else:
            node = Trie()
            self.next[key] = node
            node.add_item(string,frequencies)

    '''Perform Depth First Search Traversal'''
    def dfs(self, prediction_dic, so_far=None):
        
        # If node pointing to empty dict, add word to dic
        if not self.next.keys():
            prediction_dic.update({so_far: self.freq})
            return

        # If node containes a frequency, add word to dic
        if self.freq:
            prediction_dic.update({so_far: self.freq})

        # Recursively call dfs for all the nodes pointed by keys in the dict
        for key in self.next.keys():
            self.next[key].dfs(prediction_dic, so_far+key)

    '''Perform auto completion search on submitted string and return results'''
    def search(self, user_input, prediction_dic, so_far=""):
        
        #  Recursively search through user_input(inital letters submitted) to find starting node to pull words
        if len(user_input) > 0:
            key = user_input[0]
            user_input = user_input[1:]
            if self.next.has_key(key):
                so_far = so_far + key
                self.next[key].search(user_input, prediction_dic, so_far)
        else:
            # If word has a freq then add to dic
            if self.freq:
                prediction_dic.update({so_far: self.freq})
            # Depth first search all keys following starting node
            for key in self.next.keys():
                self.next[key].dfs(prediction_dic, so_far+key)

        return prediction_dic


'''Parse text file and apply to Trie'''
def build_trie(file_name, delim):


    # Open file to var so it can be closed
    file_obj = open(file_name)

    # Read file and split values on tab
    row_list = csv.reader(file_obj, delimiter=delim, skipinitialspace=True)

    word_trie = Trie()

    for index, row in enumerate(row_list):
        if row[0][0] != '#': # Ignore comments
            word_trie.add_item(row[0],int(row[1]))


    file_obj.close()

    return word_trie

'''Return a list of predictions only sorted by frequency'''
def predict_words_only(trie_root, user_input, result=None,
        strip_so_far=False, add_freqs=True, no_new=False, max_new_chars=None, num_predictions=None):

    res_dict = predict(trie_root, user_input, dict.fromkeys(result, 0),
        strip_so_far, add_freqs, no_new, max_new_chars, num_predictions)
    return [w for w, f in sorted(res_dict.items(), key=lambda l: l[1], reverse=True)]

'''Return a dictionary of predictions and frequencies, add frequencies
   to result if given'''
def predict(trie_root, user_input, result=None,
        strip_so_far=False, add_freqs=True, no_new=False, max_new_chars=None, num_predictions=None):

    prediction_dic = {} # A dictionary to capture pred words & frequencies
    if result is None:
        result = {}
    counter = 0

    prediction_dic = trie_root.search(user_input, prediction_dic)

    # Truncate the dic keys to the required selection and sum the
    # frequencies of duplicate entries
    if max_new_chars is not None:
        max_new_chars += len(user_input)
    start = len(user_input) if strip_so_far else 0
    for word, freq in prediction_dic.items():
        if num_predictions is None or counter < num_predictions:
            try:
                result[word[start:max_new_chars]] += freq if add_freqs else 0
            except KeyError:
                if not no_new:
                    result[word[start:max_new_chars]] = freq
            counter += 1
        else:
            break

    return result
