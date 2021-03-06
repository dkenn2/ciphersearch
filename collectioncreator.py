# Copyright 2015 David Kennedy
# Project name: ciphersearch
# Project url: https://github.com/dkenn2/ciphersearch
# [This program is licensed under the "MIT License"]
# Please see the file LICENSE in the source
# distribution of this sotware for license terms.

import hashlib, os, random
from binascii import hexlify, unhexlify
from pbkdf2 import PBKDF2, crypt
from documents import EncryptedDoc, DocIndex

class CollectionCreator(object):

  def __init__(self,  password):
    self.next_collection_id = 1


    self.enc_key = hashlib.sha256(password).digest()
    self.ind_key = self.create_or_load_keys(32, 5,password)
    self.bf_size = 0
   
  def make_word_set(self, document):
    return list(set( [
                        word.strip(" \n\t\".,")
                        for word in document.lower().split()
                      ]))

  def create_or_load_keys(self, keylen, num_keys, pw):
   
    user_keys = [] 
    rand_filename = hashlib.sha224(pw).hexdigest()

    if self.user_keys_exist(rand_filename):
      print "Loading already existing keys for this user"
      user_keys = self.load_master_key_from_file(rand_filename)    

    else:
      print "Creating ", num_keys, " keys from this user's password and saving keys to a file"
      user_keys = self.create_user_keys(num_keys,pw,keylen) 
      os.mkdir(rand_filename) 
      with open(os.path.join(rand_filename,"keys"),'w') as key_file:
        for k in user_keys:
          key_file.write(hexlify(k) + "\n")

    return tuple(user_keys)
 
  def user_keys_exist(self,pw_hash):
      if os.path.isdir(pw_hash):
        return True
      return False

  def create_user_keys(self, num_keys,pw,keylen):
#    pw_hash = crypt(pw)
    index_keys = []
   
    for i in range(num_keys):
      this_iter_salt = os.urandom(8)
      this_iter_key = PBKDF2(pw, this_iter_salt).read(keylen)  
##      print "^^^^ ", len(this_iter_key), this_iter_key
     
      index_keys.append(this_iter_key)
       


    print "ORIGINAL KEYS", index_keys
    return index_keys 
   


  
#actually this will be very different bc only storing the master key
#and generating these keys from the master key. 
  def load_master_key_from_file(self, random_filename):
#this code adapted from pbkdf2 documentation
#    key = PBKDF2(password, self.salt).read(32)
#DUMMY: CHANGE TO WORK WITH CODE LINE(S) ABOVE
    master_keys = []
    with open(os.path.join(random_filename,"keys"), 'r') as key_file:
      for key in key_file:
        master_keys.append(unhexlify(key.rstrip()))    
    print "KEYS ON FILE", master_keys
    return master_keys

  def calc_bf_size(self,src_dir):
    """Will calculate a size to make the bloom filter for
       each document.  The size of each bloom filter in the
       collection is the number of bits needed to easily accomodate 
       the document in the collection with the most words"""
    dir =  src_dir + "/"
    most_bytes = 0;
    for file in os.listdir(dir):
      length = os.path.getsize(dir + file)
      if length > most_bytes:
        most_bytes = length
    num_keys = len(self.ind_key)
    
    return (most_bytes * max(1,(num_keys / 3))) / 8 

  def parse_directory(self, doc_root):
    print "Now building secure indexes for documents in .\\" + doc_root
    self.bf_size =  self.calc_bf_size(doc_root)
    print "Bloom filter size is ",  self.bf_size, "bits"
    self.next_collection_id += 1
    collection = DocCollection(self.next_collection_id)
#what if collection creation fails? put this in a finally type thing?

    max_words_any_doc = 0
#used to keep track of the number of words in each document locally for
#later processing while blinding the index without storing this information
#with the index
    doc_word_counts = []
    for filename in os.listdir(doc_root):
      with open(doc_root + "/" + filename,"r") as file:

        doc = file.read()
        e_doc = EncryptedDoc(self.enc_key,doc)
        idx = DocIndex(e_doc)
        doc_word_list = self.make_word_set(doc)
        max_words_any_doc = max(len(doc_word_list), max_words_any_doc)
        doc_word_counts.append(len(doc_word_list))
        print "DOC LENGTH IS ", len(doc_word_list), " words"
        print max_words_any_doc, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
#If the order of the following two lines of code was reversed, this
#program would not work.  That is because a document only has an identifier
#relative to the collection it was most recently added to, and an index
#can not be built without a doc identifier
        collection.add_doc(idx)
        idx.build_index(self.ind_key,doc_word_list, self.bf_size)
    print "WORD COUNTS ARRAY:", doc_word_counts
    for i in range(1, collection.collection_size()+1):
      collection.get_doc(i).blind_index(self.ind_key,max_words_any_doc - doc_word_counts[i-1]) 
    return collection  

#pass collection to this class from main because this class
#is responsible for managing keys
  def search_coll(self, collection, word):
      plaintext_list = []
      encrypted_list = collection.search_collection(word, self.ind_key)
      for document in encrypted_list:
        plaintext_list.append(document.decrypt_and_return(self.enc_key))
#Uncomment following line to test that filter false positives works right
      plaintext_list.append("WAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
      plaintext_list = self.filter_false_positives(plaintext_list, word)
      return plaintext_list

  def filter_false_positives(self, documents, searchword):
    filtered_doc_list = []
    for doc in documents:
      if searchword in doc:
        print "HHHHHHHHHHHHHHHHHHHHHHH"
        filtered_doc_list.append(doc)
      else:
        print "FOUND A FALSE POSITIVE", doc
    return filtered_doc_list
#DOES THIS CLASS NEED TO KNOW ANYTHING ELSE TO SEARCH BLOOM FILTER?
#I DONT THINK SO BUT
class DocCollection(object):
  """This class stores a collection of secure indexes that
  have links to their respective encrypted documents.  This
  class and the objects it contains holds as little information
  as possible about the collection. All the user learns from
  this class is the number of documents in the collection and a
  unique collection identifier.  Because of security requirements,
  the secure index should be built and the document encrypted before
  being added to the collection"""
  def __init__(self, collection_id):
    self.collection_id = collection_id
    self.doc_count = 0
    self.doc_dict = {}

  def add_doc(self, secure_index):
#this line means that a document identifier is per collection, ie a
#doc would have two different ids in two diff collections
    self.doc_count += 1
    secure_index.set_doc_id(self.doc_count)
    self.doc_dict[self.doc_count] = secure_index

  def get_doc(self, doc_id):
   
    return self.doc_dict[doc_id]

  def collection_size(self):
    return self.doc_count

  def search_collection(self, word, privkeys):
    enc_doc_list = []
    for doc_id in self.doc_dict.keys():
     print "Searching Document ",  doc_id
     if self.doc_dict[doc_id].search_index(word, privkeys):
       enc_doc_list.append(self.doc_dict[doc_id].get_document())
       print" \'" + word + "\' in document"
    return enc_doc_list
      
    
