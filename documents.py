from Crypto.Cipher import AES
from pybloom import BloomFilter
from os import urandom
import hashlib, hmac, base64
#constructor takes as argument an unencrypted document, encrypts and 
#stores it in the object and generates a unique document ID.  It also
#takes as argument the user's password and translates this into a symmetric
#key of 32   but does not store the key
#in the object
class EncryptedDoc:
  def __init__(self, key, plaindoc):

#NEED to have a different IV for each encrypted doc
    self.encrypt(key, plaindoc)
#this allows us to test whether docID equals None so that we can set this
#variable only once
    self.docId = None
    self.make_doc_id()
#make sure you don't accidentally store the plaintext in an instance variable
#keep it like you do it in the self.cryptdoc line (padplain in nested function call)
#uses PKCS7
  def pad_plain(self, plaintext):
    padlen =  16 - (len(plaintext) % 16) 
    return plaintext + padlen*chr(padlen)
  def unpad(self,crypt):
    return crypt[0:-ord(crypt[-1])]
  def make_doc_id(self):
    if self.docId is None:
      self.docId = 1
    
  def get_doc_id(self):
    return self.docId

#this is a wrapper for the pycrypto encryption function
  def encrypt(self, key,plaintext):
    #iv should be diff each time we encrypt right?
    iv = urandom(16)
    print iv
    plaintext = self.pad_plain(plaintext)
    AESObj = AES.new(key, AES.MODE_CBC, iv)
    self.cryptdoc = base64.b64encode(iv + AESObj.encrypt(plaintext))    

#the signature of this function is dependent on how I create the private
#info class...the private info class can not be a member of this class
#because this class is sent to the server which should not know this info
#maybe in the constructor call something like create private info class.
#then store this private info class on disk.  Then every time the private
#info class needs to be used it will try to bring this file in from disk.
#these functions should not work 
  def decrypt_and_return(self, key):
   ciphertext = base64.b64decode(self.cryptdoc)
   iv = ciphertext[:16]
   AESObj = AES.new(key, AES.MODE_CBC, iv)
   return self.unpad(AESObj.decrypt(ciphertext[16:]))
   

#will be called every time the info in privatekeysobject is needed.  Should this
#call be here really?  I think a better place would be in the main so the info
#could be used by both the encrypted doc and secure index classes.  But then
#there would need to be some function to load that into this class
#  def loadPrivateKeysObject(self, filepath):
#    pass


#constructor takes as argument the document ID generated when creating
#the document and the document itself."
#globally unique collection id too....
class DocIndex:
  def __init__(self, cryptdoc):
#should I add a collection ID?  probably!!!!!!!!!!!!!!!!!!!!!!!



#fix this to make it safe
    self.docId = cryptdoc.get_doc_id()
    self.cryptDoc = cryptdoc
    self.index = None
    self.secureIndex = self.make_index()
  def get_doc_id(self):
    return self.cryptDoc.get_doc_id()

#add some logic later so only gives you doc if you should get it?  or
#does it not matter bc its encrypted?
  def get_document(self):
    return self.cryptDoc
#for now this is a member function but it really should be called not from
#within the class but only by the user because the class is not being made
#responsible for finding the keys...the user should supply the keys...also
#dont want to store the keys nor the word list in the index, only use them 
#to create the indexi
  def build_index(self, privKeysTup, document):
#can not be a member var, also can't in clude word count
    docWordList = self.make_word_set(document)


    print str(docWordList)

#this maybe should be done in constructor, max value for all elements in
#the collection? what I am doing here gives away length of document I think
#right?
    self.index = BloomFilter(capacity=len(docWordList)*4, error_rate=0.001) 
#^THINK ABOUT HOW TO GET THIS RIGHT OF MAKING IT JUST A BIT BIGGER THAN NEED BE
#but no maybe all bloom filters need to be size of largest doc
    numWords = len(docWordList)
#this is just to keep the copies around to test for right behavior
    finalmacs = []
    hmacs_rnd1 = [hmac.new(key, '', hashlib.sha1) for key in privKeysTup]
    doc_identifier = self.get_doc_id()
    print "Original Hmacs", hmacs_rnd1
    for word in docWordList:
      print "Now Processing: ", word, "\n"
      trpdrs = []
      codewrds = []
      mac_copies_rnd1 = [obj.copy() for obj in hmacs_rnd1]
      print "Initial Copies", mac_copies_rnd1 
      
      updated_copies_rnd1 =  map(self._hmac_update, 
                            mac_copies_rnd1, [word] * len(mac_copies_rnd1))
                
      print "Updated Copies", updated_copies_rnd1 

#digest or HEXDIGEST? DIGEST HERE IS BETTER BUT HEXDIGEST BETTER FOR PUTTING
#IN BF? 
      trpdrs = [obj.digest() for obj in updated_copies_rnd1]
      print trpdrs
#rnd 2 can't benefit from copying bc each call uses a different key
      hmacs_rnd2 = [hmac.new(key, '', hashlib.sha1) for key in trpdrs]
      print "RND 2 HMACS)", hmacs_rnd2


#THIS IS VERY BAD HOW IM JUST CASTING AN INT TO A STRING HERE MAYBE HAVE THE DOCID BE A STRING?
#OR YOU GET A HASH OF THE DOC ID?
      updated_copies_rnd2 =  map(self._hmac_update, 
                                hmacs_rnd2, [str(doc_identifier)] * len(hmacs_rnd2))
#!!!!!!!!!!!!!!!!!!!!FIX!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!doc_identifier

      codewrds = [obj.hexdigest() for obj in updated_copies_rnd2]
      print "HERES TO PUT IN BLOOM FILTER", codewrds               
     #this is to test if new mac objs all the time, seem reusing address and not reusing object which is what
     #i want but if I save these objs to finalmacs ill get an answer on that hypothesis one way or the other

      finalmacs.extend(updated_copies_rnd1)

      self.add_word_to_index(codewrds)    
#probably super bad form what im doing her
  def _hmac_update(self, macobj, string):
    print "AAAAAAAAAAAAAAAAAAAAAAA", macobj
    macobj.update(string)
    return macobj

  def make_word_set(self, document):
     return list(set( [
                        word.strip(" \n\t\".,")
                        for word in document.lower().split()
                      ]))

  def add_word_to_index(self, codewords):
    if self.index is None:
      raise Exception('Path not yet implemented')
    else:
      for word in codewords:
        self.index.add(word)
  
  def search_index(self, word, privKeysTup):
    hmacs_rnd1 = [hmac.new(key, '', hashlib.sha1) for key in privKeysTup]
    doc_identifier = self.get_doc_id()
    updated_copies_rnd1 =  map(self._hmac_update, 
                            hmacs_rnd1, [word] * len(hmacs_rnd1))
    trpdrs = [obj.digest() for obj in updated_copies_rnd1]
    hmacs_rnd2 = [hmac.new(key, '', hashlib.sha1) for key in trpdrs]
    updated_copies_rnd2 = map(self._hmac_update, hmacs_rnd2, 
                             [str(doc_identifier)] * len(hmacs_rnd2))
    codewrds = [obj.hexdigest() for obj in updated_copies_rnd2]
    return all([(wrd in self.index) for wrd in codewrds])

  def make_index(self):
    return 1


