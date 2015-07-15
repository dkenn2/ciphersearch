from documents import EncryptedDoc, DocIndex
from pybloom import BloomFilter
from Crypto.Cipher import AES
import re


bf = BloomFilter(capacity=1000, error_rate=0.001)

def build_index(doc, privkeys):
  pass 


#opens a file, reads in the entire document and returns the document
#and a list of every word in the document
def parse_doc(filename):
  wordset = set()
  with open(filename, "r") as file:
    doc = file.read()
    return  doc, list(set(
         ([word.strip(" \n\t\".,") for word in doc.split()])))
        
document, wordlist = parse_doc("quotes")

#then pass document to encrypted document constructor and wordlist and
#doc id to the index constructor (how am i gonna deal with the 2 sets of
#keys?
