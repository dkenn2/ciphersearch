from documents import EncryptedDoc, DocIndex
from collectioncreator import CollectionCreator, DocCollection
from Crypto.Cipher import AES
import re, hashlib,sys


#bf = BloomFilter(capacity=1000, error_rate=0.001)

def main(argv):
  src_dir = argv[0]
  cc = CollectionCreator()
  collection = cc.parse_directory(src_dir)
  

if __name__ == "__main__":
  main(sys.argv[1:])


#opens a file, reads in the entire document and returns the document
#and a list of every word in the document
#def parse_doc(filename):
#  with open(filename, "r") as file:
#    doc = file.read()
#    return  doc
        
#document = parse_doc("quotes")
#print document
#key = hashlib.sha256("12345").digest()

#then pass document to encrypted document constructor and wordlist and
#doc id to the index constructor (how am i gonna deal with the 2 sets of
#keys?
#ed = EncryptedDoc(key, document)
#pd = ed.decrypt_and_return(key)
#print pd
#idx = DocIndex(ed)
#idx.build_index(("abcd","edfg","aaaa"),document)
#print "encrypted document", idx.get_document().decrypt_and_return(key)
#print idx.search_index("certified", ("abcd", "edfg","aaaa"))
