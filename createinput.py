from documents import EncryptedDoc, DocIndex
from collectioncreator import CollectionCreator, DocCollection
from Crypto.Cipher import AES
import re, hashlib,sys



def main(argv):
  src_dir = argv[0]
  password = "abcdefg"
  cc = CollectionCreator(password)
#  cc.login_user(argv[1])
  collection = cc.parse_directory(src_dir)
  result = cc.search_coll(collection, "certified")  
  print result
#should get all documents"
  result2 = cc.search_coll(collection,"a")
if __name__ == "__main__":
  main(sys.argv[1:])


