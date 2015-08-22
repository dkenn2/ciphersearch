import hashlib, os
from documents import EncryptedDoc, DocIndex

class CollectionCreator(object):

  def __init__(self):
    self.next_collection_id = 1
#CHANGE THESE EVENTUALLY TO SAFELY LOOK UP KEYS
    self.ind_key = ("abcd","edfg","aaaa")
    self.enc_key = hashlib.sha256("12345").digest()
    self.bf_size = 0

  def make_word_set(self, document):
    return list(set( [
                        word.strip(" \n\t\".,")
                        for word in document.lower().split()
                      ]))

     
  def calc_bf_size(self,doc_root):
    """Will calculate a size to make the bloom filter for
       each document.  The size of each bloom filter in the
       collection is the number of bits needed to easily accomodate 
       the document in the collection with the most words"""
    dir = doc_root + "/"
    most_bytes = 0;
    for file in os.listdir(dir):
      len = os.path.getsize(dir + file)
      if len > most_bytes:
        most_bytes = len

    return most_bytes / 8 

  def parse_directory(self, doc_root):
    print "Now building secure indexes for documents in .\\" + doc_root
    self.bf_size =  self.calc_bf_size(doc_root)
    print "Bloom filter size is ",  self.bf_size, "bits"
    self.next_collection_id += 1
    collection = DocCollection(self.next_collection_id)
#what if collection creation fails? put this in a finally type thing?

    for filename in os.listdir(doc_root):
      with open(doc_root + "/" + filename,"r") as file:

        doc = file.read()
        e_doc = EncryptedDoc(self.enc_key,doc)
        idx = DocIndex(e_doc)
        doc_word_list = self.make_word_set(doc)

        idx.build_index(self.ind_key,doc_word_list, self.bf_size)
        collection.add_doc(idx)
    return collection  

#pass collection to this class from main because this class
#is responsible for managing keys
  def search_coll(self, collection, word):
      plaintext_list = []
      encrypted_list = collection.search_collection(word, self.ind_key)
      for document in encrypted_list:
        plaintext_list.append(document.decrypt_and_return(self.enc_key))
      return plaintext_list
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
    self.doc_count += 1
    self.doc_dict[self.doc_count] = secure_index
    print "Finished creating index for document ", self.doc_count

  def search_collection(self, word, privkeys):
    enc_doc_list = []
    for doc_id in self.doc_dict.keys():
     print "Searching Document ",  doc_id
     if self.doc_dict[doc_id].search_index(word, privkeys):
       enc_doc_list.append(self.doc_dict[doc_id].get_document())
       print" \'" + word + "\' in document"
    return enc_doc_list
      
    
