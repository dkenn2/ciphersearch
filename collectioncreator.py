import hashlib, os
from documents import EncryptedDoc, DocIndex

class CollectionCreator(object):

  def __init__(self):
    self.next_collection_id = 1
#CHANGE THESE EVENTUALLY TO SAFELY LOOK UP KEYS
    self.ind_key = ("abcd","edfg","aaaa")
    self.enc_key = hashlib.sha256("12345").digest()


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
    pass


  def parse_directory(self, doc_root):
#store in this class and not in doc collection class to hide info
    self.bf_size =  self.calc_bf_size(doc_root) 
    self.next_collection_id += 1
    collection = DocCollection(self.next_collection_id)
#what if collection creation fails? put this in a finally type thing?
    for filename in os.listdir(doc_root):
      with open(doc_root + "/" + filename,"r") as file:

        doc = file.read()
        e_doc = EncryptedDoc(self.enc_key,doc)
        idx = DocIndex(e_doc)
        doc_word_list = self.make_word_set(doc)
        idx.build_index(self.ind_key,doc_word_list)
        collection.add_doc(idx)
    return collection  
    

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
    self.doc_dict[++self.doc_count] = secure_index
  def get_doc(self, doc_id):
    if doc_id > self.doc_count:
      raise KeyError
    return self.doc_dict[doc_id]

    
