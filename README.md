Copyright 2015 David Kennedy

This is an implementation in Python of the version of a secure 
index described by Eu-Jin Goh (2004).  It allows the user to upload
a collection of English language documents to a server in
encrypted form and create a secure index for each document.
The user can search for any given word and retrieve all the 
encrypted documents that contain that word from the server. 
The secure index for a document is created by taking the MAC of
each word in the document twice and inserting the MAC into a bloom
filter.  Documents are retrieved by taking the MAC of the search
word twice and retrieving all documents whose index contains the
result.
