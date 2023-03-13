# Website for Security Analysis

Milestone 1 - Implementing the backend

The backend implements a database where all of the information is stored. We want to track down information about users, files and URLs. As a consequence, we will be using a database where we will define 3 collections:

The users collection which stores the following fields:
an email address - a string that represents the unique identifier of user;
a username - a string that represents the actual name that is publicly posted for a user;
a password - a string that represents the encrypted password for a user;
a name - an optional string field that represents the real name of the user;
a description - an optional string field that represents the description of the user (hobbies, passions etc.).

The files collection which stores the following fields:
a file id - a number that represents the unique identifier for an entry in this collection;
a user id - a string that contains the email address of the user that added this file;
the file contents - a ubyte[] that stores the bytes of the file;
a hash of the file - a string that contains the result of applying a hash function to the file contents;
threat level - a number representing the degree of maliciousness of the file;

The URLs collection which stores the following fields:
a URL id - a string that represents the unique identifier for an entry in this collection;
a user id - a string that contains the email address of the user that added this URL;
an address - a string that contains the actual URL (e.g. “www.google.com”);
a security level - a number representing the degree ofm maliciousness of the URL;
a list of aliases - a string[] that contains different aliases for this website;

The database is implemented using mongo-db. On top of mongo-db we will be using the vibe-d framework, which is a a high-performance asynchronous I/O, concurrency and web application toolkit written in D. By using vibe-d we will be able to both implement the database and create the server (for milestone 2).

Milestone 2 - Implementing the web API

Each of the following functions will forward the request to the backend and, depending on the response, creates the JSON object and the response code. If the request is successful, the web API function should return a JSON object, as described below. Unless otherwise stated, for a successful query you need to return a JSON object that contains an informative text of your choosing. To pack any kind of data into a JSON object, simply use the serializeToJson function. For situations where the query has failed you must throw an HTTPStatusException.
