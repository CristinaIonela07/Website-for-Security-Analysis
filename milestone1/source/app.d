import std.algorithm.searching;
import std.conv;
import std.digest;
import std.digest.sha;
import std.range;
import std.stdio;
import std.string;
import std.typecons;

import vibe.db.mongo.mongo : connectMongoDB, MongoClient, MongoCollection;
import vibe.data.bson;

import dauth : makeHash, toPassword, parseHash;

struct DBConnection
{

    MongoCollection users;
    MongoCollection files;
    MongoCollection urls;
    enum UserRet
    {
        OK,
        ERR_NULL_PASS,
        ERR_USER_EXISTS,
        ERR_INVALID_EMAIL,
        ERR_WRONG_USER,
        ERR_WRONG_PASS,
        NOT_IMPLEMENTED
    }
    
    this(string dbUser, string dbPassword, string dbAddr, string dbPort, string dbName)
    {
        string mongo = "mongodb://" ~ dbUser ~ ":" ~ dbPassword ~ "@" ~ dbAddr ~ ":" ~ dbPort;
        
        MongoClient client = connectMongoDB(mongo);
        users = client.getCollection(dbName ~ ".users");
        files = client.getCollection(dbName ~ ".files");
        urls = client.getCollection(dbName ~ ".urls");
    }
    
    
    UserRet addUser(string email, string username, string password, string name = "", string desc = "")
    {
        if (indexOf(email, '@') <1  ||  indexOf(email, '@') >= lastIndexOf(email, '.') - 1  || 
                lastIndexOf(email, '.') > email.length - 2)
            return UserRet.ERR_INVALID_EMAIL;

        else if (password == null)
            return UserRet.ERR_NULL_PASS;

        
        else if (users.findOne(["dbemail" : email]) == Bson(null)){
            users.insert(["dbemail" : email, "dbusername" : username, "dbpassword" : password, 
                            "dbname" : name, "dbdesc": desc]);
            return UserRet.OK;
        }

       else return UserRet.ERR_USER_EXISTS;
    }

    UserRet authUser(string email, string password)
    {
        if (indexOf(email, '@') <1  ||  indexOf(email, '@') >= lastIndexOf(email, '.') - 1  || 
                lastIndexOf(email, '.') > email.length - 2)
            return UserRet.ERR_INVALID_EMAIL;

        else if( password == null)
            return UserRet.ERR_NULL_PASS;

        else if (users.findOne(["dbemail" : email]) == Bson(null))
            return UserRet.ERR_WRONG_USER;
        
        else if (users.findOne(["dbemail" : email, "dbpassword" : password]) != Bson(null))
            return UserRet.OK;
        
        else return UserRet.ERR_WRONG_PASS;
    }

    UserRet deleteUser(string email)
    {
        if (users.findOne(["dbemail" : email]) != Bson(null)){
            users.remove(["dbemail" : email]);
            return UserRet.OK;
        }

        return UserRet.NOT_IMPLEMENTED;
    }

    struct File
    {
        @name("_id") BsonObjectID id; // represented as _id in the db
        string userId;
        ubyte[] binData;
        string fileName;
        string digest;
        string securityLevel;
    }

    enum FileRet
    {
        OK,
        FILE_EXISTS,
        ERR_EMPTY_FILE,
        NOT_IMPLEMENTED
    }

    FileRet addFile(string userId, immutable ubyte[] binData, string fileName)
    {
        if (binData == null)
            return FileRet.ERR_EMPTY_FILE;

        else if (files.findOne(["dbfilename" : fileName]) != Bson(null)){
            return FileRet.FILE_EXISTS;
        }
            
        string dig = digest!SHA512(binData).toHexString().to!string;
        files.insert(["dbuserid": userId, "dbdigest": dig, "dbfilename": fileName]);
        return FileRet.OK;
    }

    File[] getFiles(string userId)
    {
        
        if (files.findOne(["dbuserid": userId]) == Bson(null))
            return null;
        
        File[] file;
        auto result = files.find(["dbuserid": userId]);

        foreach (r; result){  
            File f;
            auto s = files.findOne(["dbuserid" : userId]).toString.split("\"");
               
            for (int i = 0; i < s.length - 2; i++){
                if (s[i] == "dbuserid")
                    f.userId = s[i + 2];

                else if (s[i] == "dbfilename")
                    f.fileName = s[i + 2];

                else if (s[i] == "dbdigest")
                    f.digest = s[i + 2];
            }
            file = file ~ f;          
        }
        return file; 
    }

    Nullable!File getFile(string digest)
    in(!digest.empty)
    do
    {
        if (files.findOne(["dbdigest" : digest]) == Bson(null))
            return Nullable!File();
        
        Nullable!File file = File();
        File f;
        auto result = files.findOne(["dbdigest" : digest]).toString.split("\"");

        for (int i = 0; i < result.length - 2; i++){
            if (result[i] == "dbuserid")
                f.userId = result[i + 2];

            else if (result[i] == "dbfilename")
                f.fileName = result[i + 2];

            else if (result[i] == "dbdigest")
                f.digest = result[i + 2];
        }
        file = f;
        return file;         
    }

    void deleteFile(string digest)
    in(!digest.empty)
    do
    {
        if (files.findOne(["dbdigest": digest]) != Bson(null))
            files.remove(["dbdigest": digest]);
    }

    struct Url
    {
        @name("_id") BsonObjectID id; // represented as _id in the db
        string userId;
        string addr;
        string securityLevel;
        string[] aliases;
    }

    enum UrlRet
    {
        OK,
        URL_EXISTS,
        ERR_EMPTY_URL,
        NOT_IMPLEMENTED
    }

    UrlRet addUrl(string userId, string urlAddress)
    {
        if (urlAddress == null)
            return UrlRet.ERR_EMPTY_URL;

        else if (urls.findOne(["dbuserid" : userId, "dburladdress": urlAddress]) != Bson(null))
            return UrlRet.URL_EXISTS;
        
        else if (urls.findOne(["dbuserid" : userId, "dburladdress": urlAddress]) == Bson(null)){
            urls.insert(["dbuserid": userId, "dburladdress" : urlAddress]);
            return UrlRet.OK;
        }

        return UrlRet.NOT_IMPLEMENTED;
    }

    Url[] getUrls(string userId)
    {
        Url[] url;
        if (urls.findOne(["dbuserid": userId]) == Bson(null))
            return null;

        auto result = urls.find(["dbuserid": userId]);
        foreach (r; result){  
            Url u;
            auto s = urls.findOne(["dbuserid" : userId]).toString.split("\"");
               
            for (int i = 0; i < s.length - 2; i++){
                if (s[i] == "dbuserid")
                    u.userId = s[i + 2];
                    
                else if (s[i] == "dburladdress")
                    u.addr = s[i + 2];
            }
            url = url ~ u;     
        } 
        return url; 
    }

    Nullable!Url getUrl(string urlAddress)
    in(!urlAddress.empty)
    do
    {
        if (urls.findOne(["dburladdress" : urlAddress]) == Bson(null))
            return Nullable!Url();

        Nullable!Url url = Url();
        Url u;
        auto result = urls.findOne(["dburladdress": urlAddress]).toString.split("\"");
        
        for (int i = 0; i < result.length - 2; i++){
                if (result[i] == "dbuserid")
                    u.userId = result[i + 2];
                else if (result[i] == "dburladdress")
                    u.addr = result[i + 2];
        }
        url = u;
        return url;
    }

    void deleteUrl(string urlAddress)
    in(!urlAddress.empty)
    do
    {
        if (urls.findOne(["dburladdress": urlAddress]) != Bson(null))
            urls.remove(["dburladdress": urlAddress]);

    }
}