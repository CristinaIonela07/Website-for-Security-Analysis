import std.conv;
import std.digest;
import std.digest.sha;
import std.stdio;
import std.json;
import vibe.d;
import vibe.web.auth;

import db_conn;
static struct AuthInfo
{
@safe:
    string userEmail;
}

@path("api/v1")
@requiresAuth
interface VirusTotalAPIRoot
{
    // Users management
    @noAuth
    @method(HTTPMethod.POST)
    @path("signup")
    Json addUser(string userEmail, string username, string password, string name = "", string desc = "");

    @noAuth
    @method(HTTPMethod.POST)
    @path("login")
    Json authUser(string userEmail, string password);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_user")
    Json deleteUser(string userEmail);

    // URLs management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_url") // the path could also be "/url/add", thus defining the url "namespace" in the URL
    Json addUrl(string userEmail, string urlAddress);

    @noAuth
    @method(HTTPMethod.GET)
    @path("url_info")
    Json getUrlInfo(string urlAddress);

    @noAuth
    @method(HTTPMethod.GET)
    @path ("user_urls")
    Json getUserUrls(string userEmail);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_url")
    Json deleteUrl(string userEmail, string urlAddress);

    // Files management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_file")
    Json addFile(string userEmail, immutable ubyte[] binData, string fileName);

    @noAuth
    @method(HTTPMethod.GET)
    @path("file_info")
    Json getFileInfo(string fileSHA512Digest);

    @noAuth
    @method(HTTPMethod.GET)
    @path("user_files")
    Json getUserFiles(string userEmail);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_file")
    Json deleteFile(string userEmail, string fileSHA512Digest);
}


class VirusTotalAPI : VirusTotalAPIRoot
{
    this(DBConnection dbClient)
    {
        this.dbClient = dbClient;
    }

    @noRoute AuthInfo authenticate(scope HTTPServerRequest req, scope HTTPServerResponse res)
    {
        // If "userEmail" is not present, an error 500 (ISE) will be returned
        string userEmail = req.json["userEmail"].get!string;
        string userAccessToken = dbClient.getUserAccessToken(userEmail);
        // Use headers.get to check if key exists
        string headerAccessToken = req.headers.get("AccessToken");
        if (headerAccessToken && headerAccessToken == userAccessToken)
            return AuthInfo(userEmail);
        throw new HTTPStatusException(HTTPStatus.unauthorized);
    }

    struct auth {
        string _id;
        string AccessToken;
    }

override:

    Json addUser(string userEmail, string username, string password, string name = "", string desc = "")
    {
        auto user = dbClient.addUser(userEmail, username, password, name, desc);
        if (user == DBConnection.UserRet.ERR_NULL_PASS || user == DBConnection.UserRet.ERR_INVALID_EMAIL)
            throw new HTTPStatusException(HTTPStatus.badRequest, "invalid email/password");

        if (user == DBConnection.UserRet.ERR_USER_EXISTS)
            throw new HTTPStatusException(HTTPStatus.unauthorized, "email already exists"); 
   
        if (user == DBConnection.UserRet.OK){
            throw new HTTPStatusException(HTTPStatus.OK, "ok"); 
        }

        throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
    }

    Json authUser(string userEmail, string password)
    {
        auto user = dbClient.authUser(userEmail, password);
        if (user == DBConnection.UserRet.ERR_NULL_PASS || user == DBConnection.UserRet.ERR_INVALID_EMAIL)
            throw new HTTPStatusException(HTTPStatus.badRequest, "invalid email/password");

        if (user == DBConnection.UserRet.ERR_WRONG_PASS || user == DBConnection.UserRet.ERR_WRONG_USER)
            throw new HTTPStatusException(HTTPStatus.unauthorized, "wrong email/password"); 
   
        if (user == DBConnection.UserRet.OK){
            string token = dbClient.generateUserAccessToken(userEmail);
            auth tok;
            tok._id = userEmail;
            tok.AccessToken = token;
            Json jtok = serializeToJson(tok);
            return jtok;
        }
        
        throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
     }

    Json deleteUser(string userEmail)
    {
        auto user = dbClient.deleteUser(userEmail);
        if (user == DBConnection.UserRet.ERR_INVALID_EMAIL)
            throw new HTTPStatusException(HTTPStatus.badRequest, "invalid email");

        if (user == DBConnection.UserRet.OK)
            throw new HTTPStatusException(HTTPStatus.OK, "ok");

        throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
    }

    // URLs management

    Json addUrl(string userEmail, string urlAddress)
    {
        auto url = dbClient.addUrl(userEmail, urlAddress);
        if (url == DBConnection.UrlRet.ERR_EMPTY_URL)
            throw new HTTPStatusException(HTTPStatus.badRequest, "invalid URL");


        if (url == DBConnection.UrlRet.URL_EXISTS || url == DBConnection.UrlRet.OK)
            throw new HTTPStatusException(HTTPStatus.OK, "ok");
        
        throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
    }

    Json deleteUrl(string userEmail, string urlAddress)
    {
        if (urlAddress == null)
            throw new HTTPStatusException(HTTPStatus.badRequest, "invalid URL");
        
        dbClient.deleteUrl(urlAddress);

        throw new HTTPStatusException(HTTPStatus.OK, "ok");
    }

    Json getUrlInfo(string urlAddress)
    {
        auto url = dbClient.getUrl(urlAddress);
        if (url.empty)
            throw new HTTPStatusException(HTTPStatus.notFound, "url not found");
        
        Json jurl = serializeToJson(url);
        return jurl;
    }

    Json getUserUrls(string userEmail)
    {
        auto url = dbClient.getUrls(userEmail);
        Json jurl = serializeToJson(url);
        return jurl;  
    }

    // Files management

    Json addFile(string userEmail, immutable ubyte[] binData, string fileName)
    {
        auto file = dbClient.addFile(userEmail, binData, fileName);
        if (file == DBConnection.FileRet.ERR_EMPTY_FILE)
            throw new HTTPStatusException(HTTPStatus.badRequest, "invalid file");


        if (file == DBConnection.FileRet.FILE_EXISTS || file == DBConnection.FileRet.OK)
            throw new HTTPStatusException(HTTPStatus.OK, "ok");
        
        throw new HTTPStatusException(HTTPStatus.internalServerError, "[Internal Server Error] user action not defined");
    }

    Json getFileInfo(string fileSHA512Digest)
    {
        auto file = dbClient.getFile(fileSHA512Digest);
        if (file.empty)
            throw new HTTPStatusException(HTTPStatus.notFound, "file not found");
        
        Json jfile = serializeToJson(file);
        return jfile;  
    }

    Json getUserFiles(string userEmail)
    {
        auto file = dbClient.getFiles(userEmail);  
        Json jfile = serializeToJson(file);
        return jfile;    
    }

    Json deleteFile(string userEmail, string fileSHA512Digest)
    {
        if (fileSHA512Digest == null)
            throw new HTTPStatusException(HTTPStatus.badRequest, "invalid file");
        
        dbClient.deleteFile(fileSHA512Digest);

        throw new HTTPStatusException(HTTPStatus.OK, "ok");   
    }

private:
    DBConnection dbClient;
}
