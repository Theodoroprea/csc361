# ------------------------- #
# Assignment 1 - CSC 361    #
# Theodor Oprea - V00888686 #
# ------------------------- #

import socket
import sys
import re
import ssl

https = None
passing = 0
# ------------------------------------- #
# Function that will attempt connecting #
# to the specified url, either wrapped  #
# or not, on port 443 or 80.            #
# ------------------------------------- #
def createAndConnectSocket(url, https):

    try:
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print("Something went wrong with the creation of the socket, please try again.")
        sys.exit()

    if https:
        try:
            mySocket.connect((url,443))
        except socket.error:
            return mySocket
        try:
            wrappedSocket = ssl.wrap_socket(mySocket)
            return wrappedSocket
        except ssl.SSLError:
            print ("There was a problem wrapping the socket, please try again.")
            raise Exception
    else:
        try:
            mySocket.connect((url,80))
            return mySocket
        except socket.error:
            print("There was an issue connecting. View error and try again.")
            raise Exception

    return mySocket

# ------------------------------------------------------- #
# Send a request to the specified url, with the uri given #
# ------------------------------------------------------- #
def sendRequest(url, uri, https):

    if uri == "":
        uri = "/"
    #We try to create a socket and then connect to it using https, so wrapping the socket and port 443.
    mySocket = createAndConnectSocket(url, https)
    #If we come back here and we have no connection, then we try again using http, without wrapping the socket and port 80.
    #if mySocket.fileno() == -1:
    #    mySocket = createAndConnectSocket(url, False)

    if mySocket.fileno() == -1:
        raise ValueError("Something really bad happened. Unable to connect to the url given.")

    #HEAD is pretty much the same thing as GET, without the body. Nicer to work with.
    request = (f"HEAD {uri} HTTP/1.1\r\nHost: {url}\r\n\r\n")
    mySocket.sendall(request.encode())

    #We are connected and a request has been sent, we are now retrieving the response.
    resp = b""
    while True:
        try:
            data = mySocket.recv(4096)
            #If there is no more data, we get out of this loop.
            if not data:
                break
            resp += data
        except socket.timeout:
            break

    mySocket.close()
    return resp.decode()

# -------------------------------- #
# Check if website supports http2. #
# -------------------------------- #
def checkHttp2Support(url, https):

    sslSettings = ssl.SSLContext(ssl.PROTOCOL_TLS)
    sslSettings.set_alpn_protocols(['h2'])
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #Let's connect attempting with https, port 443
    if https:
        try:
            wrappedSocket = sslSettings.wrap_socket(mySocket, server_hostname = url)
            wrappedSocket.connect((url, 443))
            if wrappedSocket.selected_alpn_protocol() == "h2":
                return "yes"
            else:
                return "no"
        except ssl.SSLError:
            return "problem"
    #Let's connect attempting with http, port 80
    else:
        return "no"

# ---------------------------------------------- #
# Check the status code of the returned response #
# Act accordingly. Redirect if needed.           #
# ---------------------------------------------- #
def checkStatusCode(url, uri, resp):

    #global https
    global passing
    #Using regex we can find the status code required. Since, it return a tuple. we need to convert the String in an int after extracting it from the tuple.
    statusCode = re.search(r"^(HTTP/1.[0|1])\s(\d+)", resp)
    statusCode = int(statusCode[2])

    #Redirect for 302 or 301
    while statusCode == 302 or statusCode == 301:
        print("\nRedirecting. Still working...\n")
        newFullUrl = re.search(r"Location: (?:https?:\/\/)?(.*)", resp)
        newFullUrl = newFullUrl[1]
        httpHttps = re.search(r"Location: (https?)?.*", resp)[1]

        checkHttp(httpHttps)
        splitNewUrlUri = newFullUrl.split("/")
        newUrl, newUri = urlUriHelper(splitNewUrlUri)

        resp = sendRequest(newUrl, newUri, https)
        statusCode = re.search(r"^(HTTP/1.[0|1])\s(\d+)", resp)
        statusCode = int(statusCode[2])

    if statusCode == 404:
        #We need this because since we off the bat try to run with https, if htto/https is not provided in the url
        #Then if a website is http, it's https counterpart will not exist, so we try with http after trying https.
        if passing == 1:
            raise ValueError("We encountered an error 404. The url you have entered does no exist. Please try again.")
        passing = 1
        #https = True
        resp = sendRequest(url, uri, False)
        newResponse = checkStatusCode(url, uri, resp)
        return newResponse
    elif statusCode == 505:
        raise ValueError("We encountered an error 505. The server encountered an internal error or misconfiguration. Probably: HTTP version is not supported, 1.1 used.")
    elif statusCode == 503:
        raise ValueError("We encountered an error 505. This service is unavailable at the moment. Probably: Maintenance.")

    return resp

# ------------------------------------------------ #
# Bake cookies will just run through the HEAD      #
# response, and extract all the cookies using      #
# regex.                                           #
# ------------------------------------------------ #
def bakeCookies(response):

    responseLines = response.splitlines()
    cookieCount = 0

    for i in responseLines:
        fullCookie = ""
        cookieName = re.search(r"Set-Cookie: (.*?)=.*;", i)
        if cookieName != None :
            cookieCount += 1
            fullCookie = "Cookie name: " + cookieName[1]

        cookieExpiry = re.search(r"expires=(.+?);.*", i)
        if cookieExpiry != None:
            fullCookie = fullCookie + ", expiry: " + cookieExpiry[1]

        cookieDomain = re.search(r"[D|d]omain=(.+?);", i)
        if cookieDomain != None:
            fullCookie = fullCookie + ", domain name: " + cookieDomain[1]

        if fullCookie != "":
            print(fullCookie)

    if cookieCount == 0:
        print("There were no cookies.")

# ------------------------------------------------ #
# Given the url and uri, we can send a POST to the #
# url with the uri, if returned 401, then we have  #
# a password-protected website.                    #
# ------------------------------------------------ #
def checkProtection(url, uri, https):

    mySocket = createAndConnectSocket(url, https)
    #If we come back here and we have no connection, then we try again using http, without wrapping the socket and port 80.
    if mySocket.fileno() == -1:
        mySocket = createAndConnectSocket(url, https)

    if mySocket.fileno() == -1:
        raise ValueError("Something really bad happened. Unable to connect to the url given.")

    request = (f"POST {uri} HTTP/1.1\r\nHost: {url}\r\n\r\n")
    mySocket.sendall(request.encode())

    resp = b""
    while True:
        try:
            data = mySocket.recv(4096)
            #If there is no more data, we get out of this loop.
            if not data:
                break
            resp += data
        except socket.timeout:
            break

    statusCode = re.search(r"^(HTTP/1.[0|1])\s(\d+)", resp.decode())
    statusCode = int(statusCode[2])
    if statusCode == 401:
        return "yes"
    return "no"

# ------------------------------------------------ #
# Simple helper method to extract the url, as well #
# as the uri.                                      #
# ------------------------------------------------ #
def urlUriHelper(myList):

    url = myList[0]
    myList.pop(0)
    uri = ""
    for i in myList:
        i = i.strip()
        if i == "":
            uri = uri + "/"
        elif i == "/":
            continue
        else:
            uri = uri + "/" + i
    return url, uri

# --------------------------------------------- #
# Helper method that just checks if a string is #
# http or https.                                #
# --------------------------------------------- #
def checkHttp(httpHttps):

    global https
    if httpHttps == None or httpHttps == "https":
        https = True
    else:
        https = False

def main():

    urlUri = re.search(r"(?:https?:\/\/)?(.*)",sys.argv[1])[1]
    httpHttps = re.search(r"(https?)?.*",sys.argv[1])[1]
    checkHttp(httpHttps)
    splitUrlUri = urlUri.split("/")
    url, uri = urlUriHelper(splitUrlUri)
    if urlUri == url:
        print(f"Connecting to website: \"{url}\"")
    else:
        print(f"Connecting to host: \"{url}\"\nWebsite: \"{urlUri}\"")

    #For some reason, I need this "setdefaulttimeout" in order to make sure that during sendRequest,
    #it ends the while loop, for SOME websites such as google.com. I tried to use settimeout(5)
    #within the function, but no luck. I also tried .setblocking(False) with no luck either.
    socket.setdefaulttimeout(5)
    response = sendRequest(url, uri, https)
    newResponse = checkStatusCode(url, uri, response)
    if newResponse != response:
        response = newResponse

    http2Support = checkHttp2Support(url, https)
    print(f"1. Supports http2: {http2Support}")

    print(f"2. List of Cookies:")
    bakeCookies(response)

    protectionResponse = checkProtection(url, uri, https)
    print("3. Password-protected: " + protectionResponse)

if __name__ == "__main__":
    main()
