
This presents an API for initiating OAuth requests to github and then redirecting back to the calling application.  This was created as the part of the Dart-Pad GitHub authorization interface but could be used for initiating OAuth authorization from any app.

(note: provided scripts are provided in .sh and .bat versions for corresponding platforms)

When testing locally it will require certificates to be generated so that it can create an HTTPS server.  The `tool/makeLocalhostCertificates` scripts will do this automatically.  OpenSSL must be installed to use this script.

A OAuth application must be registered with GitHub and the `CLIENT_ID` and `CLIENT_SECRET` must be stored in enviromental variables to make then available to dart code server.

The `tool/setEnvironmentalVars` scripts can be edited with the GitHub assigned values and used to set the required environmental variables.  Once the `setEnvironmentalVar` contain secrets the `.gitignore` and `.dockerignore` files should be edited to exclude these files (there are lines that can be uncommented to accomplish this).

When the server is run it will report the environmental variables found, and will exit if the required environmental variables are not found.  The CLIENT_ID and CLIENT_SECRET are masked to last 4 digits to protect the secrets.


- Listens on "any IP" (0.0.0.0) instead of loop-back (localhost, 127.0.0.1) to
  allow remote connections.
- Defaults to listening on port `8080`, but this can be configured by setting
  the `PORT` environment variable. (This is also the convention used by
  [Cloud Run](https://cloud.google.com/run).

Essentially just 'gcloud run deploy --source .' will deploy 

To run this server locally:

To created certificates to run local https server for testing
(This is done once, and the generated `certificates/CA/CA.pem` file should be added to your browsers trusted certificate authorities to prevent warnings)

```bash
$ ./makeLocalhostCertificates.sh
```

-To setup GitHub OAuth App go to https://github.com/settings/developers
1) Select 'OAuth Apps' on left side of screen.
2) Select 'New OAuth App' button on upper left
3) `Application Name` => 'Dart-Pad GitHub Gist Auth Endpoint'  (or whatever..)
4) `Homepage URL` - `https://localhost:8000` (or this can be the server/homepage where your dartpad runs)
5) `Authorization callback URL` - This is the IMPORTANT one - this will be
  `https://localhost:8080/authorized` for the OAuth app used for testing locally.  (or if you change the port modify accordingly)
6) Do NOT check 'Enable Device Flow'

You will then need to copy the Client ID provided and choose to generate a client secret and copy that as well.  The `setEnvironmentalVars` batch files should be edited with these values.  
You will repeat this process when making Client ID/Secret for the server running in the cloud.  The cloud endpoint URL will be specified for the `Authorization callback URL` for the new OAuth app.
The `AUTH_RETURN_URL` and `RETURN_TO_APP_URL` environmental variables can be used locally, but they will be assigned default values, but when running on google cloud run these should be set accordingly.



Edit the `setEnvironmentalVars` script with the client secrets.  Edit .dockerignore and .gitignore to exclude the edited scripts.

```bash
$ ./setEnvironmentalVars.sh
$ dart run bin/server.dart
```

Upon executing the server.dart file you will get a report of the environmental variables found and details about where the server is serving.  Connections will be logged to the console as the server runs, Ctrl-C to kill the server.

Example output:
```bash
AUTH_RETURN_URL environmental variable not set - defaulting to "https://localhost:8080/authorized"
RETURN_TO_APP_URL environmental variable not set - defaulting to "http://localhost:8000/index.html"
Got ENV CLIENT_ID=XXXXXXXXXXXXXXXXcaf3
Got ENV CLIENT_SECRET=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXb33f
Got ENV LOCAL_DEBUG=true
Got ENV AUTH_RETURN_URL=https://localhost:8080/authorized
Got ENV RETURN_TO_APP_URL=http://localhost:8000/index.html
Serving at http://0.0.0.0:8080
Redirecting to GITHUB authorize
2022-04-06T08:04:16.205497  0:00:00.023894 GET     [302] /initiate/iVBeyVWI7ABLCTudTcKiRrvdLLEYqaRb52XqLwYz
Entered _returnAuthorizeHandler
success - redirecting back to app
2022-04-06T08:04:16.528620  0:00:00.525369 GET     [302] /authorized?code=01e8c9472302a20a7e23&state=iVBeyVWI7ABLCTudTcKiRrvdLLEYqaRb52XqLwYz

```


More background details about deploying Google Cloud Run can be found on [Cloud Run](https://cloud.google.com/run), follow
[these instructions](https://cloud.google.com/run/docs/quickstarts/build-and-deploy/other).
