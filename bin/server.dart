// Copyright (c) 2021, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

//
// This presents an API for initiating OAuth requests to github and then
// redirecting back to the calling application.  This was created as the
// part of the Dart-Pad GitHub authorization interface but could be used
// for initiating OAuth authorization from any app.
//
// When testing locally it will require certificates to be generated so that
// it can create an HTTPS server.  The tool/makeLocalhostCertificates scripts
// will do this automatically.
//
// A OAuth application must be registered with GitHub and the CLIENT_ID and
// CLIENT_SECRET must be stored in enviromental variables.
//
// The tool/setEnvironmentalVars scripts can be edited with the GitHub
// assigned values and used to set the required environmental variables.
// Once edited the values are added to the script files the .gitignore and
// .dockerignore files should be edited to exclude these files (there are lines
// that can be uncommented to accomplish this) 
//
//  See README.md for more details
//
// author:  github.com/timmaffett
import 'dart:convert';
import 'dart:io';

import 'package:encrypt/encrypt.dart';
import 'package:http/http.dart' as http;
import 'package:hive/hive.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_router/shelf_router.dart' as shelf_router;

late final Box stateBox;

const passPhraseUsedToGenerateCertificates='dartdart';

late final String clientId;
late final String clientSecret;
late final String localDebug;
late final String authReturnUrl;
late final String returnToAppUrl;
bool runningLocalDebug=false;

SecurityContext getSecurityContext() { // Bind with a secure HTTPS connection
  final chain = Platform.script.resolve('../certificates/CA/localhost/localhost.pem').toFilePath();
  final key = Platform.script.resolve('../certificates/CA/localhost/localhost.key').toFilePath();

  return SecurityContext()
  ..useCertificateChain(chain)
  ..usePrivateKey(key, password: passPhraseUsedToGenerateCertificates);
}

String replaceAllButLastFour( String hide ) {
  var re = RegExp(r'\w(?!\w{0,3}$)'); // mask all but last 4 characters
  hide = hide.replaceAll(re, 'X');
  return hide;
}

String? stripQuotes(String? str) {
  if(str==null) return null;
  return str.replaceAll(RegExp(r'^"|"$'), '').replaceAll(RegExp(r"^'|'$"), '');
}

Future main() async {
  // If the "PORT" environment variable is set, listen to it. Otherwise, 8080.
  // https://cloud.google.com/run/docs/reference/container-contract#port
  final port = int.parse(Platform.environment['PORT'] ?? '8080');

  var path = Directory.current.path;
  Hive.init(path);

  stateBox = await Hive.openBox('statebox');
  stateBox.clear(); // state never persist across runs

  clientId = stripQuotes(Platform.environment['CLIENT_ID']) ?? 'MissingClientIdEnvironmentalVariable';
  clientSecret = stripQuotes(Platform.environment['CLIENT_SECRET']) ?? 'MissingClientSecretEnvironmentalVariable';
  localDebug = stripQuotes(Platform.environment['LOCAL_DEBUG']) ?? 'false';
  authReturnUrl = stripQuotes(Platform.environment['AUTH_RETURN_URL']) ?? 'https://localhost:8080/authorized';
  returnToAppUrl = stripQuotes(Platform.environment['RETURN_TO_APP_URL']) ?? 'http://localhost:8000/index.html';

  runningLocalDebug = (localDebug=='true') || (authReturnUrl.contains('localhost'));

  bool missingEnvVariables=false;
  if(clientId=='MissingClientIdEnvironmentalVariable') {
    print('CLIENT_ID environmental variable not set! This is REQUIRED.');
    missingEnvVariables=true;
  }
  if(clientSecret=='MissingClientSecretEnvironmentalVariable') {
    print('CLIENT_SECRET environmental variable not set! This is REQUIRED.');
    missingEnvVariables=true;
  }
  if(missingEnvVariables) {
    print("Ensure all required environmental variables are set and re-run.");
    exit(1);
  }

  if(authReturnUrl=='https://localhost:8080/authorized') {
    print('AUTH_RETURN_URL environmental variable not set - defaulting to "https://localhost:8080/authorized"');
  }
  if(returnToAppUrl=='http://localhost:8000/index.html') {
    print('RETURN_TO_APP_URL environmental variable not set - defaulting to "http://localhost:8000/index.html"');
  } 

  print('Got ENV CLIENT_ID=${replaceAllButLastFour(clientId)}');
  print('Got ENV CLIENT_SECRET=${replaceAllButLastFour(clientSecret)}');
  print('Got ENV LOCAL_DEBUG=$localDebug');
  print('Got ENV AUTH_RETURN_URL=$authReturnUrl');
  print('Got ENV RETURN_TO_APP_URL=$returnToAppUrl');

  late final HttpServer server;
  if(runningLocalDebug) {
    // For local debug we run as a HTTPS server so we can properly test
    server = await shelf_io.serve(
      logRequests().addHandler(_router),
      InternetAddress.anyIPv4,
      port,
      securityContext: getSecurityContext()
    );
  } else {
    // when running in gcloud run container we will have incoming https connections, so run as simple
    // server
    server = await shelf_io.serve(
      logRequests().addHandler(_router),
      InternetAddress.anyIPv4,
      port
    );
  }

  print('Serving at https://${server.address.host}:${server.port}');
}

// Router instance to handler requests.
final _router = shelf_router.Router()
  ..get('/initiate/<rand|[a-zA-Z0-9]+>', _initiateHandler)
  ..get('/authorized', _returnAuthorizeHandler)
  ..all('/<ignored|.*>', (Request request) {
      return Response.notFound('Page not found');
    });

///  The calling app initiates a request for GitHub OAuth authorization by
///  sending get request to /initiate/XXXXXXXXX where XXXXXX is a random
///  alpha numeric token of at least 40 characters in length
///  When the entire process is complete the browser will be redirected to
///  the calling app at the URL defined by the RETURN_TO_APP_URL environmental
///  variable.  The calling app will need to use the originally sent
///  random token to decrypt the returned GitHub authorization token.
Response _initiateHandler(Request request, String rand) {
  // see if we have anything stored
  dynamic stored = stateBox.get(rand);
  bool newRequest=false;
  int timestamp=0;
  int nowTimeStamp = DateTime.now().millisecondsSinceEpoch;

  if(rand.isEmpty || rand.length<40) {
    return Response.ok('Random token must be >=40 characters in length');
  }

  if(stored==null) {
    timestamp = nowTimeStamp;
    newRequest=true;
  } else {
    timestamp = stored['timestamp'];
  }
  
  dynamic toStore= {'randomStr': rand, 
                    'timestamp':timestamp};

  stateBox.put(rand, toStore);
  
  // Take this opportunity to do stateBox cleanup and remove any old entries
  if(stateBox.length>1) {
    try {
      // check everything in the box for expiration
      for(int i=stateBox.length-1;i>=0;i--) {
        var old = stateBox.getAt(i);
        if(old['timestamp']!=null) {
          int howOld = nowTimeStamp - (old['timestamp'] as int);
          if(howOld>(5*60*1000)) {
            // older than 5 minutes, delete it
            stateBox.deleteAt(i);
          }
        }
      }
    } catch (e) {
      print('Exception $e caught during state box cleanup');
    }
  }

  /*
    Incoming Random String from DartPad

    Request Users GitHub Identity

    GET https://github.com/login/oauth/authorize

    client_id=XXXXXXXXXXX
    redirect_uri=https://timmaffett.github.io/saving/authorized
    scope=gist
    state=RANDOMSTR
  */
  if(newRequest) {
    String url = 'https://github.com/login/oauth/authorize?';
                  
    url += 'client_id=$clientId&redirect_uri=$authReturnUrl&scope=gist&state=$rand';

    print('Redirecting to GITHUB authorize');
    Map<String,String> headers = {'location':url};
    return Response(302,headers:headers);
  }

  // return to app with 'authfailed' to indicate error
  String backToAppUrl = returnToAppUrl;
  backToAppUrl += '?gh=authfailed';
  Map<String,String> headers = {'location':backToAppUrl};
  return Response(302,headers:headers);
}

/// This entry point is called by the GitHub OAuth process and is the
/// client return authorization handler defined on GitHub when creating 
/// the CLIENT_ID and CLIENT_SECRET for this server.
Future<Response> _returnAuthorizeHandler(Request request) async {
  /*
    REdirects BACK to my authorize page with 
    code=XXXXXXXX
    and
    state=RANDOMSTR  we sent earlier	
      
    Now we exchange this code=XXXX for an access token

    POST https://github.com/login/oauth/access_token

    client_id=XXXXXXX
    client_secret=MYCLIENTSECRET
    code=FROMINCOMING_PARAM 'code'
    redirect_uri=https://timmaffett.github.io/saving/authorized


    PUT "Accept: application/json" in ACCEPT HEADER on POST
    and get back JSON

    Accept: application/json
    {
      "access_token":"gho_16C7e42F292c6912E7710c838347Ae178B4a",
      "scope":"repo,gist",
      "token_type":"bearer"
    }
      
  */
  print('Entered _returnAuthorizeHandler');

  String backToAppUrl = returnToAppUrl;
  bool validCallback=false;
  bool tokenAquired=false;
  Map<String, String> params = request.requestedUri.queryParameters; // query parameters automatically populated

  try {
    final String code = params['code'] ?? '';
    final String state = params['state'] ?? '';

    // see if we have anything stored
    dynamic stored = stateBox.get(state);

    if(stored==null) {
      // ERROR!! we did not have a record of this initial request - ignore
    } else {
      validCallback=true;
      var client = http.Client();
      /*
        Now we exchange this code=XXXX for an access token

        POST https://github.com/login/oauth/access_token

        client_id=XXXXXXX
        client_secret=MYCLIENTSECRET
        code=FROMINCOMING_PARAM code
        redirect_uri=https://timmaffett.github.io/saving/authorized

        PUT "Accept: application/json" in ACCEPT HEADER on POST
        and get back JSON

        Accept: application/json
        {
          "access_token":"gho_XXXXXXXXX",
          "scope":"gist",
          "token_type":"bearer"
        }
      */
      final String githubExchangeCodeUri = 'https://github.com/login/oauth/access_token';
      final Map<String, dynamic> map = {
        'client_id':clientId,
        'client_secret':clientSecret,
        'code':code,
        'redirect_uri':authReturnUrl,
      };
      final String bodydata = json.encode(map);

      await client.post(Uri.parse(githubExchangeCodeUri),
                  headers:{
                      'Accept':'application/vnd.github.v3+json',
                      'Content-Type': 'application/json',
                  },
                  body:bodydata
          ).then((http.Response postResponse) {
        late String accessToken, scope, tokenType;    
        if (postResponse.statusCode >= 200 && postResponse.statusCode<=299) {
          final retObj = jsonDecode(postResponse.body);

          accessToken = retObj['access_token'] as String;
          scope = retObj['scope'] as String;
          tokenType = retObj['token_type'] as String;

          tokenAquired = true;

          // we can delete this record because we are done
          stateBox.delete(state);

          // encrypt the auth token using the original random state
          String encrBase64AuthToken = encryptAndBase64EncodeAuthToken( accessToken, state);
          // Build URL to redirect back to the app
          backToAppUrl += '?gh=$encrBase64AuthToken&scope=$scope';

          print('success - redirecting back to app');
        } else if (postResponse.statusCode == 404) {
          throw Exception('contentNotFound');
        } else if (postResponse.statusCode == 403) {
          throw Exception('rateLimitExceeded');
        } else if (postResponse.statusCode != 200) {
          throw Exception('unknown');
        }
      });
    }

    if( !validCallback || !tokenAquired ) {
      // return to app with 'noauth' set to indicate failed authorization
      backToAppUrl += '?gh=noauth&state=$state';
    }

    Map<String,String> headers = {'location':backToAppUrl};
    return Response(302,headers:headers);
  } catch (e) {
    // fall through and redirect back to app with 'authfailed'
  }
  // return to app with 'authfailed' to indicate error
  backToAppUrl += '?gh=authfailed';
  Map<String,String> headers = {'location':backToAppUrl};
  return Response(302,headers:headers);
}

/// Take the GitHub auth token [ghAuthToken] and the original random
/// state string [randomStateWeWereSent] the client sent in the original  
/// '/initiate/XXXXX' request and encrypt the token using the random state
/// string.   This protects the GH token on the return and also allows the
/// client to verify that we origin of the token.
/// This is probably overkill, we could just XOR encrypt (or something simple),
/// but erroring on the side of security can't hurt.
/// The symetric decrypting routine in the comments below.  This is used on
/// client to decrypt the received token.
String encryptAndBase64EncodeAuthToken( String ghAuthToken, String randomStateWeWereSent ) {
  if(randomStateWeWereSent.isEmpty) {
    return 'ERROR-no stored initial state';
  }
  try {
    final iv = IV.fromUtf8(randomStateWeWereSent.substring(0,8));
    final key = Key.fromUtf8(randomStateWeWereSent.substring(8,40));
    final sasla = Salsa20(key);
    final encrypter = Encrypter(sasla);

    final encryptedToken = encrypter.encrypt(ghAuthToken,iv:iv);
  
    return Uri.encodeComponent(encryptedToken.base64);
  } catch (e) {
    print('CAUGHT EXCEPTION during encryption ${e.toString()}');
  }
  return 'ENCRYPTION_ERROR';
}

/// This is EXAMPLE routine to decrypt the encrypted token 
/// created by encryptAndBase64EncodeAuthToken
/// This is not used in the server code but is provided here as
/// an example
String decryptAuthTokenFromReturnedSecureAuthToken(
  String encryptedBase64AuthToken, String randomStateWeSent) {
  // retrieve the random state string we made for the original request in
  // makeRandomSecureAuthInitiationUrl().  Our auth token was encrypted using
  // this before sending it back to us, so use it to decrypt
  try {
    if (randomStateWeSent.isEmpty) {
      return 'ERROR-no stored initial state';
    }

    final iv = IV.fromUtf8(randomStateWeSent.substring(0, 8));
    final key = Key.fromUtf8(randomStateWeSent.substring(8, 40));
    final sasla = Salsa20(key);
    final encrypter = Encrypter(sasla);

    final encryptedToken =
        Encrypted.from64(Uri.decodeComponent(encryptedBase64AuthToken));

    final decryptedAuthToken = encrypter.decrypt(encryptedToken, iv: iv);

    return decryptedAuthToken;
  } catch (e) {
    print('CAUGHT EXCEPTION e=${e.toString()}');
  }
  return 'DECRYPTION_ERROR';
}