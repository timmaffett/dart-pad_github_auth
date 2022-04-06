REM Remember to edit .dockeringnore and .gitignore to ingore this file
REM once secrets have been added
REM CLIENT_ID and CLIENT_SECRET come from github OAuth App setup
set CLIENT_ID=<YOUR CLIENT ID>
set CLIENT_SECRET=<YOUR CLIENT SECRET>

set LOCAL_DEBUG=true

REM the AUTH_RETURN_URL must match github OAuth App Setup and
REM point to this server's /authorized URI
set AUTH_RETURN_URL=https://localhost:8080/authorized

REM the RETURN_TO_APP_URL should be url to return to the app after completing
REM github OAuth authorization.  A 'gh' query parameter will be added to this
REM url which will contain the github authorization token
set RETURN_TO_APP_URL=http://localhost:8000/index.html
