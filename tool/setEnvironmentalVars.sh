# Remember to edit .dockeringnore and .gitignore to ingore this file
# once secrets have been added
# CLIENT_ID and CLIENT_SECRET come from github OAuth App setup
CLIENT_ID=<YOUR CLIENT ID>
CLIENT_SECRET=<YOUR CLIENT SECRET>

LOCAL_DEBUG=true

# the AUTH_RETURN_URL must match github OAuth App Setup and
# REM point to this server's /authorized URI
AUTH_RETURN_URL=https://localhost:8080/authorized

# the RETURN_TO_APP_URL should be url to return to the app after completing
# github OAuth authorization.  A 'gh' query parameter will be added to this
# url which will contain the github authorization token
RETURN_TO_APP_URL=http://localhost:8000/index.html