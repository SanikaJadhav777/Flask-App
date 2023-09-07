import os
import pathlib
import requests
from flask import Flask, abort, redirect, request, render_template, session
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests


'''
**************************** Google Auth based Authentication ****************************
'''
app = Flask("Google Login App")
app.secret_key = "CodeSpecialist.com"
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "751657672688-3lcpgaq0t4mg2ncaplh94j930jiffov5.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Check whether user is logged in or not
def login_is_required(function):
    # decorator for login
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()
    return wrapper

# User login
@app.route("/login", methods = ['POST'])
def login():
    if request.method == 'POST':
        authorization_url, state = flow.authorization_url()
        session["state"] = state
        return redirect(authorization_url)

# Callback function
@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/protected_area")

# User logout
@app.route("/logout", methods = ['POST'])
def logout():
    session.clear()
    return redirect("/")

# Upload, save and generate acknowledgement
@app.route('/success', methods = ['POST'])
def success():
    if request.method == 'POST':
        f = request.files['file']
        if request.files['file'].filename == '':
            return render_template("upload_status.html", acknowledgement="Unable to upload file !")
        else:
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], f.filename))
            session['uploaded_img_file_path'] = f.filename
            return render_template("upload_status.html", acknowledgement="File Uploaded Successfully...", name="File Name: " + f.filename)

# Rendering Uploaded Image
@app.route('/show_image', methods = ['POST'])
def display_image():
    filename = session.get('uploaded_img_file_path', None)
    print(filename)
    return render_template("show_image.html", filename=filename)


@app.route("/")
def index():
    return render_template("index.html")
    #return "Hello World <a href='/login'><button>Login</button></a>"

@app.route("/protected_area")
@login_is_required
def protected_area():
    return render_template("upload_image.html", name=session['name'])
    #return f"Hello {session['name']}! <br/> <a href='/logout'><button>Logout</button></a>"

''' 
**************************** Authentication system using JWT Token ****************************
@app.route('/')
def main():
	auth = request.authorization
	if auth and auth.password == 'admin11':
		token = jwt.encode({
			'user' : auth.username,
			'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
		}, app.config['SECRET_KEY'])
		#token = jwt.encode({'user' : auth.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
		return jsonify({'token' : token.decode('UTF-8')})
	return make_response('Could not verify',401, {'WWW-Authenticate' : 'Basic realm="Login Required"' })
	#return render_template("upload_image.html")

@app.route('/upload', methods = ['GET'])
@token_required
def upload():
	#return jsonify({'message': 'Token is valid'})
	return render_template("upload_image.html")

@app.route('/success', methods = ['POST'])
def success():
	if request.method == 'POST':
		f = request.files['file']
		if request.files['file'].filename == '':
			return render_template("upload_status.html", acknowledgement="Unable to upload file !")
		else:
			f.save(f.filename)
			return render_template("upload_status.html",  acknowledgement="File Uploaded Successfully...", name = "File Name: "+f.filename)
'''

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0')