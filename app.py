from flask import Flask, render_template, request, json, redirect, url_for, send_from_directory, abort, jsonify, flash, session, logging
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
import hashlib
import os
from werkzeug import secure_filename
from OpenSSL.crypto import load_privatekey, FILETYPE_PEM, sign
import MySQLdb

UPLOAD_FOLDER = 'files'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'xls', 'ppt'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/')
def main():
    return render_template('index.html')


@app.route('/showSignUp')
def showSignUp():
    return render_template('signup.html')

@app.route('/showSignIn')
def showSignIn():
    return render_template('signin.html')

@app.route('/upOrDown')
def upOrDown():
    if 'id' in session:
	print(session['id'])
    else:
	print('no session id')
    return render_template('upOrDown.html')

@app.route('/upload')
def upload():
    return render_template('upload.html')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['POST', 'GET'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
	    if 'id' in session:
		print(session['id'])
	    conn = MySQLdb.connect(host="localhost", port=3306, user="root", passwd="123456", db="acdemo")
            cursor = conn.cursor()
            cursor.callproc('sp_createFile', (file.filename, 'key', 'sha', 1)) 
            data = cursor.fetchall()
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('upload',
                                    filename=filename))
   
    flash('File successfully uploaded!')
    return render_template('upload.html')


def generateKey():
    random_generator = Random.new().read

    rsa = RSA.generate(1024, random_generator)

    private_pem = rsa.exportKey()
    public_pem = rsa.publickey().exportKey()
    print(private_pem)
    print(public_pem)
    return {'pubkey': public_pem, 'privkey': private_pem }


@app.route('/showSignUp', methods=['POST', 'GET'])
def toSignUp():
    # read the posted values from the UI
    _name = request.form['inputName']
    _email = request.form['inputEmail']
    _password = request.form['inputPassword']

    session.pop('user', None)
    session.pop('id', None)

    if _name and _email and _password:
        # _hashed_password = generate_password_hash(_password)

	sha256 = hashlib.sha256()
        sha256.update(_password.encode('utf-8'))
        hashed_password = sha256.hexdigest()

	# create public key and private key here
	# function
	key_pair = generateKey()
	pubkey = key_pair['pubkey']
	privkey = key_pair['privkey']

	upDown_url = url_for('upOrDown')
        print(hashed_password)
        # mysql = MySQL()
        conn = MySQLdb.connect(host="localhost", port=3306, user="root", passwd="123456", db="acdemo")
        cursor = conn.cursor()
        cursor.callproc('sp_createUser', (_name, hashed_password, pubkey, privkey)) 
        data = cursor.fetchall()

        if len(data) is 0:
            conn.commit()
            return redirect(upDown_url) 
        else:
            return redirect(upDown_url)


@app.route('/showSignIn', methods=['POST', 'GET'])
def toSignIn():
    _name = request.form['inputName']
    _password = request.form['inputPassword']
    upDown_url = url_for('upOrDown')

    if _name and _password:
        # _hashed_password = generate_password_hash(_password)

	sha256 = hashlib.sha256()
        sha256.update(_password.encode('utf-8'))
        hashed_password = sha256.hexdigest()
	
	conn = MySQLdb.connect(host="localhost", port=3306, user="root", passwd="123456", db="acdemo")
        cursor = conn.cursor()
        cursor.callproc('sp_userLogin', (_name, hashed_password))
        data = cursor.fetchall()
	session['id'] = data
	session['user'] = _name
	
	print(data)
	print(session['id'])
	print(session['user'])	
	if data:
	    flash('Log in successfully!')
	    return redirect(upDown_url) 
	else:
	    flash('Wrong username or password! Please check them again!')
	    return render_template('signin.html')


@app.route('/download')
def list_files():
    """Endpoint to list files on the server."""
    files = []
    for filename in os.listdir(UPLOAD_FOLDER):
        path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.isfile(path):
            files.append(filename)
    return jsonify(files)


@app.route('/download/<path:path>')
def get_file(path):
    """Download a file."""
    return send_from_directory(UPLOAD_FOLDER, path, as_attachment=True)


@app.route('/download/<filename>', methods=['POST'])
def post_file(filename):
    """Upload a file."""

    if '/' in filename:
        # Return 400 BAD REQUEST
        abort(400, 'no subdirectories directories allowed')

    with open(os.path.join(UPLOAD_FOLDER, filename), 'wb') as fp:
        fp.write(request.data)

    # Return 201 CREATED
    return '', 201



if __name__ == '__main__':
    app.secret_key = 'secretkey'
    app.run(host='0.0.0.0', debug="True", threaded=True)


