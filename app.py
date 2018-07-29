#coding=utf-8

from flask import Flask, render_template, request, json, redirect, url_for, send_from_directory, abort, jsonify, flash, session, logging, send_file
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
import datetime
import sys
import random
import re
import rsa
import base64
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

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


class prpcrypt():
    def __init__(self, key):
        self.key = key
        self.mode = AES.MODE_CBC
	self.iv = os.urandom(16)


    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        
        length = 32
        count = len(text)
        if (count % length != 0):
            add = length - (count % length)
        else:
            add = 0
        text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        
       
        return b2a_hex(self.ciphertext)

    
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')


@app.route('/upload', methods=['POST', 'GET'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
	    filename = secure_filename(file.filename)
	    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
	    if 'id' in session:
		# session['id'] = session['id'][0]
		print(session['id'])
	    else:
		print("no session id")
	    
            now_time = datetime.datetime.now()  

            
            fsize = os.path.getsize(UPLOAD_FOLDER)
            fsize = fsize / float(1024 * 1024) 

	    conn = MySQLdb.connect(host="localhost", port=3306, user="root", passwd="123456", db="acdemo")
            cursor = conn.cursor()
            file = request.files['file']
            f = open(os.path.join(app.config['UPLOAD_FOLDER'], filename), "rb+")
            data = f.read()
	    f.close()
            
            hash = hashlib.sha256()
            hash.update(data)
            hashed_data = hash.hexdigest()

            
            key = ''  
            base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'  
            length = len(base_str) - 1
            for i in range(32):
                key += base_str[random.randint(0, length)]
	 
	    # encrypt file
            pc = prpcrypt(key)  
            e_data = pc.encrypt(data)
	    f = open(os.path.join(app.config['UPLOAD_FOLDER'], filename), "w")
	    f.write(e_data)
	    f.close()
	    
	    # encrypt key
            cursor.execute("SELECT pubkey FROM users where users.id = (%s)", [session['id']])
            r_pubkey = cursor.fetchall()[0]
	    rsakey = RSA.importKey(r_pubkey)
	    cipher = Cipher_pkcs1_v1_5.new(rsakey)
	    enckey = base64.b64encode(cipher.encrypt(key))

	    print("%s %s", filename, fsize)
	   
            cursor.callproc('sp_createFile', (
                filename,  
                fsize, 
                enckey, 
                hashed_data,  
                session['id'],  
                now_time))  
            data = cursor.fetchall()
	    if len(data) is 0:
            	flash('File successfully uploaded!')
            	conn.commit()
		return '''<h2>You've upload it successfully!</h2>'''
    return render_template('upload.html')


def generateKey():

    rsa = RSA.generate(1024)

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
    userid = 0

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
	select_stmt = "SELECT id FROM users WHERE users.name = %(username)s and users.password = %(passwd)s"
	cursor.execute(select_stmt, { 'username': _name, 'passwd': hashed_password })
        data = cursor.fetchall()
	print(data)

        if len(data):
	    session['id'] = data[0][0]
	    print(session['id'])
            conn.commit()
            return redirect(upDown_url) 
        else:
            return render_template('signup.html')


@app.route('/showSignIn', methods=['POST', 'GET'])
def toSignIn():
    _name = request.form['inputName']
    _password = request.form['inputPassword']
    upDown_url = url_for('upOrDown')

    session.pop('user', None)
    session.pop('id', None)

    if _name and _password:
        # _hashed_password = generate_password_hash(_password)

	sha256 = hashlib.sha256()
        sha256.update(_password.encode('utf-8'))
        hashed_password = sha256.hexdigest()
	
	conn = MySQLdb.connect(host="localhost", port=3306, user="root", passwd="123456", db="acdemo")
        cursor = conn.cursor()
        cursor.callproc('sp_userLogin', (_name, hashed_password))
        data = cursor.fetchall()
	session['id'] = data[0][0]
	
	print(data)
	print(session['id'])
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
    if 'id' in session:
	conn = MySQLdb.connect(host="localhost", port=3306, user="root", passwd="123456", db="acdemo")
        cursor = conn.cursor()
	
        for filename in os.listdir(UPLOAD_FOLDER):
	    print(filename)
            path = os.path.join(UPLOAD_FOLDER, filename)
	    cursor.execute("SELECT uid FROM files where files.name = (%s)", [filename])
            data = cursor.fetchall()
	    
	    for i in list(data):
		print(list(i))
                if session['id'] in list(i) and os.path.isfile(path):
                    files.append(filename)
	            print(files)
	cursor.close()
    return render_template('download.html', files=files)


@app.route('/download/<path:filename>')
def get_file(filename):
    """Download a file."""
    if 'id' in session:
        conn = MySQLdb.connect(host="localhost", port=3306, user="root", passwd="123456", db="acdemo")
        cursor = conn.cursor()
	cursor.execute("SELECT privkey FROM users WHERE users.id = (%s)", [session['id']])
        privkey = cursor.fetchall()[0][0]
	cursor.execute("SELECT enckey FROM files WHERE files.name = (%s) and files.uid = (%s)", [filename, session['id']])
	enckey = cursor.fetchall()[0][0]
       
	f = open(os.path.join(app.config['UPLOAD_FOLDER'], filename), "wb+")
	data = f.read()
	# decrypt aes key
	rsakey = RSA.importKey(privkey)
	cipher = Cipher_pkcs1_v1_5.new(rsakey)
	# decrypt file
	random_generator = Random.new().read
	key = cipher.decrypt(base64.b64decode(enckey), random_generator)
	pc = prpcrypt(key)  
        text = pc.decrypt(data)
	f.write(text)
	f.close()
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)


if __name__ == '__main__':
    app.secret_key = 'secretkey'
    app.run(host='0.0.0.0', debug="True", threaded="True", ssl_context=('cert.pem', 'key.pem'))


