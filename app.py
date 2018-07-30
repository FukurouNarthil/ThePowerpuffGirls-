#coding=utf-8

from flask import Flask, render_template, request, json, redirect, url_for, send_from_directory, abort, jsonify, flash, session, logging, send_file
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
import hashlib
import os
import shutil
from werkzeug import secure_filename
from OpenSSL.crypto import load_privatekey, FILETYPE_PEM, sign
import MySQLdb
import datetime
import sys, struct
import random
import rsa
import base64
import zipfile
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

    def encrypt(self, inf, chunksize=64*1024):
        iv = os.urandom(16)
        encryptor = AES.new(self.key, self.mode, iv)
        infile = open(inf, 'rb')
        filesize = os.path.getsize(inf)
        cipher = b''

        while True:

            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk += '\0'.encode('ascii') * (16 - len(chunk) % 16)
            cipher += encryptor.encrypt(chunk)

        infile.close()

        outfile = open(inf, 'wb')
        outfile.write(struct.pack('<Q', filesize))
        outfile.write(iv)
        outfile.write(cipher)
        outfile.close()

    def decrypt(self, inf, chunksize=24*1024):
        infile = open(inf, 'rb')
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)

        decryptor = AES.new(self.key, self.mode, iv)
        plain_text = b''

        while True:
            chunk = infile.read(chunksize)
            # print(chunk)
            if len(chunk) == 0:
                break
            plain_text += chunk

        infile.close()
        outfile = open(inf, 'wb')
        outfile.write(decryptor.decrypt(plain_text))
        outfile.truncate(origsize)

        outfile.close()


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
            f = open(os.path.join(app.config['UPLOAD_FOLDER'], filename), "rb")
            data = f.read()
	    f.close()
            
	    # sign
            digest = SHA.new()
	    digest.update(data)
	    
	    hash_file_name = filename.split('.')[0]+"_hash.txt"
	    hash_file = open(os.path.join(app.config['UPLOAD_FOLDER'], hash_file_name), "wb")
	    hash_file.write(digest)
	    hash_file.close()
            
            key = ''  
            base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'  
            length = len(base_str) - 1
            for i in range(32):
                key += base_str[random.randint(0, length)]
	 
	    # encrypt file
            pc = prpcrypt(key)  
            pc.encrypt(os.path.join(app.config['UPLOAD_FOLDER'], filename))
	    
	    # encrypt key
            cursor.execute("SELECT pubkey FROM users where users.id = (%s)", [session['id']])
            r_pubkey = cursor.fetchall()[0]
	    rsakey = RSA.importKey(r_pubkey)
	    cipher = Cipher_pkcs1_v1_5.new(rsakey)
	    enckey = base64.b64encode(cipher.encrypt(key.encode("utf-8")))

	    print("%s %s", filename, fsize)
	   
            cursor.callproc('sp_createFile', (
                filename,  
                fsize, 
                enckey, 
                digest,  
                session['id'],  
                now_time))
	    cursor.callproc('sp_createFile', (
                hash_file_name,  
                1, 
                '', 
                '',  
                session['id'],  
                now_time))
            data = cursor.fetchall()
	    if len(data) is 0:
            	flash('File successfully uploaded!')
            	conn.commit()
		return '''<h2>You've upload it successfully!</h2></br>
			<p><a  class="btn btn-default" href="upOrDown" role="button">Go Back</a></p>'''
    return render_template('upload.html')


def generateKey():
    random_generator = Random.new().read

    rsa = RSA.generate(1024, random_generator)

    private_pem = rsa.exportKey()
    public_pem = rsa.publickey().exportKey()
    return {'pubkey': public_pem, 'privkey': private_pem}


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
    hash_files = []
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
                if session['id'] in list(i) and os.path.isfile(path) and 'hash' not in filename:
                    files.append(filename)
	            print(files)
		elif session['id'] in list(i) and 'hash' in filename:
		    hash_files.append(filename)
	cursor.close()
        return render_template('download.html', files=files, hash_files=hash_files)


@app.route('/download/<path:filename>')
def get_file(filename):
    """Download a file."""
    if filename == 'cert.pem':
	return send_from_directory("", filename, as_attachment=True)
    if 'hash' in filename:
	return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    if 'id' in session:
        conn = MySQLdb.connect(host="localhost", port=3306, user="root", passwd="123456", db="acdemo")
        cursor = conn.cursor()
	cursor.execute("SELECT privkey FROM users WHERE users.id = (%s)", [session['id']])
        privkey = cursor.fetchall()[0][0]
	cursor.execute("SELECT enckey FROM files WHERE files.name = (%s) and files.uid = (%s)", [filename, session['id']])
	enckey = cursor.fetchall()[0][0]
       
	# decrypt aes key
	rsakey = RSA.importKey(privkey)
	cipher = Cipher_pkcs1_v1_5.new(rsakey)
	# decrypt file
	sentinel = Random.new().read
	key = cipher.decrypt(base64.b64decode(enckey), sentinel).decode("utf-8")
	pc = prpcrypt(key)  
        pc.decrypt(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    
    # anonymous users downloading
    else:
	conn = MySQLdb.connect(host="localhost", port=3306, user="root", passwd="123456", db="acdemo")
        cursor = conn.cursor()
	cursor.execute("SELECT enckey, uid FROM files WHERE files.name = (%s)", [filename])
	enckey = cursor.fetchall()[0][0]
	uid = cursor.fetchall()[0][1]
	cursor.execute("SELECT privkey FROM users WHERE users.id = (%s)", [uid])
        privkey = cursor.fetchall()[0][0]
       
	# decrypt aes key
	rsakey = RSA.importKey(privkey)
	cipher = Cipher_pkcs1_v1_5.new(rsakey)
	# save key
	sentinel = Random.new().read
	key = cipher.decrypt(base64.b64decode(enckey), sentinel).decode("utf-8")
	keyfile = open("key.txt", "w")
	keyfile.write(key)

	hash_file_name = filename.split('.')[0]+"_hash.txt"
	h = open(os.path.join(app.config['UPLOAD_FOLDER'], filename), "rb")

	with open('key.pem') as f:
	    server_priv_key = f.read()
	    server_rsa_key = RSA.importKey(server_priv_key)
	    signer = Signature_pkcs1_v1_5.new(server_rsa_key)
            sign = signer.sign(h)
	    signature = base64.b64encode(sign)
	s = open("sign.txt", "w")
	s.write(signature)
	s.close()

	temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp')

	os.rename(os.path.join(app.config['UPLOAD_FOLDER'], filename), os.path.join(temp_dir, filename))
	os.rename(os.path.join(app.config['UPLOAD_FOLDER'], 'key.txt'), os.path.join(temp_dir, 'key.txt'))
	os.rename(os.path.join(app.config['UPLOAD_FOLDER'], hash_file_name), os.path.join(temp_dir, hash_file_name))
	os.rename(os.path.join(app.config['UPLOAD_FOLDER'], 'sign.txt'), os.path.join(temp_dir, 'sign.txt'))
	zipf = zipfile.ZipFile(filename, 'w')
	pre_len = len(os.path.dirname(temp_dir))
	for parent, dirnames, filenames in os.walk(temp_dir):
	    for item in filenames:
		pathfile = os.path.join(parent, item)
		arcname = pathfile[prelen:].strip(os.path.sep)
		zipf.write(pathfile, arcname)
	zipf.close()
	return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)


if __name__ == '__main__':
    app.secret_key = 'secretkey'
    app.run(host='0.0.0.0', debug="True", threaded="True", ssl_context=('cert.pem', 'key.pem'))


