from flask import Flask, render_template, request, json, redirect, url_for
import hashlib
import os
from werkzeug import secure_filename
# from flask_mysqldb import MySQL
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
def showUpOrDown():
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
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('upload',
                                    filename=filename))
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form action="" method=post enctype=multipart/form-data>
      <p><input type=file name=file>
         <input type=submit value=Upload>
    </form>
    '''

@app.route('/showSignUp', methods=['POST'])
def upOrDown():
    # read the posted values from the UI
    _name = request.form['inputName']
    _email = request.form['inputEmail']
    _password = request.form['inputPassword']

    if _name and _email and _password:
        # _hashed_password = generate_password_hash(_password)

	sha256 = hashlib.sha256()
        sha256.update(_password.encode('utf-8'))
        hashed_password = sha256.hexdigest()

	# create public key and private key here
	# function

	upDown_url = url_for('showUpOrDown')
        print(hashed_password)
        # mysql = MySQL()
        conn = MySQLdb.connect(host="localhost", port=3306, user="root", passwd="123456", db="acdemo")
        cursor = conn.cursor()
        cursor.callproc('sp_createUser', (_name, hashed_password, 'test', 'test')) 
        data = cursor.fetchall()

        if len(data) is 0:
            conn.commit()
            return redirect(upDown_url) 
        else:
            return redirect(upDown_url)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug="True")


