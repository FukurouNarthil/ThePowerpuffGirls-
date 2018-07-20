from flask import Flask, render_template, request, json
import hashlib
# from flask_mysqldb import MySQL
import MySQLdb

app = Flask(__name__)


@app.route('/')
def main():
    return render_template('index.html')


@app.route('/showSignUp')
def showSignUp():
    return render_template('signup.html')


# show signin html
# @app.route('/showSignIn')
# def showSignIn():
# return render_template('signin.html')


@app.route('/signUp', methods=['POST'])
def signUp():
    # read the posted values from the UI
    _name = request.form['inputName']
    _email = request.form['inputEmail']
    _password = request.form['inputPassword']

    # validate the received values
    # if _name and _email and _password:
    # print(_name)
    # print(_email)
    # return json.dumps({'html':'<span>All fields good !!</span>'})

    # else:
    # return json.dumps({'html':'<span>Enter the required fields</span>'})

    if _name and _email and _password:
        # _hashed_password = generate_password_hash(_password)

        # 用sha256对明文密码做哈希
        sha256 = hashlib.sha256()
        sha256.update(_password.encode('utf-8'))
        hashed_password = sha256.hexdigest()

        print(hashed_password)
        # mysql = MySQL()
        conn = MySQLdb.connect(host="localhost", port=3306, user="root", passwd="hexie123", db="acdemo")
        cursor = conn.cursor()
        cursor.callproc('sp_createUser', (_name, hashed_password))  # 调用在users表中插入信息的存储过程

        data = cursor.fetchall()

        if len(data) is 0:
            conn.commit()
            return json.dumps({'message': 'User created successfully !'})  # 在browser的console中可以看到返回信息
        else:
            return json.dumps({'error': str(data[0])})


if __name__ == '__main__':
    app.run()


