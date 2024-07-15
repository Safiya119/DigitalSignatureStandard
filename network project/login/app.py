from flask import Flask,render_template,request,session,redirect,url_for,g,flash

from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
app=Flask(__name__, template_folder='templates')
app.secret_key="123"

class User:
    def __init__(self,id,username,password):
        self.id=id
        self.username=username
        self.password=password

users=[]
users.append(User(id=1,username='safiya',password='safiya@123'))
users.append(User(id=2,username='thaseem',password='thaseem@123'))
users.append(User(id=3,username='seneha',password='seneha@123'))
users.append(User(id=3,username='raksha',password='raksha@123'))
users.append(User(id=3,username='priya',password='priya@123'))

@app.route("/",methods=['GET','POST'])
def login():
    if request.method=='POST':
        uname=request.form['uname']
        upass = request.form['upass']

        for data in users:
            if data.username==uname and data.password==upass:
                session['userid']=data.id
                g.record=1
                return redirect(url_for('user'))
            else:
                g.record=0
        if g.record!=1:
            flash("Username or Password Mismatch...!!!",'danger')
            return redirect(url_for('login'))
    return render_template("login.html")


@app.before_request
def before_request():
    if 'userid' in session:
        for data in users:
            if data.id==session['userid']:
                g.user=data

@app.route('/user')
def user():
    if not g.user:
        return redirect(url_for('login'))
    return render_template('user.html')

# Generate RSA keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

private_key, public_key = generate_keys()

# Sign message
def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify signature
def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False



@app.route('/generate_certificate', methods=['POST'])
def generate_certificate():
    data = request.json
    message = data.get('message')
    signature = sign_message(message.encode(), private_key)
    return jsonify({'message': message, 'signature': signature.hex()})

@app.route('/verify_certificate', methods=['POST'])
def verify_certificate():
    data = request.json
    message = data.get('message')
    signature = bytes.fromhex(data.get('signature'))
    valid = verify_signature(message.encode(), signature, public_key)
    return jsonify({'valid': valid})


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__=='__main__':
    app.run(debug=True)

