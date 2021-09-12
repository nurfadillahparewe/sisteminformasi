from logging import log
from flask import Flask, render_template, request, redirect, url_for, flash, session
from requests.api import post
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug import datastructures
from werkzeug.exceptions import BadRequest
from functools import wraps
import requests
from requests.structures import CaseInsensitiveDict

cred = credentials.Certificate('firebase.json')
firebase_admin.initialize_app(cred)

db = firestore.client()


app = Flask(__name__)
app.secret_key = "cobacobacoba"

def login_required(f):
    @wraps(f)
    def wrapper (*args, **kwargs):
        if 'user' in session:
            return f(*args, **kwargs)
        else:
            flash('Anda harus login', 'danger')
            return redirect(url_for('login'))
    return wrapper

def send_wa(m, p):
    api ='018514667b6b377454246b336b1dae31a5ebc459'
    url = 'https://starsender.online/api/sendText'

    data = {
        "tujuan" : p,
        "message" : m
    }

    headers = CaseInsensitiveDict()
    headers['apikey'] = api
    res = requests.post(url, json=data, headers=headers)
    return res.text

@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/login', methods=["GET","POST"])
def login():
    if request.method == "POST":
    #ambil data dari form
        data = {
            "usernameta" : request.form  ["usernameta"],
            "passwordta" : request.form ["passwordta"]
        }
        #lakukan pengecekan
        users = db.collection('username').where("usernameta",'==',data["usernameta"]).stream()
        user = {}

        for us in users  :
            user = us.to_dict()
        if user :
            if check_password_hash(user["passwordta"], data["passwordta"]):
                flash('selamat anda berhasil login', 'success')
                session ['user'] = user
                return redirect(url_for('dashboard'))
            else :
                flash('maaf password anda salah', 'danger')
                return redirect(url_for('login'))
        else :
            flash('user belum terdaftar','danger')
            return redirect(url_for('login'))

    if 'user' in session:
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # if 'user' not in session:
    #     flash ('anda belum login', 'danger')
    #     return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/mahasiswa')
@login_required
def mahasiswa():

    # panggil data di database
    # lakukan pengulangan terhadap data
    # simpan data yang sudah di ulang di dalam sebuah array

    maba = db.collection('mahasiswa').stream()
    mb = []

    

    for mhs in maba :
        m = mhs.to_dict()
        m['id']=mhs.id
        # dalam maba terdapat 10 dictionary yang isinya ada 5 key (nama, email, nim, jurusan, dan id)
        mb.append(m)

    return render_template('mahasiswa.html', mb=mb)

@app.route('/mahasiswa/tambah', methods=["GET", "POST"])
@login_required
def tambah_mhs():
    if request.method == "POST":
        data = {
            "Namata" : request.form['nama'],
            "Emailta" : request.form['email'],
            "NIMta" : request.form['nim'],
            "Jurusanta" : request.form['jurusan']
        }

        db.collection("mahasiswa").document().set(data)
        flash('Berhasil Tambah Mahasiswa','success')
        return redirect(url_for('tambah_mhs'))
        
    return render_template('tambah_mhs.html')

@app.route('/register', methods=["GET", "POST"])
def register():
    #cek dulu methodnya
    #if post
        # ambil data dari form
        # kita masukkan datanya ke database
        # redirect ke halaman login
    
    #menampilkan halaman register

    if request.method == "POST":
        data = {
            "usernameta" : request.form['username'],
            "passwordta" : request.form['password'],
            "nomor_hpta" : request.form['nomor_hp']
        }

        username = db.collection('username').where('usernameta','==', data['usernameta']).stream()
        users = {}
        for us in username :
            users = us.to_dict()
        
        if users :
            flash('Username sudah terdaftar', 'danger')
            return redirect(url_for('register'))
        
        data['passwordta'] = generate_password_hash(request.form['password'],'sha256')
        db.collection("username").document().set(data)
        flash('Berhasil Register','success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/mahasiswa/hapus/<uid>')
@login_required
def hapus_mhs(uid):
    db.collection('mahasiswa').document(uid).delete()
    flash('Berhasil Hapus Mahasiswa','danger')
    return redirect(url_for('mahasiswa'))


@app.route('/mahasiswa/lihat/<uid>')
@login_required
def lihat_mhs(uid):
    
    # db.collection('mahasiswa').document(uid).delete()
    return render_template('lihat_mhs.html')

@app.route('/mahasiswa/ubah/<uid>', methods=["GET", "POST"])
@login_required
def ubah_mhs(uid):
    
    # menentukan method
    if request.method == "POST":
        data = {
            "Namata" : request.form['nama'],
            "Emailta" : request.form['email'],
            "NIMta" : request.form['nim'],
            "Jurusanta" : request.form['jurusan']
        }
        db.collection('mahasiswa').document(uid).set(data, merge=True)
        flash('Berhasil Ubah Data','success')
        return redirect(url_for('mahasiswa'))

    user = db.collection('mahasiswa').document(uid).get().to_dict()
    user['id']= uid
    return render_template('ubah_mhs.html', user=user)

@app.route ('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
