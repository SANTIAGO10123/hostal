from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == "admin" and password == "admin":  # Ejemplo simple
            return redirect(url_for('reservas'))
        else:
            return "Datos incorrectos"
    return render_template('login.html')

@app.route('/reservas')
def reservas():
    return render_template('reservas.html')

@app.route('/contacto')
def contacto():
    return render_template('contact.html')

if __name__ == "__main__":
    app.run(debug=True)
