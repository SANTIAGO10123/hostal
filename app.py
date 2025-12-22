# app.py - Sistema de Login
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
import sqlite3
import os
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = '1012341850'  # Cambia esto por una clave única
bcrypt = Bcrypt(app)

# Configuración de base de datos SQLite
def init_db():
    conn = sqlite3.connect('hostal.db')
    c = conn.cursor()
    
    # Tabla de usuarios con todos los campos necesarios
    c.execute('''CREATE TABLE IF NOT EXISTS usuarios
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  nombre TEXT NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  telefono TEXT,
                  documento_identidad TEXT,
                  rol TEXT DEFAULT 'cliente',
                  fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  activo BOOLEAN DEFAULT 1)''')
    
    # Tabla de reservas
    c.execute('''CREATE TABLE IF NOT EXISTS reservas
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  nombre_cliente TEXT NOT NULL,
                  email_cliente TEXT NOT NULL,
                  telefono TEXT NOT NULL,
                  fecha_entrada DATE NOT NULL,
                  fecha_salida DATE NOT NULL,
                  tipo_habitacion TEXT NOT NULL,
                  numero_personas INTEGER NOT NULL,
                  estado TEXT DEFAULT 'pendiente',
                  fecha_reserva TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  usuario_id INTEGER,
                  FOREIGN KEY (usuario_id) REFERENCES usuarios (id))''')
    
    # Insertar usuario administrador por defecto (si no existe)
    c.execute("SELECT COUNT(*) FROM usuarios WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        c.execute("INSERT INTO usuarios (username, password, nombre, rol) VALUES (?, ?, ?, ?)",
                  ('admin', hashed_password, 'Administrador Principal', 'administrador'))
    
    conn.commit()
    conn.close()



# Decorador para requerir login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, inicia sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorador para requerir rol de administrador
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'rol' not in session or session['rol'] != 'administrador':
            flash('Acceso denegado. Se requieren permisos de administrador.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Ruta de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('hostal.db')
        c = conn.cursor()
        c.execute("SELECT id, username, password, nombre, rol FROM usuarios WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['nombre'] = user[3]
            session['rol'] = user[4]
            
            flash(f'¡Bienvenido, {user[3]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos.', 'danger')
    
    return render_template('login.html')

# Ruta del dashboard (después del login)

@app.route('/dashboard')
@login_required
def dashboard():
    # Estadísticas para el dashboard
    if session.get('rol') == 'cliente':
        return redirect(url_for('perfil_cliente'))
    
    # Estadísticas solo para admin/recepcionista
    conn = sqlite3.connect('hostal.db')
    
    conn = sqlite3.connect('hostal.db')
    c = conn.cursor()
    
    # Contar reservas pendientes
    c.execute("SELECT COUNT(*) FROM reservas WHERE estado = 'pendiente'")
    pendientes = c.fetchone()[0]
    
    # Contar reservas confirmadas
    c.execute("SELECT COUNT(*) FROM reservas WHERE estado = 'confirmada'")
    confirmadas = c.fetchone()[0]
    
    # Total de reservas
    c.execute("SELECT COUNT(*) FROM reservas")
    total_reservas = c.fetchone()[0]
    
    # Últimas 5 reservas
    c.execute('''SELECT nombre_cliente, email_cliente, tipo_habitacion, 
                 fecha_entrada, fecha_salida, estado 
                 FROM reservas ORDER BY fecha_reserva DESC LIMIT 5''')
    ultimas_reservas = c.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html',
                         pendientes=pendientes,
                         confirmadas=confirmadas,
                         total_reservas=total_reservas,
                         ultimas_reservas=ultimas_reservas,
                         now=datetime.now())


# Ruta de logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada exitosamente.', 'info')
    return redirect(url_for('login'))

# Ruta para registrar nuevos usuarios (solo administradores)
@app.route('/registrar-usuario', methods=['GET', 'POST'])
@login_required
@admin_required
def registrar_usuario():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        nombre = request.form['nombre']
        email = request.form['email']
        rol = request.form['rol']
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        conn = sqlite3.connect('hostal.db')
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO usuarios (username, password, nombre, email, rol)
                         VALUES (?, ?, ?, ?, ?)''',
                      (username, hashed_password, nombre, email, rol))
            conn.commit()
            flash('Usuario registrado exitosamente.', 'success')
        except sqlite3.IntegrityError:
            flash('El nombre de usuario ya existe.', 'danger')
        finally:
            conn.close()
        
        return redirect(url_for('registrar_usuario'))
    
    conn = sqlite3.connect('hostal.db')
    c = conn.cursor()
    c.execute("SELECT * FROM usuarios ORDER BY fecha_registro DESC")
    usuarios = c.fetchall()
    conn.close()
    
    return render_template('registrar_usuario.html', usuarios=usuarios)


@app.route('/registro-cliente', methods=['GET', 'POST'])
def registro_cliente():
    if request.method == 'POST':
        try:
            # Obtener datos del formulario
            username = request.form['username']
            password = request.form['password']
            nombre = request.form['nombre']
            email = request.form['email']
            telefono = request.form.get('telefono', '')
            documento_identidad = request.form.get('documento_identidad', '')
            
            # Validaciones básicas
            if len(password) < 6:
                flash('La contraseña debe tener al menos 6 caracteres.', 'warning')
                return render_template('registro_cliente.html')
            
            # Rol por defecto: cliente
            rol = 'cliente'
            
            # Hashear la contraseña
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # Guardar en base de datos
            conn = sqlite3.connect('hostal.db')
            c = conn.cursor()
            
            try:
                c.execute('''INSERT INTO usuarios (username, password, nombre, email, telefono, documento_identidad, rol)
                             VALUES (?, ?, ?, ?, ?, ?, ?)''',
                          (username, hashed_password, nombre, email, telefono, documento_identidad, rol))
                conn.commit()
                
                # Iniciar sesión automáticamente
                c.execute("SELECT id, username, nombre, rol FROM usuarios WHERE username = ?", (username,))
                user = c.fetchone()
                
                if user:
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    session['nombre'] = user[2]
                    session['rol'] = user[3]
                    
                    flash(f'¡Cuenta creada exitosamente! Bienvenido/a, {nombre}.', 'success')
                    
                    # Redirigir según rol
                    if user[3] == 'cliente':
                        return redirect(url_for('index'))
                    else:
                        return redirect(url_for('dashboard'))
                
            except sqlite3.IntegrityError as e:
                error_msg = str(e)
                if 'UNIQUE constraint failed: usuarios.username' in error_msg:
                    flash('El nombre de usuario ya está registrado. Por favor, elige otro.', 'danger')
                elif 'UNIQUE constraint failed: usuarios.email' in error_msg:
                    flash('El correo electrónico ya está registrado. Por favor, usa otro.', 'danger')
                else:
                    flash('Error al crear la cuenta. Por favor, intenta nuevamente.', 'danger')
            
            finally:
                conn.close()
        
        except Exception as e:
            flash(f'Error inesperado: {str(e)}', 'danger')
    
    # GET request o si hay error en POST
    return render_template('registro_cliente.html')

@app.route('/mi-cuenta')
@login_required
def perfil_cliente():
    # Verificar que el usuario sea cliente
    if session.get('rol') != 'cliente':
        flash('Acceso no autorizado.', 'warning')
        return redirect(url_for('dashboard'))
    
    # Obtener datos del cliente
    conn = sqlite3.connect('hostal.db')
    c = conn.cursor()
    
    # Obtener información personal
    c.execute("SELECT nombre, email, telefono, documento_identidad, fecha_registro FROM usuarios WHERE id = ?", 
              (session['user_id'],))
    datos_cliente = c.fetchone()
    
    # Obtener reservas del cliente (usando el email)
    c.execute('''SELECT * FROM reservas 
                 WHERE email_cliente = ? 
                 ORDER BY fecha_entrada DESC''', 
              (datos_cliente[1],))  # email está en posición 1
    mis_reservas = c.fetchall()
    
    conn.close()
    
    return render_template('perfil_cliente.html', 
                         datos=datos_cliente, 
                         reservas=mis_reservas)


# Ruta para ver todas las reservas
@app.route('/reservas')
@login_required
def ver_reservas():
    conn = sqlite3.connect('hostal.db')
    c = conn.cursor()
    c.execute('''SELECT * FROM reservas ORDER BY fecha_reserva DESC''')
    reservas = c.fetchall()
    conn.close()
    
    return render_template('reservas.html', reservas=reservas)

# Ruta para cambiar estado de reserva
@app.route('/cambiar-estado/<int:reserva_id>/<estado>')
@login_required
def cambiar_estado(reserva_id, estado):
    conn = sqlite3.connect('hostal.db')
    c = conn.cursor()
    c.execute('''UPDATE reservas SET estado = ? WHERE id = ?''', (estado, reserva_id))
    conn.commit()
    conn.close()
    
    flash(f'Reserva {estado} exitosamente.', 'success')
    return redirect(url_for('ver_reservas'))

# Tus rutas existentes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=True)