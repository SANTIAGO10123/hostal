# Flask y extensiones
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bcrypt import Bcrypt

# Python estándar
import sqlite3
import os
from functools import wraps
from datetime import datetime, timedelta

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
from datetime import datetime, timedelta

@app.route('/reservas')
@login_required
def ver_reservas():
    # Solo admin y recepcionistas pueden ver todas las reservas
    if session.get('rol') not in ['administrador', 'recepcionista']:
        flash('Acceso no autorizado.', 'warning')
        return redirect(url_for('perfil_cliente'))
    
    # Obtener parámetros de filtro
    filtro_estado = request.args.get('estado', '')
    filtro_tipo = request.args.get('tipo', '')
    filtro_desde = request.args.get('desde', '')
    filtro_hasta = request.args.get('hasta', '')
    filtro_busqueda = request.args.get('busqueda', '')
    
    conn = sqlite3.connect('hostal.db')
    c = conn.cursor()
    
    # Construir consulta con filtros
    query = "SELECT * FROM reservas WHERE 1=1"
    params = []
    
    if filtro_estado:
        query += " AND estado = ?"
        params.append(filtro_estado)
    
    if filtro_tipo:
        query += " AND tipo_habitacion = ?"
        params.append(filtro_tipo)
    
    if filtro_desde:
        query += " AND fecha_entrada >= ?"
        params.append(filtro_desde)
    
    if filtro_hasta:
        query += " AND fecha_entrada <= ?"
        params.append(filtro_hasta)
    
    if filtro_busqueda:
        query += " AND (nombre_cliente LIKE ? OR email_cliente LIKE ? OR telefono LIKE ?)"
        search_term = f"%{filtro_busqueda}%"
        params.extend([search_term, search_term, search_term])
    
    query += " ORDER BY fecha_entrada DESC"
    
    # Ejecutar consulta
    c.execute(query, params)
    reservas = c.fetchall()
    
    # Obtener estadísticas
    c.execute("SELECT COUNT(*) FROM reservas WHERE estado = 'pendiente'")
    pendientes = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM reservas WHERE estado = 'confirmada'")
    confirmadas = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM reservas WHERE estado = 'cancelada'")
    canceladas = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM reservas")
    total = c.fetchone()[0]
    
    conn.close()
    
    # Fechas para highlights
    hoy = datetime.now().strftime('%Y-%m-%d')
    manana = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    
    return render_template('reservas.html',
                         reservas=reservas,
                         estadisticas={
                             'pendientes': pendientes,
                             'confirmadas': confirmadas,
                             'canceladas': canceladas,
                             'total': total
                         },
                         filtro_estado=filtro_estado,
                         filtro_tipo=filtro_tipo,
                         filtro_desde=filtro_desde,
                         filtro_hasta=filtro_hasta,
                         filtro_busqueda=filtro_busqueda,
                         hoy=hoy,
                         manana=manana)

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

@app.route('/api/reserva-detalles/<int:reserva_id>')
@login_required
def reserva_detalles(reserva_id):
    if session.get('rol') not in ['administrador', 'recepcionista']:
        return jsonify({'error': 'No autorizado'}), 403
    
    conn = sqlite3.connect('hostal.db')
    c = conn.cursor()
    
    c.execute("SELECT * FROM reservas WHERE id = ?", (reserva_id,))
    reserva = c.fetchone()
    conn.close()
    
    if not reserva:
        return jsonify({'error': 'Reserva no encontrada'}), 404
    
    # Convertir a diccionario
    column_names = ['id', 'nombre_cliente', 'email_cliente', 'telefono',
                   'fecha_entrada', 'fecha_salida', 'tipo_habitacion',
                   'numero_personas', 'estado', 'fecha_reserva', 'usuario_id']
    
    reserva_dict = dict(zip(column_names, reserva))
    
    # Formatear fechas
    reserva_dict['fecha_entrada'] = reserva_dict['fecha_entrada']
    reserva_dict['fecha_salida'] = reserva_dict['fecha_salida']
    reserva_dict['fecha_reserva'] = reserva_dict['fecha_reserva']
    
    return jsonify(reserva_dict)    

from datetime import datetime, date

# Ruta para mostrar formulario de reserva
@app.route('/reservar', methods=['GET', 'POST'])
def reservar():
    hoy = date.today().isoformat()
    return render_template('form_reserva.html', hoy=hoy)

# Ruta para procesar reserva
@app.route('/crear-reserva', methods=['POST'])
def crear_reserva():
    try:
        # Obtener datos del formulario
        nombre_cliente = request.form['nombre']
        email_cliente = request.form['email']
        telefono = request.form['telefono']
        fecha_entrada = request.form['fecha_entrada']
        fecha_salida = request.form['fecha_salida']
        tipo_habitacion = request.form['tipo_habitacion']
        numero_personas = int(request.form['numero_personas'])
        observaciones = request.form.get('observaciones', '')
        
        # Validar fechas
        entrada = datetime.strptime(fecha_entrada, '%Y-%m-%d').date()
        salida = datetime.strptime(fecha_salida, '%Y-%m-%d').date()
        
        if salida <= entrada:
            flash('La fecha de salida debe ser posterior a la de entrada.', 'danger')
            return redirect(url_for('reservar'))
        
        if entrada < date.today():
            flash('No se pueden hacer reservas en fechas pasadas.', 'danger')
            return redirect(url_for('reservar'))
        
        # Verificar disponibilidad (simplificado - en un sistema real se verificaría contra la BD)
        conn = sqlite3.connect('hostal.db')
        c = conn.cursor()
        
        # Consultar si hay reservas que se solapen
        c.execute('''SELECT COUNT(*) FROM reservas 
                     WHERE tipo_habitacion = ? 
                     AND estado IN ('pendiente', 'confirmada')
                     AND (
                         (fecha_entrada <= ? AND fecha_salida >= ?) OR
                         (fecha_entrada <= ? AND fecha_salida >= ?) OR
                         (fecha_entrada >= ? AND fecha_salida <= ?)
                     )''', 
                  (tipo_habitacion, fecha_salida, fecha_entrada, 
                   fecha_salida, fecha_entrada, fecha_entrada, fecha_salida))
        
        solapamientos = c.fetchone()[0]
        
        if solapamientos > 0:
            flash(f'Lo sentimos, la {tipo_habitacion} no está disponible en esas fechas.', 'warning')
            return redirect(url_for('reservar'))
        
        # Obtener usuario_id si está logueado
        usuario_id = session.get('user_id') if session.get('rol') == 'cliente' else None
        
        # Insertar reserva
        c.execute('''INSERT INTO reservas 
                     (nombre_cliente, email_cliente, telefono, fecha_entrada, 
                      fecha_salida, tipo_habitacion, numero_personas, observaciones, usuario_id)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (nombre_cliente, email_cliente, telefono, fecha_entrada, 
                   fecha_salida, tipo_habitacion, numero_personas, observaciones, usuario_id))
        
        conn.commit()
        reserva_id = c.lastrowid
        conn.close()
        
        # Preparar mensaje de éxito
        dias = (salida - entrada).days
        mensaje = f'¡Reserva #{reserva_id} confirmada! {nombre_cliente}, tu reserva para {tipo_habitacion} '
        mensaje += f'del {fecha_entrada} al {fecha_salida} ({dias} noches) ha sido registrada.'
        
        flash(mensaje, 'success')
        
        # Redirigir según el usuario
        if usuario_id:
            return redirect(url_for('perfil_cliente'))
        else:
            return redirect(url_for('reservar'))
            
    except Exception as e:
        flash(f'Error al crear la reserva: {str(e)}', 'danger')
        return redirect(url_for('reservar'))

# Ruta para cancelar reserva
@app.route('/cancelar-reserva/<int:reserva_id>')
@login_required
def cancelar_reserva(reserva_id):
    conn = sqlite3.connect('hostal.db')
    c = conn.cursor()
    
    # Verificar permisos
    if session.get('rol') == 'cliente':
        # Cliente solo puede cancelar sus propias reservas
        c.execute('''SELECT email_cliente FROM reservas WHERE id = ?''', (reserva_id,))
        reserva = c.fetchone()
        
        if not reserva or reserva[0] != session.get('email'):
            flash('No tienes permiso para cancelar esta reserva.', 'danger')
            return redirect(url_for('perfil_cliente'))
    
    # Actualizar estado
    c.execute('''UPDATE reservas SET estado = 'cancelada' WHERE id = ?''', (reserva_id,))
    conn.commit()
    conn.close()
    
    flash('Reserva cancelada exitosamente.', 'success')
    
    # Redirigir según el usuario
    if session.get('rol') == 'cliente':
        return redirect(url_for('perfil_cliente'))
    else:
        return redirect(url_for('ver_reservas'))

# Ruta para ver detalles de una reserva
@app.route('/reserva/<int:reserva_id>')
@login_required
def ver_reserva(reserva_id):
    conn = sqlite3.connect('hostal.db')
    c = conn.cursor()
    
    c.execute('''SELECT * FROM reservas WHERE id = ?''', (reserva_id,))
    reserva = c.fetchone()
    conn.close()
    
    if not reserva:
        flash('Reserva no encontrada.', 'danger')
        return redirect(url_for('index'))
    
    # Verificar permisos
    if session.get('rol') == 'cliente' and reserva[2] != session.get('email'):
        flash('No tienes permiso para ver esta reserva.', 'danger')
        return redirect(url_for('perfil_cliente'))
    
    column_names = ['id', 'nombre_cliente', 'email_cliente', 'telefono',
                   'fecha_entrada', 'fecha_salida', 'tipo_habitacion',
                   'numero_personas', 'estado', 'fecha_reserva', 'usuario_id', 'observaciones']
    
    reserva_dict = dict(zip(column_names, reserva))
    
    return render_template('detalle_reserva.html', reserva=reserva_dict)