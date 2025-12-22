# fix_contacto.py - Ejecútalo en la carpeta templates
import os
import re

archivos = ['dashboard.html', 'perfil_cliente.html', 'reservas.html']

for archivo in archivos:
    ruta = os.path.join('templates', archivo)
    if os.path.exists(ruta):
        with open(ruta, 'r', encoding='utf-8') as f:
            contenido = f.read()
        
        # Reemplazar url_for('contacto') por url_for('contact')
        contenido_corregido = re.sub(
            r"url_for\('contacto'\)", 
            "url_for('contact')", 
            contenido
        )
        
        with open(ruta, 'w', encoding='utf-8') as f:
            f.write(contenido_corregido)
        
        print(f'✅ {archivo} corregido')
    else:
        print(f'❌ {archivo} no encontrado')