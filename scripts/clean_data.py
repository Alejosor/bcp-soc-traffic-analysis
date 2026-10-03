import pandas as pd
import numpy as np

# 1. Cargar los datos
df = pd.read_csv("./data/raw/cybersecurity_attacks.csv")

# 2. Tratamiento de nulos
cols_with_nulls = ['Malware Indicators', 'Alerts/Warnings', 'Proxy Information', 'Firewall Logs', 'IDS/IPS Alerts']
for col in cols_with_nulls:
    df[col] = df[col].fillna("No Detectado")

# 3. Estandarización de fecha y hora
df['Timestamp'] = pd.to_datetime(df['Timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')

# 4. Catálogo de ciudades y regiones congruentes de Perú
peru_locations = [
    ("Lima", "Lima"),
    ("Chiclayo", "Lambayeque"),
    ("Trujillo", "La Libertad"),
    ("Arequipa", "Arequipa"),
    ("Cusco", "Cusco"),
    ("Piura", "Piura"),
    ("Iquitos", "Loreto"),
    ("Huancayo", "Junín"),
    ("Cajamarca", "Cajamarca"),
    ("Pucallpa", "Ucayali"),
    ("Tacna", "Tacna"),
    ("Ica", "Ica"),
    ("Juliaca", "Puno"),
    ("Chimbote", "Áncash"),
    ("Tarapoto", "San Martín")
]

# 5. Asignación aleatoria a los 40,000 registros
np.random.seed(42) # Semilla para mantener los resultados fijos
random_indices = np.random.choice(len(peru_locations), size=len(df))

# 6. Creación de las nuevas columnas y eliminación de la antigua
df['City'] = [peru_locations[i][0] for i in random_indices]
df['Region'] = [peru_locations[i][1] for i in random_indices]
df = df.drop(columns=['Geo-location Data'])

# 7. Transformación de nombres de usuario (Contexto BCP - Nombres peruanos)
nombres_masc = ["Luis", "Juan", "Carlos", "Jose", "Jorge", "Victor", "Miguel", "Julio", "Jesus", "Pedro", "Diego", "Alejandro", "Marco"]
nombres_fem = ["Maria", "Rosa", "Ana", "Carmen", "Marta", "Julia", "Patricia", "Diana", "Silvia", "Rocio", "Teresa", "Elena", "Flor"]
apellidos = ["Garcia", "Sanchez", "Flores", "Rodriguez", "Rojas", "Diaz", "Chuquilin", "Gonzales", "Perez", "Chavez", "Quispe", "Mamani", "Ramos", "Vargas", "Mendoza", "Castillo"]

nombres_completos = []
for _ in range(len(df)):
    # 50% probabilidad de ser hombre o mujer
    nombre = np.random.choice(nombres_masc) if np.random.rand() > 0.5 else np.random.choice(nombres_fem)
    nombres_completos.append(f"{nombre} {np.random.choice(apellidos)} {np.random.choice(apellidos)}")

df['User Information'] = nombres_completos

# 8. Adaptación de la Arquitectura de Red (Contexto Bancario)
segment_mapping = {
    'Segment A': 'DMZ',
    'Segment B': 'Internal Core',
    'Segment C': 'Corporate Network'
}
df['Network Segment'] = df['Network Segment'].replace(segment_mapping)

# 9. Normalizar nombres de columnas (Quitar espacios y caracteres especiales)
df.columns = df.columns.str.replace(' ', '_').str.replace('/', '_').str.replace('-', '_')

# 10. Exportar el nuevo CSV limpio
df.to_csv("./data/processed/cybersecurity_peru_cleaned.csv", index=False)
print("¡Archivo limpio generado con éxito!")