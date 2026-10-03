-- ==============================================================================
-- 🛡️ SCRIPT DDL: CREACIÓN DE ESQUEMA BCP SOC 
-- ==============================================================================

-- Se crea la base de datos en donde se va a trabajar
CREATE DATABASE BcpSOC;
GO
USE BcpSOC;
GO

-- ==============================================================================
-- 1. CREACIÓN DE LA TABLA STAGING (Para recibir el CSV plano)
-- ==============================================================================
CREATE TABLE Staging_Logs (
    Timestamp DATETIME,
    Source_IP VARCHAR(50),
    Destination_IP VARCHAR(50),
    Source_Port INT,
    Destination_Port INT,
    Protocol VARCHAR(20),
    Packet_Length INT,
    Packet_Type VARCHAR(50),
    Traffic_Type VARCHAR(50),
    Payload_Data VARCHAR(MAX),
    Malware_Indicators VARCHAR(100),
    Anomaly_Scores DECIMAL(10,2),
    Alerts_Warnings VARCHAR(100),
    Attack_Type VARCHAR(100),
    Attack_Signature VARCHAR(255),
    Action_Taken VARCHAR(50),
    Severity_Level VARCHAR(50),
    User_Information VARCHAR(255),
    Device_Information VARCHAR(255),
    Network_Segment VARCHAR(50),
    Proxy_Information VARCHAR(50),
    Firewall_Logs VARCHAR(100),
    IDS_IPS_Alerts VARCHAR(100),
    Log_Source VARCHAR(100),
    City VARCHAR(100),
    Region VARCHAR(100)
);

-- ⚠️ IMPORTANTE: En este punto, se debe usar el "Import Flat File Wizard" de SQL Server 
-- Management Studio (SSMS) para cargar el archivo 'cybersecurity_peru_cleaned.csv' 
-- directamente dentro de la tabla 'Staging_Logs'.

-- ==============================================================================
-- 2. CREACIÓN DEL MODELO ESTRELLA (Dimensiones y Hechos)
-- ==============================================================================

-- Dimensión 1: Usuarios
CREATE TABLE Dim_Usuarios (
    ID_Usuario INT IDENTITY(1,1) PRIMARY KEY,
    Nombre_Completo VARCHAR(255)
);

-- Dimensión 2: Orígenes y Dispositivos
CREATE TABLE Dim_Dispositivos_Red (
    ID_Dispositivo INT IDENTITY(1,1) PRIMARY KEY,
    Source_IP VARCHAR(50),
    Device_Information VARCHAR(255),
    City VARCHAR(100),
    Region VARCHAR(100),
    Network_Segment VARCHAR(50),
    Proxy_Information VARCHAR(50)
);

-- Dimensión 3: Catálogo de Amenazas
CREATE TABLE Dim_Amenazas (
    ID_Amenaza INT IDENTITY(1,1) PRIMARY KEY,
    Attack_Type VARCHAR(100),
    Attack_Signature VARCHAR(255),
    Malware_Indicators VARCHAR(100),
    Severity_Level VARCHAR(50)
);

-- Tabla de Hechos: Tráfico Web
CREATE TABLE Fact_Trafico_Web (
    ID_Log INT IDENTITY(1,1) PRIMARY KEY,
    ID_Usuario INT FOREIGN KEY REFERENCES Dim_Usuarios(ID_Usuario),
    ID_Dispositivo INT FOREIGN KEY REFERENCES Dim_Dispositivos_Red(ID_Dispositivo),
    ID_Amenaza INT FOREIGN KEY REFERENCES Dim_Amenazas(ID_Amenaza),
    
    Event_Timestamp DATETIME,
    Destination_IP VARCHAR(50),
    Source_Port INT,
    Destination_Port INT,
    Protocol VARCHAR(20),
    Traffic_Type VARCHAR(50),
    Packet_Type VARCHAR(50),
    Packet_Length INT,
    Anomaly_Score DECIMAL(10,2),
    Alerts_Warnings VARCHAR(100),
    Action_Taken VARCHAR(50),
    Firewall_Logs VARCHAR(100),
    IDS_IPS_Alerts VARCHAR(100),
    Log_Source VARCHAR(100)
);

-- ==============================================================================
-- 3. POBLAR LAS TABLAS (ETL: Extracción, Transformación y Carga)
-- ==============================================================================

-- Poblar Dim_Usuarios
INSERT INTO Dim_Usuarios (Nombre_Completo)
SELECT DISTINCT User_Information 
FROM Staging_Logs;

INSERT INTO Dim_Dispositivos_Red (Source_IP, Device_Information, City, Region, Network_Segment, Proxy_Information)
SELECT DISTINCT Source_IP_Address, Device_Information, City, Region, Network_Segment, Proxy_Information
FROM Staging_Logs;

INSERT INTO Dim_Amenazas (Attack_Type, Attack_Signature, Malware_Indicators, Severity_Level)
SELECT DISTINCT Attack_Type, Attack_Signature, Malware_Indicators, Severity_Level
FROM Staging_Logs;

INSERT INTO Fact_Trafico_Web (
    ID_Usuario, ID_Dispositivo, ID_Amenaza, Event_Timestamp, Destination_IP, 
    Source_Port, Destination_Port, Protocol, Traffic_Type, Packet_Type, 
    Packet_Length, Anomaly_Score, Alerts_Warnings, Action_Taken, 
    Firewall_Logs, IDS_IPS_Alerts, Log_Source
)
SELECT 
    u.ID_Usuario,
    d.ID_Dispositivo,
    a.ID_Amenaza,
    s.Timestamp,
    s.Destination_IP_Address,
    s.Source_Port,
    s.Destination_Port,
    s.Protocol,
    s.Traffic_Type,
    s.Packet_Type,
    s.Packet_Length,
    s.Anomaly_Scores,
    s.Alerts_Warnings,
    s.Action_Taken,
    s.Firewall_Logs,
    s.IDS_IPS_Alerts,
    s.Log_Source
FROM Staging_Logs s
LEFT JOIN Dim_Usuarios u ON s.User_Information = u.Nombre_Completo
LEFT JOIN Dim_Dispositivos_Red d ON 
    s.Source_IP_Address = d.Source_IP AND 
    s.Device_Information = d.Device_Information AND 
    s.City = d.City AND 
    s.Region = d.Region AND 
    s.Network_Segment = d.Network_Segment AND
    s.Proxy_Information = d.Proxy_Information
LEFT JOIN Dim_Amenazas a ON 
    s.Attack_Type = a.Attack_Type AND 
    s.Attack_Signature = a.Attack_Signature AND 
    s.Severity_Level = a.Severity_Level AND
    s.Malware_Indicators = a.Malware_Indicators;

-- Opcional: Eliminar la tabla Staging para liberar espacio una vez finalizado
DROP TABLE Staging_Logs;