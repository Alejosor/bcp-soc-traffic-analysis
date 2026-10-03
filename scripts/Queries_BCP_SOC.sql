/**
Pregunta #1: ¿Cuáles son las 5 ciudades peruanas desde donde se origina la mayor cantidad de ataques contra 
la Banca por Internet?
**/
-- Top 5 Ciudades con mayor cantidad de ataques registrados
SELECT TOP 5
    d.City,
    d.Region,
    COUNT(f.ID_Log) AS Total_Ataques
FROM Fact_Trafico_Web f
JOIN Dim_Dispositivos_Red d ON f.ID_Dispositivo = d.ID_Dispositivo
GROUP BY 
    d.City,
    d.Region
ORDER BY 
    Total_Ataques DESC;


/**
Pregunta #2: ¿Qué porcentaje del tráfico clasificado con severidad "Alta" logró evadir los controles de seguridad 
y fue catalogado como ignorado (Action_Taken = 'Ignored')?
**/
-- Porcentaje de evasión para amenazas de Severidad Alta
SELECT 
    COUNT(f.ID_Log) AS Total_Amenazas_Altas,
    SUM(CASE WHEN f.Action_Taken = 'Ignored' THEN 1 ELSE 0 END) AS Amenazas_Evadidas,
    ROUND(SUM(CASE WHEN f.Action_Taken = 'Ignored' THEN 1 ELSE 0 END) * 100.0 / COUNT(f.ID_Log), 2) AS Porcentaje_Evasion
FROM Fact_Trafico_Web f
JOIN Dim_Amenazas a ON f.ID_Amenaza = a.ID_Amenaza
WHERE a.Severity_Level = 'High';


/**
Pregunta #3: ¿Qué volumen de ataques de tipo "Malware" logró alcanzar el segmento crítico 
Internal Core en comparación con los mitigados en la DMZ?
**/
-- Distribución de penetración de Malware por segmento de red
SELECT 
    d.Network_Segment,
    COUNT(f.ID_Log) AS Volumen_Malware
FROM Fact_Trafico_Web f
JOIN Dim_Amenazas a ON f.ID_Amenaza = a.ID_Amenaza
JOIN Dim_Dispositivos_Red d ON f.ID_Dispositivo = d.ID_Dispositivo
WHERE a.Attack_Type = 'Malware' 
  AND d.Network_Segment IN ('Internal Core', 'DMZ')
GROUP BY d.Network_Segment
ORDER BY Volumen_Malware DESC;


/**
Pregunta #4: ¿Cuáles son las horas del día (madrugada vs. horario de oficina) que concentran el mayor 
volumen de peticiones anómalas en los servidores de autenticación?
**/
-- Análisis temporal de picos de anomalías
SELECT 
    DATEPART(HOUR, Event_Timestamp) AS Hora_Del_Dia,
    COUNT(ID_Log) AS Volumen_Peticiones,
    ROUND(AVG(Anomaly_Score), 2) AS Promedio_Score_Anomalia
FROM Fact_Trafico_Web
GROUP BY DATEPART(HOUR, Event_Timestamp)
ORDER BY Volumen_Peticiones DESC;


/**
Pregunta #5: ¿Desde qué regiones específicas del Perú se originan los 
picos más altos en las puntuaciones de anomalía (Anomaly Scores)?
**/
-- Distribución de Anomalías por Región
SELECT TOP 5
    d.Region,
    COUNT(f.ID_Log) AS Total_Peticiones,
    ROUND(AVG(f.Anomaly_Score), 2) AS Promedio_Score_Anomalia,
    MAX(f.Anomaly_Score) AS Score_Maximo_Registrado
FROM Fact_Trafico_Web f
JOIN Dim_Dispositivos_Red d ON f.ID_Dispositivo = d.ID_Dispositivo
GROUP BY d.Region
ORDER BY Promedio_Score_Anomalia DESC;


/**
Pregunta #6: ¿Cuáles son las 3 firmas de ataque (Attack_Signature) más utilizadas por los 
cibercriminales para intentar vulnerar el sistema del BCP?
**/
-- Top 3 firmas de ataque más frecuentes
SELECT TOP 3
    a.Attack_Signature,
    COUNT(f.ID_Log) AS Frecuencia_Ataque
FROM Fact_Trafico_Web f
JOIN Dim_Amenazas a ON f.ID_Amenaza = a.ID_Amenaza
GROUP BY a.Attack_Signature
ORDER BY Frecuencia_Ataque DESC;


/**
Pregunta #7: ¿Qué perfiles de agentes de usuario (Device_Information) han detonado 
la mayor cantidad de alertas críticas del sistema IDS/IPS?
**/
-- Top 5 Dispositivos/User-Agents con más alertas IDS/IPS
SELECT TOP 5
    d.Device_Information,
    COUNT(f.ID_Log) AS Total_Alertas_Seguridad
FROM Fact_Trafico_Web f
JOIN Dim_Dispositivos_Red d ON f.ID_Dispositivo = d.ID_Dispositivo
WHERE f.IDS_IPS_Alerts != 'No Detectado'
GROUP BY d.Device_Information
ORDER BY Total_Alertas_Seguridad DESC;


/**
Pregunta #8: ¿Cuál es la tasa de éxito del firewall (Action_Taken = 'Blocked') al enfrentar tráfico 
oculto detrás de Proxies en comparación con conexiones directas?
**/
-- Efectividad de bloqueos: Proxies vs Conexiones Directas
SELECT 
    CASE 
        WHEN d.Proxy_Information = 'No Detectado' THEN 'Conexión Directa'
        ELSE 'Trafico Oculto (Proxy)' 
    END AS Tipo_Conexion,
    COUNT(f.ID_Log) AS Total_Peticiones,
    SUM(CASE WHEN f.Action_Taken = 'Blocked' THEN 1 ELSE 0 END) AS Bloqueos_Exitosos,
    ROUND(SUM(CASE WHEN f.Action_Taken = 'Blocked' THEN 1 ELSE 0 END) * 100.0 / COUNT(f.ID_Log), 2) AS Tasa_de_Bloqueo
FROM Fact_Trafico_Web f
JOIN Dim_Dispositivos_Red d ON f.ID_Dispositivo = d.ID_Dispositivo
GROUP BY 
    CASE 
        WHEN d.Proxy_Information = 'No Detectado' THEN 'Conexión Directa'
        ELSE 'Trafico Oculto (Proxy)' 
    END;


/**
Pregunta #9: ¿Qué protocolo de comunicación está mayormente asociado a los ataques de denegación de 
servicio (DDoS) que buscan generar caídas intermitentes en la banca por internet?
**/
-- Protocolos de comunicación preferidos en ataques DDoS
SELECT 
    f.Protocol,
    COUNT(f.ID_Log) AS Volumen_Peticiones_DDoS
FROM Fact_Trafico_Web f
JOIN Dim_Amenazas a ON f.ID_Amenaza = a.ID_Amenaza
WHERE a.Attack_Type = 'DDoS'
GROUP BY f.Protocol
ORDER BY Volumen_Peticiones_DDoS DESC;


/**
Pregunta #10: ¿Qué porcentaje de las alertas de seguridad se originan de manera inusual 
dentro de la red interna de empleados (Corporate Network)?
**/
-- Volumen y proporción de amenazas originadas internamente (Insider Threats)
SELECT 
    d.Network_Segment,
    COUNT(f.ID_Log) AS Total_Alertas,
    ROUND(COUNT(f.ID_Log) * 100.0 / (SELECT COUNT(*) FROM Fact_Trafico_Web WHERE Alerts_Warnings != 'No Detectado'), 2) AS Porcentaje_Del_Total
FROM Fact_Trafico_Web f
JOIN Dim_Dispositivos_Red d ON f.ID_Dispositivo = d.ID_Dispositivo
WHERE f.Alerts_Warnings != 'No Detectado'
GROUP BY d.Network_Segment
ORDER BY Total_Alertas DESC;


/**
Pregunta #11: ¿Cuáles son los indicadores de malware (Malware_Indicators) más detectados 
en los ataques que lograron infiltrarse exitosamente?
**/
-- Top 5 IoCs presentes en ataques no bloqueados
SELECT TOP 5
    a.Malware_Indicators,
    COUNT(f.ID_Log) AS Infiltraciones_Exitosas
FROM Fact_Trafico_Web f
JOIN Dim_Amenazas a ON f.ID_Amenaza = a.ID_Amenaza
WHERE f.Action_Taken != 'Blocked' 
  AND a.Malware_Indicators != 'No Detectado'
GROUP BY a.Malware_Indicators
ORDER BY Infiltraciones_Exitosas DESC;


/**
Pregunta #12: ¿Cuál es el promedio matemático del Anomaly Score dependiendo de si el 
nivel de severidad de la amenaza es Bajo, Medio o Alto?
**/
-- Correlación entre nivel de severidad y Anomaly Score
SELECT 
    a.Severity_Level,
    ROUND(AVG(f.Anomaly_Score), 2) AS Promedio_Score_Anomalia
FROM Fact_Trafico_Web f
JOIN Dim_Amenazas a ON f.ID_Amenaza = a.ID_Amenaza
GROUP BY a.Severity_Level
ORDER BY Promedio_Score_Anomalia DESC;


/**
Pregunta #13: ¿Existe algún tipo de tráfico web (Traffic_Type) que esté recurrentemente vinculado 
a intentos de intrusión que terminan siendo bloqueados?
**/
-- Tipos de tráfico web más bloqueados por el Firewall
SELECT 
    f.Traffic_Type,
    COUNT(f.ID_Log) AS Total_Bloqueos
FROM Fact_Trafico_Web f
WHERE f.Action_Taken = 'Blocked'
GROUP BY f.Traffic_Type
ORDER BY Total_Bloqueos DESC;


/**
Pregunta #14: ¿Existe una diferencia significativa en la longitud promedio de los paquetes de datos (Packet_Length) 
entre el tráfico bloqueado y el tráfico permitido?
**/
-- Evaluación del tamaño de paquetes (Payload) según la acción del firewall
SELECT 
    f.Action_Taken,
    ROUND(AVG(CAST(f.Packet_Length AS FLOAT)), 2) AS Promedio_Longitud_Paquete,
    MAX(f.Packet_Length) AS Maxima_Longitud_Registrada
FROM Fact_Trafico_Web f
GROUP BY f.Action_Taken
ORDER BY Promedio_Longitud_Paquete DESC;


/**
Pregunta #15: ¿Cómo se compara el volumen total de amenazas detectadas y detenidas 
por el Firewall de perímetro frente a las detenidas por el sistema IDS/IPS interno?
**/
-- Comparativa de carga defensiva: Firewall Perimetral vs IDS/IPS Interno
SELECT 
    SUM(CASE WHEN Firewall_Logs != 'No Detectado' THEN 1 ELSE 0 END) AS Detenidas_Por_Firewall,
    SUM(CASE WHEN IDS_IPS_Alerts != 'No Detectado' THEN 1 ELSE 0 END) AS Detenidas_Por_IDS_IPS
FROM Fact_Trafico_Web;