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