# Segunda fase: reconstrucción desde PCAP

Esta fase se decidió después de inspeccionar los resultados del CSV. Todas sus comparaciones predictivas son exploratorias; no constituyen un test nuevo e intacto.

## Preguntas

1. ¿Son diferentes adquisiciones? Verificar fechas, hashes, duración y coincidencia exacta de ransomware-3 con el CSV.
2. ¿Las observaciones repetidas contienen bytes idénticos? Comparar literalmente bytes de red dentro de 1 ms del primer registro de cada grupo, excluyendo solo la cabecera Linux SLL. Conservar los originales y una vista derivada.
3. ¿Se reconstruyen los fragmentos? Usar TShark con dos pasadas, reensamblado IPv4 explícito y resolución de nombres desactivada; conservar números de trama y comandos.
4. ¿Qué información interior falta en el CSV? Separar direcciones/longitudes exteriores e interiores y documentar qué capa se estudia.
5. ¿Cambian las conclusiones usando datagramas interiores y direccionalidad? Mantener clasificadores, umbral 0,5, exclusión temporal y selección dentro del entrenamiento. Comparar sin elegir retrospectivamente la mejor prueba.

## Etiquetas y límites

El registro disponible pertenece al 7 de noviembre de 2025 y a dos dispositivos nombrados. Debe comprobarse contra todos los registros del CSV. El nombre de un archivo o una conexión a un dominio no autoriza a inventar tiempos de ataque para octubre. Sin registro adicional, ransomware-2 se tratará como captura sin etiquetas verificadas, no como test externo de detección.

Las IP, dominios, TEID, números de trama, tiempos absolutos y flujos identificados se usarán solo para reconstrucción y auditoría; no como predictores. Una etiqueta de período no prueba que cada paquete o flujo sea malicioso. No se atribuirán nombres físicos a las IP por mera coincidencia temporal.

Los originales permanecen en recursos. Los resultados del CSV se conservan como primera fase. Si la reconstrucción no mejora la predicción, se informará también. No se ejecuta el tráfico ni el malware: solo se procesan capturas offline.

## Comparación de representación por ventanas

Se mantienen las mismas ventanas y particiones de la primera fase (2 s principal; 1 y 5 s sensibilidad). Se exportan características de tamaño y tiempo del datagrama interior, direccionalidad y cabeceras de transporte; las longitudes declaradas y bytes observados se distinguen. Una vista usa solo datagramas completos y otra añade cabeceras completas de primeros fragmentos con cuerpo incompleto. No se imputa ni se reconstruye la cola ausente. RF y regresión logística mantienen sus parámetros y umbral. La selección de cinco características se realiza exclusivamente en entrenamiento. Se guardan todas las combinaciones.

## Pregunta distinta: identificación del servicio experimental entre sesiones

Se añade una tarea separada, explícitamente distinta de detectar ejecución de ransomware. Las conexiones TCP con SNI observado se anotan como servicio experimental (dominio documentado en el correo) u otro servicio identificado; conexiones sin SNI o con nombres contradictorios se excluyen. Es una etiqueta derivada de metadatos de conexión, no verdad-terreno de infección o malicia. El dominio, IP, puertos, TEID, identificadores, tiempos absolutos y contenido TLS no son entradas del modelo.

Entrenar con todas las conexiones anotadas de octubre y evaluar con las de noviembre. No utilizar el registro de noviembre para inventar etiquetas de octubre. Evaluar RF y regresión logística fijos, con grupos de tamaño/tiempo, direccionalidad y selección de cinco características. La representación principal considera los primeros 20 paquetes de cada conexión, acotados a los primeros 10 segundos; se guarda también una vista de conexión completa como sensibilidad retrospectiva. No optimizar hiperparámetros ni umbral en noviembre. Características de tamaños pueden reflejar clientes y servicios; incluso un resultado alto no demuestra una firma del ransomware ni transferencia a otras familias/servidores. La dependencia entre conexiones del mismo dispositivo/servicio se informará.
