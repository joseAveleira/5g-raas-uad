# Qué cambia al recuperar los originales

Sí merece la pena continuar con una aportación concreta: un dataset 5G auditado desde los bytes, con recuperación de cabeceras y dos tareas cuyos significados se explican por separado. Ahora hay evidencia que el CSV solo no permitía obtener. Eso no garantiza la aceptación ni convierte el trabajo en un detector general de ransomware.

## 1. Dos adquisiciones reales y etiquetas comprobadas

Los PCAP son del 29 de octubre y del 7 de noviembre de 2025. El de noviembre coincide exactamente con los 107.694 registros del CSV en número de trama, timestamp a microsegundos y longitud. Su registro reproduce todas las etiquetas sin discrepancias. Octubre tiene 123.003 registros y no dispone de tiempos de ejecución verificados: no se han inventado etiquetas temporales.

## 2. Una aportación de red verificable

Se confirman 53.832 repeticiones de bytes de red en noviembre y 61.501 en octubre, excluyendo solo la cabecera SLL y usando 1 ms desde el primer registro. El CSV ocultaba las IP interiores y dejaba sin decodificar primeros fragmentos de GTP. Las colas de esos fragmentos no están en los archivos; no se pueden recuperar mágicamente.

Sí contienen cabeceras interiores completas: se recuperan 11.261 observaciones adicionales en noviembre y 15.668 en octubre. Se separan longitudes declaradas de bytes presentes, subida/bajada y conexiones. La decodificación coincide con TShark en 88.299 observaciones completas y con Scapy en una muestra estratificada de 1.261. La dirección coincide con el tipo del contenedor de sesión GTP en todas las observaciones recuperadas.

## 3. La prueba temporal mejora, con límites

En las mismas 48 ventanas de test de 2 segundos:

- RF direccional: BA 0,724 usando cuerpos completos y 0,786 añadiendo las cabeceras recuperadas.
- Regresión logística con cinco variables: BA 0,766 y 0,831, respectivamente. En la vista recuperada obtiene F1 0,846, con 5 falsas alarmas entre 23 ventanas normales y 3 omisiones entre 25 ventanas de ejecución.

No es una mejora universal: a 5 segundos el modelo compacto baja a BA 0,636, y los controles temporales siguen siendo competitivos. Dos de las cinco falsas alarmas ocurren tras el STOP, mientras siguen circulando paquetes de conexiones al servicio experimental. Se documenta el contexto, sin cambiar etiquetas ni descontar errores.

## 4. Utilidad entre días, con otra pregunta

Se anotan conexiones TCP por el SNI observado: servicio experimental u otro servicio. Se entrena con 170 conexiones de octubre (39 del servicio, 131 otras) y se prueba con 90 de noviembre (36 del servicio, 54 otras). Las conexiones sin SNI fiable quedan excluidas. IP, dominio, puertos, TEID, identificadores y tiempos absolutos no son predictores.

Usando como máximo los primeros 20 paquetes y los primeros 10 segundos de cada conexión:

- RF de tamaño/tiempo: BA 0,986.
- RF direccional: 90/90 conexiones correctamente clasificadas en este test pequeño.
- RF con cinco variables: BA 0,991 y F1 0,986; una falsa alarma y ninguna omisión. Reduce de 42 a 5 las variables retenidas de la representación direccional (88,1%).

Las cinco variables son media de tamaño en subida, media y desviación de tamaño en bajada, y desviación y percentil 90 de la ventana TCP sin escalar. No todos los modelos compactos funcionan igual: la regresión logística de cinco variables obtiene BA 0,884.

Ningún vector completo de características coincide entre días. Los refits reproducen los resultados. La puntuación del RF compacto sigue cerca de 0,988 al restringir la prueba a endpoints que también contactan el servicio o a otros dominios no vistos en entrenamiento. Los controles con etiquetas barajadas alcanzan como máximo 0,755.

**Esto es identificación del servicio experimental, no 99,1% de detección de ransomware.** Puede reflejar la aplicación, su cliente TLS, la biblioteca de red o el comportamiento del backend. Las conexiones comparten dispositivos y servicios, y solo hay dos días. Hace falta actividad legítima comparable contra el mismo backend para aislar mejor el efecto de la ejecución maliciosa.

## Enfoque que defendería en el artículo

Dataset de un experimento Android/5G con auditoría de captura, recuperación de representación, anotaciones temporales y de conexión separadas, y evaluación reproducible de utilidad. El papel de GTP es recuperar la capa y la dirección correctas; no afirmar que sus campos redundantes detectan ransomware.

La revisión ya incorpora estos resultados en el LaTeX. La versión basada solo en CSV queda archivada. Antes del envío, los coautores deben confirmar el contexto de las capturas y la anotación del servidor, revisar el texto y preparar el depósito público de los materiales. Recuperar el registro de octubre y añadir tráfico legítimo comparable son las ampliaciones de mayor valor; seguir probando clasificadores tiene menos prioridad.
