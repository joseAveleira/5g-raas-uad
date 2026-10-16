# Conclusiones de la primera fase (CSV)

**Esta valoración es histórica.** La recuperación posterior de dos PCAP y del registro permite nuevas comprobaciones y una tarea de servicio entre días. Leer primero [CONCLUSIONES_PCAP.md](pcap_analysis/CONCLUSIONES_PCAP.md). Las limitaciones de detección general siguen vigentes; ya no falta el PCAP de noviembre.

El trabajo deja de limitarse a describir el escenario y contar protocolos: ahora examina qué información es realmente utilizable, qué resultados produce un protocolo temporal reproducible y qué conclusiones no permite el dataset.

## Valoración del resultado actual

La evidencia de detección es débil. La BA de 0,72–0,74 muestra cierta separación entre períodos de esta captura, pero los controles con etiquetas desplazadas alcanzan cifras similares. Por tanto, todavía no hemos establecido que la separación sea específica del ransomware. Además, el baseline de red produce 10 falsas alarmas en 23 ventanas normales (43,5%). Las 48 ventanas de prueba pertenecen a la misma sesión; no son 48 ejecuciones independientes.

Esto no convierte el trabajo en inútil. El testbed, la adquisición, el esquema documentado, la auditoría y el código sirven como recurso piloto reproducible. La reducción de 46 a 5 entradas es un resultado exploratorio de compactación, cuya estabilidad y utilidad fuera de esta sesión siguen sin demostrarse. Las puntuaciones actuales no bastan para presentar el recurso como un benchmark validado de detección.

Mi recomendación editorial es no considerar esta ampliación lista para enviar si su argumento principal va a ser la detección de ransomware o una ventaja predictiva de GTP. El siguiente incremento de evidencia debería venir de sesiones independientes y controles de actividad legítima comparables. Variar clasificadores o escoger retrospectivamente la ventana con mejor puntuación no resolvería la falta de especificidad. Si no se puede ampliar la adquisición, el alcance defendible queda en un estudio piloto de representación y evaluación, sin garantía de encaje o aceptación en una revista concreta.

## Resultados que sí podemos explicar

1. **Selección compacta de características.** En la prueba principal de 2 segundos, el random forest con 5 variables obtiene BA 0,724 y F1 0,764. El modelo de contexto completo retiene 46 variables y obtiene BA 0,723 y F1 0,772. Se reduce el número de entradas un 89,1% con resultados cercanos en este test. Esto no es una prueba de equivalencia estadística ni garantía de estabilidad en otras sesiones.

2. **Un baseline de red explícito.** Sin campos GTP explícitos, el random forest obtiene BA 0,743, F1 0,793, precisión 0,697 y recall 0,920. Su test contiene 23 ventanas normales y 25 de ejecución: 13 verdaderos negativos, 10 falsos positivos, 2 falsos negativos y 23 verdaderos positivos. La tasa de falsas alarmas sigue siendo importante; no se propone desplegarlo como detector validado.

3. **El valor de GTP está acotado por el propio esquema.** En las 84.994 observaciones GTP, gtp_length es exactamente frame_len menos 52. Message y flags son constantes. Los 10 TEIDs permiten describir actividad local de túneles, pero no son diez dispositivos ni predictores transportables. Añadir los campos GTP no mejora de forma consistente los modelos. Este resultado negativo es informativo y debe publicarse con claridad.

4. **Visibilidad de protocolos y fragmentación.** Hay 22.522 registros UDP con MF activado, pila IP:data y longitud de trama de 1.516 bytes. Su contenido no se decodifica como GTP. Representan el 10,68% del baseline y el 28,42% de los períodos de ejecución. Por ello, una caída de presencia GTP decodificada no demuestra por sí sola menor tráfico real de túneles. El CSV no contiene offset/payload suficientes para atribuir o reconstruir esos fragmentos.

5. **Observaciones repetidas y evaluación por paquetes.** Se encuentran 50.939 candidatos a repetición dentro de 1 ms, conservando 56.755 representantes. Los umbrales de 10 y 100 microsegundos dan el mismo recuento. En una partición aleatoria por paquete, el 65,62% de las filas de test tiene un candidato del mismo grupo en entrenamiento. Agruparlos elimina ese solapamiento, pero no la dependencia temporal.

6. **Un control de fuga muy demostrativo.** Un árbol que utiliza solo el tiempo alcanza BA 1,000 con partición aleatoria y 0,500 con prueba temporal hacia delante. El modelo por paquetes con características permitidas baja de BA 0,716 en partición aleatoria a 0,593 en temporal. No se atribuye toda la diferencia a duplicados: también cambian distribución y composición de la prueba.

## Lo que impide exagerar

- Solo hay una captura de 291,6 segundos y dos ejecuciones de un prototipo.
- La prueba principal tiene 48 ventanas, no decenas de miles de ejecuciones independientes.
- Las cinco variables elegidas cambian con la parte de la captura usada para entrenar: solo dos coinciden, Jaccard 0,25.
- Cambiar la ventana altera los resultados. Con selección de cinco variables, RF da BA 0,818 / 0,724 / 0,707 para 1 / 2 / 5 segundos. Se mantienen las tres, sin elegir la mejor como resultado principal.
- Las etiquetas desplazadas circularmente producen, en algunos controles, BA tan alta como 0,748 para RF. Es evidencia de fragilidad temporal, no un p-valor; impide atribuir automáticamente la separabilidad al ransomware.
- En la población restringida a GTP decodificado, el RF de red obtiene BA 0,713 a 2 segundos. La interpretación sigue siendo de períodos de esta sesión.

## Enfoque editorial propuesto

Presentar el artículo como **dataset de tráfico 5G con auditoría de representación y evaluación temporal de utilidad**, apoyado por:

- documentación del testbed y de las etiquetas;
- análisis de redundancia, fragmentación y observaciones repetidas;
- comparación de red/GTP y selección compacta;
- controles que muestran cuándo una evaluación puede ser engañosa;
- código, predicciones, modelos, tablas y figuras reproducibles.

No titularlo como un nuevo detector de ransomware ni afirmar que GTP mejora la detección. La contribución es más defendible cuando demuestra tanto la utilidad como los límites del recurso.

## Paso con más valor si podemos ampliar la captura

Recuperar PCAP/log para confirmar fragmentos y repeticiones, y adquirir nuevas sesiones con baseline y ejecución, en distintos días y dispositivos. Reservar al menos una sesión completa como prueba externa antes de elegir características. Añadir más clasificadores a la misma captura no resuelve esa falta de independencia.

La carpeta contiene 98 ajustes de modelos por ventanas, 40 controles por desplazamiento de etiquetas y 6 diagnósticos por paquetes/tiempo, además de comprobaciones de integridad y réplicas deterministas. Son comparaciones del mismo registro, no 144 experimentos de adquisición independientes.
