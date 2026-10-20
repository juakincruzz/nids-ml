# NIDS-ML: detector de intrusiones de red con machine learning

![Python](https://img.shields.io/badge/Python-3.12+-blue)
![FastAPI](https://img.shields.io/badge/Web-FastAPI%20%2B%20HTMX%20%2B%20SSE-009688)
![LightGBM](https://img.shields.io/badge/ML-LightGBM-red)
![Tests](https://img.shields.io/badge/tests-pytest-green)

Sistema de detección de intrusiones de red (NIDS) que clasifica flujos de tráfico como
normales o como ataques (escaneos de puertos, fuerza bruta, DoS/DDoS, botnets, ataques web…).
Se evalúa **con honestidad**: frente a reglas clásicas, contando las falsas alarmas por hora y
probando ataques que el modelo **no vio nunca** al entrenar. Además, explica cada alerta con SHAP.

Un panel web reproduce acelerado el tráfico de test (el que el modelo no vio) y va marcando las
alertas en directo. Para cada alerta enseña qué la ha provocado y si una regla clásica la habría
detectado.

---

## Resultados en una frase

Con los ataques que ha visto, el modelo detecta el **99,6 %** de los flujos de ataque con
**10,3 falsas alarmas por hora**. Con una familia de ataques que **no** ha visto, no detecta
prácticamente nada (≤ 2 %), y ahí las reglas clásicas generalizan mejor. Y en **otra red**
(UNSW-NB15) detecta el 2 % de los ataques, con una PR-AUC cerca del azar. Las tres cosas son
ciertas a la vez, y por eso se miden por separado.

## Qué hace

- **Detecta ataques conocidos** en flujos de red con LightGBM entrenado con CIC-IDS2017
  (versión corregida).
- **Mide cuánto aguanta ante ataques nuevos.** Se entrena sin una familia de ataques entera y se
  comprueba si la detecta igualmente, con el clasificador y con un detector de anomalías
  (Isolation Forest) entrenado solo con tráfico normal.
- **Se compara con referencias**: reglas de umbral como las de un IDS clásico, una regresión
  logística con las mismas variables y «decir siempre normal».
- **Explica cada alerta** con SHAP y en lenguaje claro: las 3 variables que más han empujado
  hacia la alerta, su valor y lo que sería normal. Por ejemplo, «no hay pausas entre
  paquetes: 48 µs (lo normal: 59,9 ms)».
- **Panel de reproducción**: el tráfico de test pasa acelerado (×60, ×300, ×1000), las alertas
  llegan en directo por Server-Sent Events y se puede pulsar cualquiera para ver su explicación.

## Por qué esto no es tan fácil como parece

Es habitual ver detectores de intrusiones con un 99 % de *accuracy* en estos datasets. Casi
siempre ese número engaña:

- **El tráfico normal es la inmensa mayoría.** Un modelo que dijera siempre «normal» ya tendría
  una *accuracy* altísima. Por eso aquí se miden el recall de cada familia de ataque, la
  precisión y, sobre todo, las **falsas alarmas por hora**: es lo que decide si un analista
  puede usar el sistema o lo apaga.
- **Repartir los flujos al azar entre entrenamiento y test hace trampa.** Los flujos de un mismo
  ataque se parecen muchísimo entre sí, así que el modelo «reconoce» el ataque en vez de
  aprender a detectarlo. Aquí el reparto es **temporal**: se entrena con lo que pasó antes y se
  prueba con lo que pasó después.
- **Algunas columnas delatan la respuesta** (IPs, identificadores de flujo, marcas de tiempo).
  En CIC-IDS2017 casi todos los ataques salen de la misma IP, así que el modelo nunca las ve.
  Un test falla si alguna se cuela, aunque venga escrita de otra forma («Source IP», «src_ip»…).
- **El CIC-IDS2017 original tiene errores conocidos** de etiquetado y de extracción de flujos.
  Se usa la versión corregida por Engelen et al. (2021).

## Datos

| Dataset | Uso | Notas |
|---|---|---|
| [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html), versión corregida de [Engelen et al. (2021)](https://intrusion-detection.distrinet-research.be/CNS2022/) | Entrenamiento y test | 5 días de tráfico de laboratorio (lunes a viernes) con ataques reales. El lunes solo hay tráfico normal. |
| [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | Prueba en otra red | Otra red (UNSW Canberra, 2015), otras herramientas de ataque y otro extractor de flujos (Argus/Bro). 2 540 047 flujos en dos sesiones de captura. |

Tras la limpieza quedan **2 099 976 flujos** con 83 variables.

Los datos no se suben al repositorio: `make data` y `make data-unsw` los descargan (con
comprobación de SHA-256) y los preparan en `data/`.

### Decisiones de limpieza

- **Flujos «Attempted»** (11 979): son flujos que formaban parte de un ataque pero no llevan
  nada malicioso. Se reetiquetan como normales, como recomiendan los autores del dataset
  corregido.
- **Infinitos y valores imposibles**: 10 tasas infinitas y 781 longitudes de cabecera negativas
  (un fallo de CICFlowMeter) pasan a desconocidas y se rellenan con la mediana de **train**.
  Las columnas constantes también se deciden solo con train.
- **Duplicados**: se eliminan las filas idénticas en todo (en esta versión no hay ninguna). Los
  flujos con las mismas variables pero distinta hora se conservan: son conexiones reales
  distintas, y quitarlos falsearía las falsas alarmas por hora.
- **Puertos**: el de destino sí es una variable (indica el servicio atacado); el de origen no,
  porque casi siempre es un puerto efímero.
- **Familias**: DoS/DDoS, fuerza bruta, escaneo, web, botnet e infiltración, más Heartbleed
  (11 flujos) aparte. El escaneo que lanza la máquina infectada cuenta como escaneo, no como
  infiltración: si no, al «dejar fuera los escaneos» el modelo seguiría viéndolos.

## Cómo se evalúa

| Protocolo | Pregunta que responde | Cómo |
|---|---|---|
| **Ataques conocidos** | ¿Detecta los tipos de ataque que ha visto? | Dentro de cada día, el 70 % inicial del tiempo para entrenar y el 30 % final para test (12,2 h). |
| **Ataques nuevos** | ¿Detecta un tipo de ataque que no ha visto nunca? | *Leave-one-attack-family-out*: se entrena sin una familia y se mide si sus flujos se marcan como ataque. |
| **Otra red** | ¿Funciona en una red que no ha visto? | Se entrena con CIC-IDS2017 y se prueba con UNSW-NB15, con las variables que significan lo mismo en los dos extractores. |

**Umbral de decisión.** Se elige sin mirar test, con el mismo criterio para todos los
detectores: el umbral más sensible que no supera un presupuesto de **10 falsas alarmas por
hora**. Para los modelos se mide sobre el tráfico normal del tramo final antes del corte
(validación); para las reglas, sobre todo lo anterior al corte.

**Métricas.** Recall por familia, precisión, PR-AUC, tasa de falsos positivos y falsas alarmas
por hora, con la duración real del periodo de test. La *accuracy* aparece solo junto a la de
«decir siempre normal».

**Referencias.**
- **Reglas de umbral por IP de origen, en ventanas de 60 s:**
  - muchos puertos de destino distintos → escaneo;
  - muchas conexiones cortas a FTP/SSH → fuerza bruta;
  - muchos paquetes por segundo hacia un mismo destino → DoS.
- **Regresión logística** con las mismas variables que el modelo.
- **«Siempre normal».**

## Resultados

Todas las cifras salen de [`reports/`](reports/) y se regeneran con `make evaluate`.

### Ataques conocidos (test: 12,2 h)

| Detector | Recall | Precisión | Falsas alarmas/h | PR-AUC | Accuracy |
|---|---|---|---|---|---|
| **LightGBM** | **0,996** | **1,000** | **10,3** | **1,000** | 0,998 |
| Regresión logística | 0,884 | 0,992 | 193,4 | 0,981 | 0,951 |
| Reglas de umbral | 0,152 | 0,981 | 79,6 | — | 0,659 |
| Siempre normal | 0,000 | — | 0,0 | 0,401 | 0,599 |

En este test el 40 % de los flujos son ataques (el escaneo y el DDoS del viernes caen en el
tramo final), así que «siempre normal» ya tiene 0,599 de *accuracy*.

Recall por familia:

| Familia | Flujos en test | LightGBM | Regresión logística | Reglas |
|---|---|---|---|---|
| DoS/DDoS | 95 144 | 0,999 | 0,867 | 0,000 |
| Escaneo | 227 515 | 0,996 | 0,890 | 0,210 |
| Fuerza bruta | 1 744 | 0,996 | 0,993 | 0,998 |
| Infiltración | 24 | 0,542 | 0,000 | 0,292 |
| Heartbleed | 11 | 0,000 | 0,000 | 0,000 |

**Cómo leerlo:**
- **LightGBM mantiene las falsas alarmas cerca del presupuesto** (10,3/h frente a 10). La
  regresión logística y las reglas no: el umbral elegido antes del corte no aguanta el cambio de
  tráfico, y se van a 193/h y 80/h.
- **En test, el DoS es solo el DDoS del viernes**, una herramienta distinta de las de
  entrenamiento (Hulk, GoldenEye, Slowloris…). Aun así el modelo lo detecta.
- **La regla de DoS no detecta nada:** su umbral sale de 1 809 paquetes/s y el DDoS va muy por
  debajo.
- **Heartbleed nunca aparece antes del corte**, así que en la práctica es un ataque nuevo.
- **Web y botnet no tienen flujos en test:** todos caen antes del corte. Se evalúan en el
  protocolo siguiente.

### Ataques nuevos (familia excluida del entrenamiento)

Recall sobre **todos** los flujos de la familia excluida y, entre paréntesis, falsas alarmas
por hora sobre el tráfico normal de test:

| Familia excluida | Flujos | LightGBM sin esa familia | Isolation Forest (solo normal) | Reglas |
|---|---|---|---|---|
| DoS/DDoS | 266 778 | 0,002 (38) | 0,000 (45) | **0,396** (80) |
| Fuerza bruta | 6 933 | 0,000 (36) | 0,000 (45) | **1,000** (80) |
| Escaneo | 230 833 | 0,001 (10) | **0,351** (45) | 0,207 (80) |
| Web | 104 | 0,019 (39) | 0,000 (45) | 0,000 (80) |
| Botnet | 736 | 0,000 (40) | 0,000 (45) | 0,000 (80) |
| Infiltración | 36 | 0,000 (19) | 0,000 (45) | 0,194 (80) |

**Cómo leerlo:**
- **El modelo supervisado casi no detecta lo que no ha visto.** No es que no lo distinga: sin
  haber visto DoS, su PR-AUC en DoS frente al tráfico normal es 0,956 (escaneo: 0,840). Lo
  pone por encima de casi todo el tráfico normal, pero no por encima del tráfico normal más
  raro, que es el que fija el umbral con un presupuesto de 10 alarmas por hora.
- **El Isolation Forest solo saca algo en escaneo** (recall 0,351, PR-AUC 0,985).
- **Las reglas son las únicas que generalizan** a fuerza bruta y a parte del DoS, a cambio de
  muchas más falsas alarmas.

**Conclusión:** un detector supervisado es excelente con lo conocido e insuficiente con lo
nuevo; un IDS real necesita también reglas o detección de anomalías.

### Otra red (entrenado con CIC-IDS2017, probado con UNSW-NB15)

Los dos datasets usan extractores de flujos distintos (CICFlowMeter frente a Argus/Bro), así que
solo se usan las **10 variables que significan lo mismo** en los dos, con las unidades
convertidas:
- puerto de destino y protocolo;
- duración;
- paquetes en cada sentido;
- paquetes por segundo (total y por sentido);
- tiempo medio entre paquetes en cada sentido.

Se excluyen a propósito:
- **Los bytes:** Argus cuenta las cabeceras y CICFlowMeter no. El modelo fallaría por la medida,
  no por la red.
- **La ventana TCP:** el campo de Argus no es la ventana en bytes.
- **Los flujos que no son TCP/UDP:** ARP, OSPF y otros 130 protocolos que CICFlowMeter no
  produce. Son 54 538 flujos, de los que 39 349 son ataques; se evalúan los 2 485 509 restantes.

El umbral de cada modelo se elige con su propia validación (presupuesto de 10 falsas alarmas
por hora). La «PR-AUC al azar» es la proporción de ataques.

| Entrenado → evaluado | Recall | Precisión | Falsas alarmas/h | PR-AUC | PR-AUC al azar |
|---|---|---|---|---|---|
| CIC → test de CIC (solo 10 variables) | 0,594 | 0,998 | 35,5 | 0,995 | 0,401 |
| **CIC → todo UNSW-NB15** | **0,021** | 0,738 | 84,8 | 0,168 | 0,113 |
| CIC → test de UNSW | 0,018 | 0,750 | 65,5 | 0,150 | 0,104 |
| UNSW → test de UNSW (techo con estas variables) | 0,138 | 0,990 | 15,2 | 0,719 | 0,104 |

Recall por categoría de UNSW-NB15, en el mismo test:

| Categoría | Flujos en test | Entrenado en CIC | Entrenado en UNSW (techo) |
|---|---|---|---|
| Generic | 61 384 | 0,001 | 0,013 |
| Exploits | 7 395 | 0,111 | 0,758 |
| Fuzzers | 5 414 | 0,016 | 0,117 |
| Reconnaissance | 3 125 | 0,118 | 0,936 |
| DoS | 1 018 | 0,105 | 0,634 |
| Shellcode | 398 | 0,000 | 0,560 |
| Analysis | 136 | 0,059 | 0,022 |
| Backdoor | 102 | 0,069 | 0,510 |
| Worms | 47 | 0,383 | 0,723 |

**Cómo leerlo:**
- **Al cambiar de red, el modelo casi no detecta nada**: un 2 % de recall, con una PR-AUC
  (0,168) apenas por encima de la de puntuar al azar (0,113), y 85 falsas alarmas por hora.
- **No es solo por usar menos variables.** Con las mismas 10 variables, el modelo sigue
  ordenando casi perfecto en CIC (PR-AUC 0,995), aunque con el presupuesto de alarmas su recall
  es 0,594, frente al 0,996 del modelo principal con las 83 variables. Y entrenado dentro de UNSW llega a 0,936 en reconocimiento y 0,758 en
  exploits. El problema principal es la red.
- **Ni siquiera dentro de UNSW estas variables bastan para todo.** «Generic», que es el 78 % de
  los ataques del test, se queda en 0,013 de recall: con 10 variables de tiempos y paquetes se
  parece demasiado al tráfico normal.

### Explicaciones

Sobre una muestra de 1 214 alertas de test, lo que más pesa en las decisiones del modelo
(contribución SHAP media) es:
1. el puerto de destino;
2. la pausa más larga entre paquetes;
3. la ventana TCP inicial del origen;
4. el tamaño medio de las respuestas.

Ejemplos reales de explicaciones, incluidas falsas alarmas, en
[`reports/explanations/examples.json`](reports/explanations/examples.json).

## Cómo se llegó a estas cifras

Hay tres fallos que salieron durante el desarrollo, y los cuento porque cambian cómo leer los
resultados. En las dos primeras evaluaciones LightGBM daba recall 0. Cada causa se diagnosticó y
se corrigió con train y validación, sin tocar ningún parámetro mirando test:

1. **Probabilidades saturadas.** Con 1 − P(normal) en float64, miles de flujos empataban en 1,0
   justo donde va el umbral. La puntuación pasó a ser las log-odds de ataque, que ordenan igual
   pero no empatan.
2. **Una validación que se quedaba con lo importante.** El tramo final antes del corte contenía
   todo el escaneo y todo el SSH-Patator, así que el modelo entrenaba sin ver un solo escaneo.
   Como el umbral solo depende del tráfico normal, la validación pasó a usar solo los flujos
   normales de ese tramo, y sus ataques se usan para entrenar.
3. **Inestabilidad numérica en multiclase.** Con familias de 12 o 104 flujos, LightGBM producía
   log-odds de millones. Se arregló con un hessiano mínimo por hoja y regularización L2.

Además, LightGBM se entrena en modo determinista: dos entrenamientos dan resultados idénticos
bit a bit.

## Panel web

Hecho con FastAPI, plantillas Jinja2, HTMX para cargar las explicaciones y la pestaña de
evaluación, y Server-Sent Events para el directo. El gráfico es un SVG propio, sin librerías de
gráficos.

- **Reproducción** de la parte de test de cada día, con velocidad ×60, ×300 o ×1000,
  play/pausa (o la tecla Espacio) y barra de tiempo.
- **Gráfico de flujos por segundo** con los episodios de ataque real sombreados y con nombre, y
  las alertas del modelo (▼) y de las reglas (■).
- **Alertas en directo agrupadas en incidentes** (mismo origen, destino y familia, sin huecos de
  más de 60 s), como haría un SIEM. Pulsar una abre su explicación y dice si las reglas la
  habrían visto y qué dice la etiqueta real.
- **Marcador**: ataques detectados, falsas alarmas por hora y lo que habrían detectado las
  reglas.
- **Pestaña «Evaluación»** con las tablas de los protocolos.
- **Accesible**: navegable con teclado, con etiquetas ARIA, sin depender solo del color y
  respetando `prefers-reduced-motion`.

URL lista para grabar (arranca reproduciendo el viernes justo antes del DDoS):

```
http://127.0.0.1:8000/?dia=viernes&desde=15:50&velocidad=300&play=1
```

Las horas son las locales del laboratorio (UTC−3). `&alerta=N` abre al cargar la explicación
del incidente N y `&vista=evaluacion` abre directamente las tablas.

## Arranque rápido

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

make data        # descarga y limpia CIC-IDS2017 (328 MB comprimidos, solo la primera vez)
make data-unsw   # descarga UNSW-NB15 (586 MB) y lo alinea con CIC (protocolo «otra red»)
make train       # umbrales de las reglas, LightGBM y regresión logística
make evaluate    # los tres protocolos -> reports/ («otra red» solo si hay datos de UNSW)
make explain     # ejemplos explicados e importancia global (SHAP) -> reports/explanations/
make replay      # precalcula la reproducción del panel
make web         # panel en http://127.0.0.1:8000
make test        # tests (datos sintéticos, sin red)
make lint        # ruff
```

Todo cabe en un portátil: el paso más pesado ronda los 4 GB de RAM. Los hilos de LightGBM se
configuran en `config/config.yaml` (`n_jobs`).

## Arquitectura

```
config/         config.yaml: semilla, rutas, reparto, presupuesto de falsas alarmas,
                parámetros del modelo y umbrales de las reglas
src/nids/
  data/         descarga reanudable, limpieza, etiquetas y familias; UNSW-NB15 alineado
  features/     columnas permitidas y prohibidas para el modelo
  models/       reglas de umbral, LightGBM y regresión logística, Isolation Forest
  evaluation/   reparto temporal, métricas, protocolos y gráficos de reports/
  explain/      SHAP y diccionario variable -> frase en lenguaje claro
  replay/       precálculo y motor de la reproducción (incidentes, marcador)
  web/          FastAPI + Jinja2 + HTMX + SSE
tests/          pytest con datos sintéticos (reparto temporal, columnas prohibidas,
                limpieza y umbral solo con train, métricas calculadas a mano,
                reglas, leave-one-family-out, SHAP exacto, panel)
reports/        métricas, resúmenes y gráficos generados (se versionan)
```

## Limitaciones conocidas

- **Son datos de laboratorio, y no generalizan a otra red.** Entrenado con CIC-IDS2017 y
  probado con UNSW-NB15, el modelo apenas detecta nada. Para usarlo en una red concreta habría
  que reentrenarlo con tráfico de esa red, y extraer los flujos con la misma herramienta.
- **«Otra red» compara solo 10 variables y solo TCP/UDP.** Deja fuera los bytes, la ventana TCP
  y el 12 % de los ataques de UNSW-NB15, que van sobre otros protocolos.
- **Posibles atajos del dataset.** Entre las variables que más pesan está la ventana TCP inicial,
  que suele delatar la herramienta o el sistema operativo del atacante más que el ataque en sí.
- **Atribución de familia.** El modelo detecta el DDoS del viernes, que no vio al entrenar, pero
  a menudo lo atribuye a «escaneo». Detecta bien; nombra peor lo que no conoce.
- **Ruido en las etiquetas.** La máquina infectada del jueves (192.168.10.8) tiene flujos
  etiquetados como normales que tocan unos 1 000 puertos por minuto. Eso obliga a la regla de
  escaneo a un umbral muy alto. Y durante el DDoS, respuestas de la víctima etiquetadas como
  normales cuentan como falsas alarmas.
- **Con un solo corte por día**, web y botnet quedan sin test en «ataques conocidos» y Heartbleed
  solo aparece en test. Se aceptó para garantizar que ningún flujo de test es anterior a uno de
  entrenamiento del mismo día.
- **El presupuesto de 10 falsas alarmas por hora es una decisión de diseño**, no un resultado.
  Con otro presupuesto cambian todos los recalls; la PR-AUC no depende de él.
- **El modelo trabaja con flujos ya extraídos**, no con paquetes en directo. Analizar capturas
  `.pcap` propias está en la hoja de ruta.
- **Es un proyecto de aprendizaje e investigación**, no un producto de seguridad.

## Uso responsable

Este proyecto solo analiza datasets públicos. Si en algún momento se prueba con tráfico
generado (escaneos, fuerza bruta…), se hará contra máquinas propias en un laboratorio aislado y
nunca contra sistemas de terceros sin autorización.

## Referencias

- Sharafaldin, Lashkari y Ghorbani (2018). *Toward Generating a New Intrusion Detection Dataset
  and Intrusion Traffic Characterization*. ICISSP.
- Engelen, Rimmer y Joosen (2021). *Troubleshooting an Intrusion Detection Dataset: the
  CICIDS2017 Case Study*. IEEE Security and Privacy Workshops.
- Moustafa y Slay (2015). *UNSW-NB15: a comprehensive data set for network intrusion detection
  systems (UNSW-NB15 network data set)*. MilCIS.
- Moustafa y Slay (2016). *The evaluation of Network Anomaly Detection Systems: Statistical
  analysis of the UNSW-NB15 dataset and the comparison with the KDD99 dataset*. Information
  Security Journal: A Global Perspective.
- Moustafa, Slay y Creech (2017). *Novel geometric area analysis technique for anomaly detection
  using trapezoidal area estimation on large-scale networks*. IEEE Transactions on Big Data.
- Moustafa, Creech y Slay (2017). *Big data analytics for intrusion detection system: statistical
  decision-making using finite dirichlet mixture models*. Data Analytics and Decision Support
  for Cybersecurity, Springer.
- Sarhan, Layeghy, Moustafa y Portmann (2020). *NetFlow Datasets for Machine Learning-Based
  Network Intrusion Detection Systems*. BDTA / WiCON.
- Lundberg y Lee (2017). *A Unified Approach to Interpreting Model Predictions*. NeurIPS.

## Autor

**Joaquín José Cruz Lorenzo**
GitHub: [@juakincruzz](https://github.com/juakincruzz) · Web: [joaquinjcl.dev](https://joaquinjcl.dev)
