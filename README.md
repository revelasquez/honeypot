# honeypot

- Requisitos
- Python3
- pip3
- virtualenv
```sh
  sudo apt update
  sudo apt install python3 python3-pip
  pip3 install django virtualenv
```
- Clonar el proyecto
```sh
git clone https://github.com/revelasquez/honeypot.git
```
- Crear un entorno virtual y activarlo (una vez activado en la terminal aparecera un texto con el nombre del entorno virtual)
```sh
virtualenv venv
source venv/bin/activate
```
- instalar la libreria para la base de datos
```sh
pip3 install psycopg2.binary
```
- Ingresar al proyecto
```sh
cd honeypot
```
- Instalar el honeypotadmin
```
pip3 install django-admin-honeypot-advanced
```
- Ejecutar las migraciones a la base de datos
```
python3 manage.py makemigrations
python3 manage.py migrate
```
- crear un superusuario
```
python3 manage.py createsuperuser
```
- Levantar el proyecto
```sh
python3 manage.py runserver
```
- Para Levantar el proyecto en un ip o puerto especifico
```sh
python3 manage.py runserver 0.0.0.0:8000
```
