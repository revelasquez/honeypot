# honeypot

- docker
- postgres
```sh
  sudo apt update
  sudo apt install docker.io
```
- Clonar el proyecto
```sh
git clone https://github.com/revelasquez/honeypot.git
```
- Descargar la imagen desde dockerhub 
```sh
docker pull revelasquez76226637/docker-django:latest
```
- levantar el proyecto
```sh
docker run -p 8000:8000 -d honeypot/docker-django  
```
- Ingresar al proyecto
```sh
docker exec -it id_imagen /bin/sh
```
- Ejecutar las migraciones a la base de datos
```
python3 manage.py makemigrations
python3 manage.py migrate
```
- crear un superusuario
```sh
python3 manage.py createsuperuser
```
