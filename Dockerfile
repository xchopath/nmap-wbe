FROM python:3.10.10-buster
RUN apt-get update && apt-get install -y g++ libxml2-dev nmap
WORKDIR /app
COPY . /app/
RUN pip3 install --upgrade pip
RUN pip3 install -r /app/requirements.txt
ENTRYPOINT [ "python3", "/app/main.py" ]