FROM golang:1.22
RUN apt-get update && apt-get install -y python3 python3-pip
WORKDIR /app
