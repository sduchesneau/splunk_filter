FROM ubuntu

MAINTAINER Farid Bellameche "farid.bellameche@desjardins.com"
MAINTAINER Stéphane Duchesneau "stephane.a.duchesneau@desjardins.com"

RUN apt-get update && apt-get -y install python python-pip python-ldap python-requests ipython git vim
WORKDIR /app


