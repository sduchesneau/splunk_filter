FROM python:2.7

MAINTAINER Farid Bellameche "farid.bellameche@desjardins.com"

RUN pip install requests
RUN apt-get update && apt-get -y install libsasl2-dev python-dev libldap2-dev libssl-dev
RUN echo slapd slapd/password1 password admin | debconf-set-selections
RUN echo slapd slapd/password2 password admin | debconf-set-selections
RUN apt-get update && apt-get -y install slapd ldap-utils
RUN pip install python-ldap
RUN git clone https://github.com/emerald-squad/splunk_filter.git
WORKDIR /splunk_filter


