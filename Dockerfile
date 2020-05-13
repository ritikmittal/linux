FROM ubuntu

ENTRYPOINT /bin/bash
RUN apt-get update
RUN apt-get install -y locales
RUN locale-gen en_US.UTF-8
ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8

RUN apt-get install cron

RUN mkdir /usr/local/scripts
COPY ./scripts/* /usr/local/scripts/
COPY ./*.log /usr/local/
RUN /usr/local/scripts/userGenerate.sh
RUN /usr/local/scripts/permit.sh
RUN /usr/local/scripts/setup2.sh
RUN /usr/local/scripts/cron.sh
