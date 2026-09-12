# docker build . -t mymalloc:latest
# docker run --restart=always -p 31314:31314 -itd --name mymalloc mymalloc:latest

FROM ubuntu:16.04
LABEL maintainer "awe"
ARG chall=mymalloc
ARG libc=libc6-i386_2.23-0ubuntu11_amd64.deb

RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install xinetd -y
COPY ${libc} /tmp/
RUN dpkg -i /tmp/${libc} && rm -f /tmp/${libc}
RUN useradd -m ${chall}
RUN rm -f /etc/xinetd.d/mymalloc

COPY ${chall} flag /home/${chall}/
COPY xinetd.conf /etc/xinetd.d/${chall}

RUN chown -R root:${chall} /home/${chall} && chmod -R 750 /home/${chall}
EXPOSE 31314
ENTRYPOINT ["xinetd", "-dontfork"]
