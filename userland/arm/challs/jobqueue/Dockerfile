FROM ubuntu:26.04@sha256:c6c0067e0e45b7a826eaebb193cef957be28045380963a9b1eeb2a5d3c70a1b9
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        socat \
        qemu-user \ 
        libc6-arm64-cross && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf

WORKDIR /home/ctf
COPY jobqueue /home/ctf/jobqueue
COPY flag.txt /home/ctf/flag.txt

RUN chown ctf:ctf /home/ctf/flag.txt && chmod 400 /home/ctf/flag.txt && \
    chown ctf:ctf /home/ctf/jobqueue && chmod 755 /home/ctf/jobqueue

USER ctf
EXPOSE 9999

CMD ["socat", "-T60", \
     "tcp-listen:9999,reuseaddr,fork", \
     "exec:/usr/bin/qemu-aarch64 -cpu max -L /usr/aarch64-linux-gnu /home/ctf/jobqueue,stderr"]