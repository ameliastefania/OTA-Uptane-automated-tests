FROM ubuntu:latest
RUN apt-get update
RUN apt-get install -y --no-install-recommends apt-utils nano iptables python3 python3-pip tcpdump
RUN apt-get install -y --no-install-recommends net-tools python3-dev build-essential libnetfilter-queue-dev
RUN pip3 install --upgrade pip
RUN pip3 install setuptools
RUN pip3 install NetfilterQueue
RUN pip3 install scapy-python3

WORKDIR /work
CMD ["sleep", "9999999"]