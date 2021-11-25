echo "Compare log outputs"
echo "ETHERNET"
diff -y log_wire/ethernet.txt log/ethernet.txt
echo "IPV4"
diff -y log_wire/ipv4.txt log/ipv4.txt
echo "IPV6"
diff -y log_wire/ipv6.txt log/ipv6.txt
echo "ARP"
diff -y log_wire/arp.txt log/arp.txt