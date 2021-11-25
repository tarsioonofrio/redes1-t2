VAR="${1:-100}"

mkdir -p capture
touch capture/log.cap
chmod o=rw capture/log.cap
tshark -i enp3s0 -w capture/log.cap &
/home/tarsio/pucrs/redes1/redes1-t2/cmake-build-debug/redes1_t2 $VAR
pkill -f tshark