FROM debian

RUN apt-get update -y
RUN apt-get install -y yosys fpga-icestorm arachne-pnr
COPY build.sh .
COPY challenge.v .
COPY challenge.pcf .
RUN chmod +x build.sh
RUN ./build.sh
