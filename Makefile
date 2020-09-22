all: pcap-test

pcap-test : pcap-test.o
	g++ -o pcap-test pcap-test.o -lpcap

pcap-test.o : main.cpp
	g++ -c -o pcap-test.o main.cpp

clean :
		rm -f pcap-test *.o