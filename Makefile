all:
	$(CC) -o pinetbootd pinetbootd.c dhcpd.c tftpd.c

clean:	
	rm -fr pinetbootd



