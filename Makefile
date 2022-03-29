all:
	gcc main.c handlers.c resolve.c -o coap-sample -l coap-2-openssl

clean:
	rm -f coap-sample
