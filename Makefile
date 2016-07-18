all: multiplexer

%: %.go
	source ./go_env.sh; \
		go build -x -i $<


test:
	curl http://localhost:8081/some/file/in
	curl -H 'Host: p7:9' http://localhost:8081

setcap:
	sudo setcap cap_net_bind_service=ep multiplexer
