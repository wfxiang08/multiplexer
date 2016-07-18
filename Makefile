all: multiplexer

%: %.go
	source ./go_env.sh; \
		go build -x -i $<


test:
	curl http://localhost:8080
