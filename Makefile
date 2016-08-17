all: mp2

%: %.go
	source ./go_env.sh; \
		go build -x -i $<


#test:
#	curl http://localhost:8081/some/file/in
#	curl -H 'Host: p7:9' http://localhost:8081

setcap:
	sudo setcap cap_net_bind_service=ep mp2

linksys:
	mkdir -p src
	ln -s /usr/share/gocode/src/github.com src/ || true
	ln -s /usr/share/gocode/src/gopkg.in   src/ || true
