%: %.go
	source ./go_env.sh; \
		go build -x -i $<


