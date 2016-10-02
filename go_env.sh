# debian go packages in /usr/share/gocode
#export GOROOT="/home/pkg/go"
export GOROOT=$(go env GOROOT)
export GOPATH="$PWD:/usr/share/gocode/:$GOROOT";
# for cross compiling
export GOOS=linux
export GOARCH=amd64
#export GOARCH=arm
