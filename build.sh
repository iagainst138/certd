#!/bin/bash

set -ex


BUILD_DIR=out
GOFMT_FILES=$(ls src/certd/*.go)

function _cleanup() {
    r=$?
    set +x
    if [ $r -eq 0 ];then
        echo "BUILD OK"
    else
        echo "BUILD FAILED"
    fi
    exit $r
}

function SET_GOPATH() {
    if which cygpath &> /dev/null;then # on windows
        export GOPATH="$(cygpath -w $(dirname $(readlink -f $0)));$(go env GOPATH)"
    else
        export GOPATH=$(dirname $(readlink -f $0)):$(go env GOPATH)
    fi
}

trap _cleanup EXIT

rm -rf ${BUILD_DIR}

# temporarily reconfigure configure GOPATH
SET_GOPATH

UNFORMATTED_FILES=($(gofmt -l ${GOFMT_FILES[@]}))
[ ${#UNFORMATTED_FILES[@]} -gt 0 ] && {
    set +x
    echo -e "ERROR: unformatted files detected:\n$(echo ${UNFORMATTED_FILES[@]} | tr ' ' '\n')"
    exit 1
}

if [ -z ${SKIP_TESTS} ]; then
    # run the tests
    ./test.sh
fi

mkdir -p ${BUILD_DIR}
go build -i -o ${BUILD_DIR}/certd-cli src/certd/cmds/cert-cli/main.go
go build -i -o ${BUILD_DIR}/certd src/certd/cmds/certd/main.go
