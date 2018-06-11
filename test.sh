#!/bin/bash

set -eo pipefail

if which cygpath &> /dev/null;then # on windows
    export GOPATH="$(cygpath -w $(dirname $(readlink -f $0)));$(go env GOPATH)"
else
    export GOPATH=$(dirname $(readlink -f $0)):$(go env GOPATH)
fi

mkdir -p coverage
REPORT=coverage/coverage.html

export RUNNING_TESTS=1

function GEN_REPORT() {
    TOTAL_COVERAGE=$(grep '^coverage: .*statements$' | awk '{print $2}')
    # generate the coverage html file
    go tool cover -html=coverage/cover.out -o $REPORT
    # add the overall coverage to the report
    sed -i "s#<span class=\"cov8\">covered</span>.*#<span class=\"cov8\">covered</span> <span style=\"color:white;\">Overall Coverage: $TOTAL_COVERAGE</span>#g" $REPORT
}

go test certd -v -cover -coverprofile=coverage/cover.out $@ | tee >(GEN_REPORT)
