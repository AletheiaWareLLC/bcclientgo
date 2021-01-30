#!/bin/bash
#
# Copyright 2020-2021 Aletheia Ware LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
set -x

go fmt $GOPATH/src/aletheiaware.com/bcclientgo/{,cmd/bc}
go test $GOPATH/src/aletheiaware.com/bcclientgo/{,cmd/bc}
env GOOS=darwin GOARCH=amd64 go build -o $GOPATH/bin/bc-darwin-amd64 aletheiaware.com/bcclientgo/cmd/bc
# TODO env GOOS=darwin GOARCH=arm64 go build -o $GOPATH/bin/bc-darwin-arm64 aletheiaware.com/bcclientgo/cmd/bc
env GOOS=linux GOARCH=386 go build -o $GOPATH/bin/bc-linux-386 aletheiaware.com/bcclientgo/cmd/bc
env GOOS=linux GOARCH=amd64 go build -o $GOPATH/bin/bc-linux-amd64 aletheiaware.com/bcclientgo/cmd/bc
env GOOS=linux GOARCH=arm GOARM=5 go build -o $GOPATH/bin/bc-linux-arm5 aletheiaware.com/bcclientgo/cmd/bc
env GOOS=linux GOARCH=arm GOARM=6 go build -o $GOPATH/bin/bc-linux-arm6 aletheiaware.com/bcclientgo/cmd/bc
env GOOS=linux GOARCH=arm GOARM=7 go build -o $GOPATH/bin/bc-linux-arm7 aletheiaware.com/bcclientgo/cmd/bc
env GOOS=linux GOARCH=arm64 go build -o $GOPATH/bin/bc-linux-arm8 aletheiaware.com/bcclientgo/cmd/bc
env GOOS=windows GOARCH=386 go build -o $GOPATH/bin/bc-windows-386.exe aletheiaware.com/bcclientgo/cmd/bc
env GOOS=windows GOARCH=amd64 go build -o $GOPATH/bin/bc-windows-amd64.exe aletheiaware.com/bcclientgo/cmd/bc
