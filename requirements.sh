#!/bin/bash

TMP_DIR=/tmp
ARCH=`uname -m`
GO_VERSION=`go version`

if [[ "$OSTYPE" == "linux-gnu"* ]] && [ "$ARCH" == "x86_64" ]; then
    # waits for the url to finish
    if [ -d /usr/local/go ]; then 
        echo ""
        echo "...... [ Found an older: $GO_VERSION ]"
    else
        echo "Installing.."
        for url in "https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz"
        do
            wget -O $TMP_DIR $url
        done
        sudo tar -C /usr/local -zxvf go1.14.4.linux-amd64.tar.gz
        mkdir -p ~/go/{bin,pkg,src}
    fi
    # The following assume that your shell is bash
    if grep -xq "export GOROOT=/usr/local/go" ~/.bashrc
    then
        # code if found
        echo ""
    else
        # code if not found
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin:$GOROOT/bin' >> ~/.bashrc
    fi
    source ~/.bashrc
else
    echo 'Only for LINUX distribution!'
fi

