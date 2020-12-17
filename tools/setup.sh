#!/bin/bash

#--------------------------------------------------------------------------------------------------------------
TMP_DIR=/tmp
ARCH=`uname -m`
GO_VERSION=`go version`
VIMRC="set ts=2 sw=2 expandtab et number"
OS_TYPE=$(awk '{ print $1 }' /proc/version)

#--------------------------------------------------------------------------------------------------------------
# Making sure that vim environment files exists
if [ -f "$HOME/.vimrc" ] && [ -f "$HOME/.virc" ];
then
    echo "vimrc and virc file exists"
else
    touch ~/.vimrc
    touch ~/.virc
fi
# Adding the VIMRC configuration to the vimrc and virc files
if grep -Fxq "$VIMRC" $HOME/.vimrc && grep -Fxq "$VIMRC" $HOME/.virc;
then
    # code if found
    echo "Already added the vim environment settings!"
else
    # code if not found
    echo $VIMRC >> $HOME/.vimrc
    echo $VIMRC >> $HOME/.virc
fi
#--------------------------------------------------------------------------------------------------------------
# Making sure that last golang version available is installed
if [ $OS_TYPE == "Linux" ]; then
    # waits for the url to finish
    if [ -d /usr/local/go ]; then 
        echo ""
        echo "...... [ Found an older: $GO_VERSION ]"
    else
        echo "Installing.."
        if "$ARCH" == "armv"* ;
        then
            for url in "https://golang.org/dl/go1.15.6.linux-armv6l.tar.gz"
            do
                wget -P $TMP_DIR $url
            done
            sudo tar -C /usr/local -zxvf go1.*
            mkdir -p ~/go/{bin,pkg,src}
        else "$ARCH" == "x86_64";
            for url in "https://golang.org/dl/go1.15.6.linux-amd64.tar.gz"
            do
                wget -P $TMP_DIR $url
            done
            sudo tar -C /usr/local -zxvf go1.*
            mkdir -p ~/go/{bin,pkg,src}
        fi
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
    echo "Only for LINUX distribution!"
fi
