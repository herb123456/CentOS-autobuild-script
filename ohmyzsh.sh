#!/bin/bash

source variable.sh

# install oh-my-zsh
yum -y install zsh 
sh -c "$(wget https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh -O -)"
sed -i 's/ZSH_THEME="robbyrussell"/ZSH_THEME="dst"/g' ~/.zshrc

sed -ie "\$a#enable php71\nsource /opt/remi/php71/enable" ~/.zshrc

source ~/.zshrc