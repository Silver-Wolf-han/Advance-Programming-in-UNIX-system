savedcmd_/home/zjinghan/lab2/cryptomod/cryptomod.mod := printf '%s\n'   cryptomod.o | awk '!x[$$0]++ { print("/home/zjinghan/lab2/cryptomod/"$$0) }' > /home/zjinghan/lab2/cryptomod/cryptomod.mod
