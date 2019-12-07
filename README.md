# Kirbys-Nose-Knows
Cross Platform Packet Sniffer (Mac OS &amp; Linux)

git clone repo to computer.

cd into repo.

## Compile
``` gcc sniffer.c bpf.c -o kirby.out```

## Execute
```sudo ./kirby.out```

## View Log
There are two ways to view the log.  
1. You can open a second terminal to the repository and use 
```cat log.txt```
    to view the contents as the packets are being sniffed.
2. After letting the log run for a while, you can end the process with the key combo: ```control + c```  
    You can now use ```cat log.txt``` to view the packet log.
