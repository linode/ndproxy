# ndproxy

this tool is capable of spoofing / injecting a custom mac for a list of IPs read (and updated) from a flat file

by doing so we can:
- leverage fast hardware asics to forward traffic while still breaking up layer2 domains
- breaking layer 2 domain in a transparent way to the client
- migrate layer 2 traffic out of a vlan into a routed environment
- by using the mac of the local interface (and using the spoofed mac in the payload) we do not break any cam/switch tables along the way


NOTE:
the best way is still sending the prefix RAs without the onlink flag



### usage:
tools comes with a systemd service unit and a /etc/default/ndproxy file  
update the file to your needs

for a up2date list of options run
```
ndproxy --help
```


the list of IPs is read out of `/etc/ndproxy.list` by default but any file can be specified in the command line option
