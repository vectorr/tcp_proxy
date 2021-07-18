# tcp_proxy

A tcp proxy using epoll, listen on Port 1922, and forward tcp traffic to target_ip:target_port, where target_ip and target_port are arguments to this program.
usage:
```
$tcp_proxy <target_ip> <target_port>
```
