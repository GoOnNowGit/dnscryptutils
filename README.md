[![Run Tests](https://github.com/GoOnNowGit/dnsstamps-to-fwrules/actions/workflows/main.yml/badge.svg)](https://github.com/GoOnNowGit/dnsstamps-to-fwrules/actions/workflows/main.yml)
# dnsstamps-to-fwrules (Still a work in progress...)
Create firewall rules based on sources in your dnscrypt-proxy.toml file

```dnsstamps-to-fwrules.py```
* Gets the sources in your dnscrypt-proxy.toml file
* Extracts the dnsstamps from each source
* Creates firewall rules from each stamp

## Execute
```
python dnsstamps-to-rules.py --config /usr/local/etc/dnscrypt-proxy.toml --rule_type pf

```
### Output Snippet (Using the PF rule maker)
```
Signature and comment signature verified
Trusted comment: timestamp:1645006385	file:public-resolvers.md
pass out quick on en0 proto tcp to 94.140.14.14 port 5443 label public-resolvers
pass out quick on en0 proto tcp to 176.103.130.130 label public-resolvers
pass out quick on en0 proto tcp to 94.140.14.15 port 5443 label public-resolvers
pass out quick on en0 proto tcp to 176.103.130.132 label public-resolvers
pass out quick on en0 proto tcp to 2a04:5200:fff4::13ff port 8443 label public-resolvers
pass out quick on en0 proto tcp to 51.15.124.208 label public-resolvers
```

## Resources
* https://github.com/DNSCrypt/dnscrypt-proxy
