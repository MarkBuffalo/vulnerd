# Vulnerd

# What is it?

Parses greppable nmap vulners to TSV for easy viewing. 

# How do I use it?

Just use nmap with vulners and a greppable output like so:

```
$ nmap ip/range -sV -sT --script=vulners -oG vulners-results.txt
```

And then feed the grep file to the program:

```
$ python3 vulnerd.py vulners-results.txt
```

