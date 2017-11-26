**I made this to teach myself how to transmit and receive simple OOK
signals using RfCat, please don't use this to commit crimes. :(**

Linear MegaCode is a protocol that is in widespread use in apartment
complexes in my area to control access to buildings, parking garages,
and entry and exit gates. They use a fixed code and have long been known
to be vulnerable to replay attacks.

Example devices:
http://nortekcontrol.com/products/radio-controls/#megacode

An excellent resource for this protocol is available at:
https://wiki.cuvoodoo.info/doku.php?id=megacode

```
Linear Technologies MegaCode RfCat transmitter and receiver.

Use this to transmit a single remote ID or iterate through a range.
You can also listen for a defined period of time and display recorded
IDs.
IDs are 20 bits and are provided as an integer between 1 and 1048575.
    -s, --systemid    <integer between 1-1048575>
    -l, --lower       <lower end of range>
    -u, --upper       <upper end of range>
    -b, --bruteforce  Attempts to randomly guess a key in the reduced 14
bit keyspace based on research from King Kevin at www.cuvoodoo.info
    -r, --record      <seconds> Listen for transmissions and return the
IDs and data.
```
