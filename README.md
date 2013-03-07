sda
===

Self decrypting archive, ported from http://jgae.de/sda.htm

Example
=======
```javascript
var Sda = require('kaerus-component-sda');

var a = new Sda();

a.encrypt("something secret","passphrase"); // => '4IAHl5T2k4bgPq5s2QI'

a.decrypt('4IAHl5T2k4bgPq5s2QI',"passphrase") // => 'something secret'
```




