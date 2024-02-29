# brute bitcoin address

by given part of mnemonic words and bitcoin address, calculate left words


# benchmark

In my M1 Mac and release mode, 1 thread can calculate 11,000 per second; use 10 thread can calculate 108,000 per second.

# config.toml

```
# the part of mnemonic words which you know, must be continued
words=""

# If the missing mnemonic words are from the beginning, set head to true; if the missing mnemonic words are at the end, set it to false.
head = true

# address type, currently only support p2wpkh format 
addr_type = "p2wpkh"

# expect bitcoin address
expect_addr = ""
```

