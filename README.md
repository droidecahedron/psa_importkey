# psa_importkey


# hardware
`nRF54L15DK`

# software
nRF Connect SDK `v3.1.0`

# desc
This sample uses the multi-step PSA api for manual iv generation.
It has "mock" generated keys `DEBUG_MOCK_KEYS`, in reality you should pass these keys in via secure provisioning step.

The keys are stored with PSA API to a secure element -- the application prints what key it generated for debug purposes before it purges it in the import function.
**A single master key, re-used keys, and easily obtainable keys are a bad idea. Do not commit any key material to code anywhere.**.

The combination of the public + private key thought process and randomized initialization vector are used in this sample.
The private imported keys are never shared other than in the "provisioning" stage of the devices.

The encrypt/decrypt process is separated, and the IV generation is stored separately.

The overall thinking is you provision each device with the keys, and it will use those keys for cryptographic operation. This sample is set up for 3 keys via `NUM_KEYS`. The first key ID handle starts at the user min, 0 is not an able user keyhandle (see link in code comments).

So with each transmission over whatever medium, you can also append the IV.
The receiving device only knows the IV, it does not know which private key was used to encrypt.
So it will iterate through all the keys it has to see if there's a match.

You can alternatively rely on crcs or embedded control words.

You can reset the device and it won't try to re-create new keys. It only creates new keys on a reset.

This way, you can see the message encryption vary and which private key was successful and decrypting the message.

The following [blog](https://devzone.nordicsemi.com/nordic/nordic-blog/b/blog/posts/intro-to-application-level-security-using-the-ecb-) is a good read for a lot of the thinking in the sample.

Majority of the code was also based on the [persistent-key-usage](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/crypto/persistent_key_usage) crypto sample.



# building and running
`west build -b nrf54l15dk/nrf54l15/cpuapp/ns -p`

followed by

`west flash --recover` for first startup, and any time you want a fresh set of keys.

# example output


## Startup and key generation
```
** Booting nRF Connect SDK v3.1.0-6c6e5b32496e ***
*** Using Zephyr OS v4.1.99-1612683d4010 ***
[00:00:00.010,347] <inf> enc_central: crypto init
[00:00:00.015,615] <inf> enc_central: KEY ID 1 ATTR GET STATS -136
[00:00:00.022,073] <inf> enc_central: generating and importing keys
[00:00:00.028,818] <inf> enc_central: made key %z/Kr, importing
[00:00:00.050,627] <inf> enc_central: Key imported! index 0 id 1
[00:00:00.056,993] <inf> enc_central: Key imported successfuly, handle 1
[00:00:00.064,098] <inf> enc_central: made key ԨolC99   ,, importing
[00:00:00.076,591] <inf> enc_central: Key imported! index 1 id 2
[00:00:00.082,962] <inf> enc_central: Key imported successfuly, handle 2
[00:00:00.090,074] <inf> enc_central: made key 귬mթnP X, importing
[00:00:00.103,132] <inf> enc_central: Key imported! index 2 id 3
[00:00:00.109,497] <inf> enc_central: Key imported successfuly, handle 3
[00:00:00.116,479] <inf> enc_central: unenc msg: Example string to demonstrate basic usage of a persistent key.
```

## Random key selection and Encryption
```
[00:00:00.127,003] <inf> enc_central: random key choice for encrypt: 2
[00:00:00.133,807] <inf> enc_central: encrypting
[00:00:00.139,636] <inf> enc_central: generated IV: +   \Y=
[00:00:00.146,551] <inf> enc_central: encrypt success
[00:00:00.151,892] <inf> enc_central: Encryption successful!
[00:00:00.157,907] <inf> enc_central: IV: +     \Y= len 16
[00:00:00.164,343] <inf> enc_central: ---- Plaintext (len: 100): ----
[00:00:00.171,124] <inf> enc_central: Content:
                                      45 78 61 6d 70 6c 65 20  73 74 72 69 6e 67 20 74 |Example  string t
                                      6f 20 64 65 6d 6f 6e 73  74 72 61 74 65 20 62 61 |o demons trate ba
                                      73 69 63 20 75 73 61 67  65 20 6f 66 20 61 20 70 |sic usag e of a p
                                      65 72 73 69 73 74 65 6e  74 20 6b 65 79 2e 00 00 |ersisten t key...
                                      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |........ ........
                                      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |........ ........
                                      00 00 00 00                                      |....             
[00:00:00.240,220] <inf> enc_central: ---- Plaintext end  ----
[00:00:00.246,401] <inf> enc_central: ---- Encrypted text (len: 116): ----
[00:00:00.253,610] <inf> enc_central: Content:
                                      14 f4 ad 42 da 9c f2 6f  b6 88 09 71 33 3d 92 de |...B...o ...q3=..
                                      a3 3d 19 ee 17 6a 79 33  38 88 01 a1 2c 74 91 6a |.=...jy3 8...,t.j
                                      6d 1b 88 f7 a5 b7 e6 d4  e4 7a 4b 51 4a c8 9d 1e |m....... .zKQJ...
                                      07 17 97 36 a5 44 db e9  70 d9 e8 e2 4a 3e 57 3a |...6.D.. p...J>W:
                                      cf a8 97 13 8e 30 4f 4d  bd d4 e0 f5 ea 16 c9 8f |.....0OM ........
                                      9e 1e 63 44 80 e0 d9 55  62 f8 ed 57 57 d8 57 80 |..cD...U b..WW.W.
                                      ed 22 06 91 00 00 00 00  00 00 00 00 00 00 00 00 |."...... ........
                                      00 00 00 00                                      |....             
[00:00:00.331,875] <inf> enc_central: ---- Encrypted text end  ----
[00:00:00.338,481] <inf> enc_central: enc op len: 100
```

## Decryption attempts
```
[00:00:00.343,890] <inf> enc_central: Decrypt attempt with key 0
[00:00:00.351,244] <inf> enc_central: decrypt attempt successfully executed
[00:00:00.358,478] <inf> enc_central: Decrypted data does not match original
[00:00:00.365,858] <inf> enc_central: ---- dec (len: 100): ----
[00:00:00.372,119] <inf> enc_central: Content:
                                      52 5b 11 99 6c 43 67 54  fb 8f d4 2e d4 c3 bb 30 |R[..lCgT .......0
                                      93 98 e1 ff c8 6c a4 b1  33 8a 60 32 94 4a 42 ae |.....l.. 3.`2.JB.
                                      9c 4a 99 0b 88 56 f0 95  d4 be ce b1 98 a5 42 1d |.J...V.. ......B.
                                      d5 32 93 9a e9 b4 b2 42  da 71 4a fd ec 43 49 85 |.2.....B .qJ..CI.
                                      a0 ad e0 06 fa 83 4d 36  3a e1 78 81 06 93 ce ab |......M6 :.x.....
                                      ab ba 51 db 51 9d 55 e5  d4 05 31 c0 8b a1 21 cc |..Q.Q.U. ..1...!.
                                      f9 a2 72 69                                      |..ri             
[00:00:00.441,201] <inf> enc_central: ---- dec end  ----
[00:00:00.446,866] <inf> enc_central: Decrypt attempt with key 1
[00:00:00.454,242] <inf> enc_central: decrypt attempt successfully executed
[00:00:00.461,477] <inf> enc_central: Decrypted data does not match original
[00:00:00.468,858] <inf> enc_central: ---- dec (len: 100): ----
[00:00:00.475,123] <inf> enc_central: Content:
                                      25 dd f1 66 06 75 75 1b  26 a3 60 89 8e bf c8 c5 |%..f.uu. &.`.....
                                      31 67 c7 30 95 1b 31 f4  62 7e 80 1b 57 30 90 66 |1g.0..1. b~..W0.f
                                      e4 0a fe 51 3b 93 17 1f  7e 81 7b df 44 7e bd 17 |...Q;... ~.{.D~..
                                      19 8b 77 0b a8 db 55 09  37 08 0d f5 21 dc 19 df |..w...U. 7...!...
                                      07 37 80 c9 c8 fa 3e c0  4f 19 95 23 6e eb 63 08 |.7....>. O..#n.c.
                                      e2 17 de 7b 06 2f 44 d1  88 34 97 48 ce ba 92 bc |...{./D. .4.H....
                                      9b 60 09 15                                      |.`..             
[00:00:00.544,229] <inf> enc_central: ---- dec end  ----
[00:00:00.549,895] <inf> enc_central: Decrypt attempt with key 2
[00:00:00.556,780] <inf> enc_central: decrypt attempt successfully executed
[00:00:00.564,019] <inf> enc_central: Encryption and decryption match
[00:00:00.570,793] <inf> enc_central: ---- dec (len: 100): ----
[00:00:00.577,059] <inf> enc_central: Content:
                                      45 78 61 6d 70 6c 65 20  73 74 72 69 6e 67 20 74 |Example  string t
                                      6f 20 64 65 6d 6f 6e 73  74 72 61 74 65 20 62 61 |o demons trate ba
                                      73 69 63 20 75 73 61 67  65 20 6f 66 20 61 20 70 |sic usag e of a p
                                      65 72 73 69 73 74 65 6e  74 20 6b 65 79 2e 00 00 |ersisten t key...
                                      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |........ ........
                                      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 |........ ........
                                      00 00 00 00                                      |....             
[00:00:00.646,185] <inf> enc_central: ---- dec end  ----
```

## key generation skipped on reset
```
*** Booting nRF Connect SDK v3.1.0-6c6e5b32496e ***
*** Using Zephyr OS v4.1.99-1612683d4010 ***
[00:00:19.269,291] <inf> enc_central: crypto init
[00:00:19.275,030] <inf> enc_central: KEY ID 1 ATTR GET STATS 0
[00:00:19.281,939] <inf> enc_central: KEY ID 2 ATTR GET STATS 0
[00:00:19.288,851] <inf> enc_central: KEY ID 3 ATTR GET STATS 0
[00:00:19.295,048] <inf> enc_central: all keys exist
[00:00:19.300,389] <inf> enc_central: Keys already exist, skipping to enc/dec
```

## idle loop
```
[00:00:15.545,260] <inf> enc_central: alive
[00:00:25.550,038] <inf> enc_central: alive
[00:00:35.555,035] <inf> enc_central: alive
[00:00:45.560,034] <inf> enc_central: alive
```