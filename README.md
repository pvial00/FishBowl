# FishBowl
FishBowl is a mod 26 (A-Z) block cipher modeled after a combination of Blowfish and Speck ciphers.

It operates on blocks of 20 characters, has 10 key dependent S-Boxes and applies a 10 character round key per round.  10 rounds is the default number of rounds.

Currently, FishBowl is available in CBC mode only.

# fbcrypt.py usage

python fbcrypt.py encrypt filename1 filename2 PASSWORD

python fbcrypt.py decrypt filename2 filename3 PASSWORD
