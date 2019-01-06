# FishBowl
FishBowl is a mod 26 (A-Z) block cipher modeled after a combination of Blowfish and Speck ciphers.

It operates on blocks of 20 characters, has 10 key dependent S-Boxes and applies a 10 character round key per round.  10 rounds is the default number of rounds.

One FishBowl round consists of the following operations:

- Right half rotated 3 characters to the right
- Right half added to the round key
- Left half substituted through the S-Boxes
- Left half added to the right half
- Right half added to the left half
- Left and Right halves are swapped


Currently, FishBowl is available in CBC and OFB modes.

# fbcrypt.py usage

python fbcrypt.py encrypt filename1 filename2 PASSWORD

python fbcrypt.py decrypt filename2 filename3 PASSWORD
