class FishBowlOFB:
    rounds = 10
    blocklen = 20
    shift = 3
    def tonums(self, key):
        k = []
        for x in xrange(len(key)):
            k.append(ord(key[x]) - 65)
        return k
    
    def genRkeys(self, key, rounds, blocklen):
        k = [0] * len(key)
        j = 0
        for c, byte in enumerate(key):
            k[c] = (k[c] + (ord(byte) - 65)) % 26
            j = (j + (ord(byte) - 65)) % 26
        roundkeys = []
        for r in range(rounds):
            rk = [0] * blocklen
            c = 0
            for x in range(26):
                j = k[j]
                k[j] = (k[c] + k[j]) % 26
                output = (k[j] + k[k[j]]) % 26
                k[c] = (k[c] + output) % 26
                k = self.rotate(k, self.shift)
                c = (c + 1) % 26
            for x in range(100 * 26):
                j = k[j]
                k[j] = (k[c] + k[j]) % 26
                output = (k[j] + k[k[j]]) % 26
                k[c] = (k[c] + output) % 26
                k = self.rotate(k, self.shift)
                c = (c + 1) % 26
            for x in range(blocklen):
                j = k[j]
                k[j] = (k[c] + k[j]) % 26
                output = (k[j] + k[k[j]]) % 26
                k = self.rotate(k, self.shift)
                rk[x] = (rk[x] + output) % 26
                c = (c + 1) % len(k)
            roundkeys.append(rk)
        return roundkeys

    def gensbox(self, key, blocklen):
        S = []
        k = [0] * len(key)
        j = 0
        for c, byte in enumerate(key):
            k[c] = (k[c] + (ord(byte) - 65)) % 26
            j = (j + (ord(byte) - 65)) % 26
        c = 0
        for x in range(blocklen):
            box = list(range(26))
            for y in range(26):
                j = k[j]
                k[j] = (k[j] + k[c]) % 26
                output = (k[j] + k[k[j]]) % 26
                self.rotate(k, self.shift)
                box[c], box[output] = box[output], box[c]
                c = (c + 1) % 26
            S.append(box)
        return S

    def subblock(self, block, S, blocklen):
        b = list(block)
        for x in xrange(blocklen):
            b[x] = S[x][b[x]]
        return b

    def rotate(self, block, r):
        for x in xrange(r):
            block.append(block.pop(0))
        return block

    def rotateback(self, block, r):
        for x in xrange(r):
            block.insert(0, block.pop())
        return block

    def roundenc(self, left, right, blocklen, r):
        right = self.rotate(right, self.shift)
        for x in xrange(blocklen):
            right[x] = (right[x] + self.roundkeys[r][x]) % 26
            left[x] = self.S[x][left[x]]
            left[x] = (left[x] + right[x]) % 26
            right[x] = (right[x] + left[x]) % 26
        return right, left
    
    def rounddec(self, left, right, blocklen, r):
        for x in reversed(xrange(blocklen)):
            left[x] = (left[x] - right[x]) % 26
            right[x] = (right[x] - left[x]) % 26
            right[x] = self.S[x].index(right[x])
            left[x] = (left[x] - self.roundkeys[r][x]) % 26
        left = self.rotateback(left, self.shift)
        return right, left

    def tochars(self, nums):
        for x in xrange(len(nums)):
            nums[x] = chr(nums[x] + 65)
        return "".join(nums)

    def encrypt(self, secret, key, iv):
        k = self.tonums(key)
        IV = self.tonums(iv)
        ctxt  = []
        c = 0
        klen = len(k)
        blocklen = self.blocklen
        blocks = (len(secret) / blocklen)
        bl = blocklen / 2
        extra = (blocklen) - (len(secret) % (blocklen))
        if extra != 0:
            blocks += 1
        s1 = 0
        e1 = blocklen
        self.S = self.gensbox(key, blocklen)
        self.roundkeys = self.genRkeys(key, self.rounds, blocklen)
        for x in xrange(len(self.roundkeys)):
            self.subblock(self.roundkeys[x], self.S, blocklen)
            
        block1 = list(IV[:len(IV) / 2])
        block2 = list(IV[len(IV) / 2:])
        for x in range(blocks):
            block = self.tonums(secret[s1:e1])
            s1 += blocklen
            e1 += blocklen

            for r in xrange(self.rounds):
                block1, block2 = self.roundenc(block1, block2, bl, r)
            k = list(block1)
            k.extend(block2)
            if x == (blocks - 1):
                blocklen = len(block)
            for y in xrange(blocklen):
                block[y] = (block[y] + k[y]) % 26
                
            ctxt.append(self.tochars(block))
        return "".join(ctxt)
    
    def decrypt(self, secret, key, iv):
        k = self.tonums(key)
        IV = self.tonums(iv)
        ctxt  = []
        c = 0
        klen = len(k)
        blocklen = self.blocklen
        blocks = len(secret) / (blocklen)
        bl = blocklen / 2
        if blocks == 0:
            blocks += 1
        s1 = 0
        e1 = blocklen
        self.S = self.gensbox(key, blocklen)
        self.roundkeys = self.genRkeys(key, self.rounds, blocklen)
        for x in xrange(len(self.roundkeys)):
            self.subblock(self.roundkeys[x], self.S, blocklen)
        block1 = list(IV[:len(IV) / 2])
        block2 = list(IV[len(IV) / 2:])
        for x in range(blocks):
            block = self.tonums(secret[s1:e1])
            s1 += blocklen
            e1 += blocklen
            for r in xrange(self.rounds):
                block1, block2 = self.roundenc(block1, block2, bl, r)
            k = list(block1)
            k.extend(block2)
            if x == (blocks - 1):
                blocklen = len(block)
            for y in xrange(blocklen):
                block[y] = (block[y] - k[y]) % 26
            ctxt.append(self.tochars(block))
        return "".join(ctxt)

class FishBowlKDF:
    def kdf(self, password, keylen=26, iterations=10):
        diff = keylen - len(password)
        iv = "AAAAAAAAAAAAAAAAAAAA"
        for x in xrange(diff):
            password += "A"
        fb = FishBowlOFB()
        key = password
        for i in xrange(iterations):
            key = fb.encrypt(key[:keylen], key, iv)
        return key
