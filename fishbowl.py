class FishBowl:
    rounds = 10
    blocklen = 10
    shift = 3
    def tonums(self, key):
        k = []
        for x in xrange(len(key)):
            k.append(ord(key[x]) - 65)
        return k
    
    def genRkeys(self, key, rounds, blocklen):
        k = []
        for x in xrange(len(key)):
            k.append(ord(key[x]) - 65)
        roundkeys = []
        for r in xrange(rounds):
            rk = [0] * blocklen
            c = 0
            for x in xrange(len(k)):
                k[x] = (k[x] + k[x]) % 26
            for x in xrange(blocklen):
                rk[x] = (rk[x] + k[c]) % 26
                c = (c + 1) % len(k)
            roundkeys.append(rk)
        return roundkeys

    def gensbox(self, key, blocklen):
        S = []
        k = self.tonums(key)
        klen = len(k)
        j = 0
        c = 0
        for el in k:
            j = (j + el) % 26
        for x in xrange(blocklen):
            box = range(26)
            for y in xrange(26):
                k[c % klen] = (k[c % klen] + k[(c + 1) % klen]) % 26
                j = (j + k[c % klen]) % 26
                box[c], box[j] = box[j], box[c]
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
        blocks = (len(secret) / blocklen) / 2
        extra = (blocklen * 2) - (len(secret) % (blocklen * 2))
        if extra != 0:
            blocks += 1
        s1 = 0
        s2 = blocklen
        e1 = blocklen
        e2 = blocklen * 2
        self.S = self.gensbox(key, blocklen)
        self.roundkeys = self.genRkeys(key, self.rounds, blocklen)
        for x in xrange(len(self.roundkeys)):
            self.subblock(self.roundkeys[x], self.S, blocklen)
            
        previous_block = list(IV)
        for x in range(blocks):
            block1 = self.tonums(secret[s1:e1])
            block2 = self.tonums(secret[s2:e2])
            s1 += blocklen * 2
            s2 += blocklen * 2
            e1 += blocklen * 2
            e2 += blocklen * 2
            if x == (blocks - 1):
                if extra != 0:
                    if extra > (blocklen):
                        d = (blocklen * 2) - extra
                        d1 = blocklen - (d % blocklen)
                        for b in xrange(d1):
                            block1.append(extra)
                        for b in xrange(blocklen):
                            block2.append(extra)
                    elif extra <= blocklen:
                        for b in xrange(extra):
                            block2.append(extra)

            for y in xrange(blocklen):
                block1[y] = (block1[y] + previous_block[y]) % 26
            for y in xrange(blocklen):
                block2[y] = (block2[y] + previous_block[y + blocklen]) % 26

            for r in xrange(self.rounds):
                block1, block2 = self.roundenc(block1, block2, blocklen, r)
            previous_block = list(block1)
            previous_block.extend(block2)
            ctxt.append(self.tochars(block1))
            ctxt.append(self.tochars(block2))
        return "".join(ctxt)
    
    def decrypt(self, secret, key, iv):
        k = self.tonums(key)
        IV = self.tonums(iv)
        ctxt  = []
        c = 0
        klen = len(k)
        blocklen = self.blocklen
        blocks = len(secret) / (blocklen * 2)
        if blocks == 0:
            blocks += 1
        s1 = 0
        s2 = blocklen
        e1 = blocklen
        e2 = blocklen * 2
        self.S = self.gensbox(key, blocklen)
        self.roundkeys = self.genRkeys(key, self.rounds, blocklen)
        for x in xrange(len(self.roundkeys)):
            self.subblock(self.roundkeys[x], self.S, blocklen)
        previous_block = list(IV)
        for x in range(blocks):
            block1 = self.tonums(secret[s1:e1])
            block2 = self.tonums(secret[s2:e2])
            s1 += blocklen * 2
            s2 += blocklen * 2
            e1 += blocklen * 2
            e2 += blocklen * 2
            last_block = list(block1)
            last_block.extend(block2)
            for r in reversed(xrange(self.rounds)):
                block1, block2 = self.rounddec(block1, block2, blocklen, r)
            for y in xrange(blocklen):
                block1[y] = (block1[y] - previous_block[y]) % 26
            for y in xrange(blocklen):
                block2[y] = (block2[y] - previous_block[y + blocklen]) % 26
            if x == (blocks - 1):
                mark = block2[len(block2) - 1]
                count = 0
                if mark <= blocklen:
                    m = blocklen - 1
                    for b in xrange(mark):
                        if block2[m] == mark:
                            count += 1
                            m = m - 1
                    if count == mark:
                        block2 = block2[:(len(block2) - mark)]
                elif mark > blocklen:
                    m = blocklen - 1
                    for b in xrange(blocklen):
                        if block2[m] == mark:
                            count += 1
                            m = m - 1
                    m = (blocklen) - 1
                    d = (blocklen * 2) - mark
                    d1 = blocklen - d
                    for b in xrange(d1):
                        if block1[m] == mark:
                            count += 1
                            m = m - 1
                    if count == mark:
                        block1 = block1[:len(block1) - d1]
                        block2 = []

            previous_block = list(last_block)
            ctxt.append(self.tochars(block1))
            ctxt.append(self.tochars(block2))
        return "".join(ctxt)
