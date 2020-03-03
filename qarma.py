#!/usr/bin/env python2
# encoding=utf-8

# selection of used sbox
sbox0 = [0,14,2,10,9,15,8,11,6,4,3,7,13,12,1,5] # sbox 0: lightest version, fixed points at 0,2
sbox1 = [10,13,14,6,15,7,3,5,9,8,0,12,11,1,2,4] # sbox 1: no fixed points
sbox2 = [11,6,8,15,12,0,9,14,3,7,4,5,13,2,1,10] # sbox 2: lightweight sbox from prince family
used_sbox = sbox0
used_sbox_inv = [used_sbox.index(x) for x in range(16)]

state_permutation = [0,11,6,13,10,1,12,7,5,14,3,8,15,4,9,2]
state_permutation_inv = [state_permutation.index(x) for x in range(16)]
tweak_permutation = [6,5,14,15,0,1,2,3,7,12,13,4,8,9,10,11]


def HexToBlock(hexstring):
    return [int(b,16) for b in hexstring]

def BlockToHex(block):
    return "".join([hex(b)[2:] for b in block])

alpha_string = "C0AC29B7C97C50DD"
alpha = HexToBlock(alpha_string)

round_constants_string = [
        "0000000000000000",
        "13198A2E03707344",
        "A4093822299F31D0",
        "082EFA98EC4E6C89",
        "452821E638D01377",
        "BE5466CF34E90C6C",
        "3F84D5B5B5470917",
        "9216D5D98979FB1B"]

round_constants = [HexToBlock(s) for s in round_constants_string]

def SubBytes(state,inverse):
    if not inverse:
        return [used_sbox[b] for b in state]
    else:
        return [used_sbox_inv[b] for b in state]

def XorBlocks(a,b):
    return [x^y for x,y in zip(a,b)]

def rot(b, r):
    return ((b << r) | (b >> (4-r))) % 16



def MixColumns_M41(col):
    newcol = [0]*4
    newcol[0] = rot(col[1],1) ^ rot(col[2],2) ^ rot(col[3],3)
    newcol[1] = rot(col[0],3) ^ rot(col[2],1) ^ rot(col[3],2)
    newcol[2] = rot(col[0],2) ^ rot(col[1],3) ^ rot(col[3],1)
    newcol[3] = rot(col[0],1) ^ rot(col[1],2) ^ rot(col[2],3)
    return newcol

def MixColumns_M43(col):
    newcol = [0]*4
    newcol[0] = rot(col[1],1) ^ rot(col[2],2) ^ rot(col[3],1)
    newcol[1] = rot(col[0],1) ^ rot(col[2],1) ^ rot(col[3],2)
    newcol[2] = rot(col[0],2) ^ rot(col[1],1) ^ rot(col[3],1)
    newcol[3] = rot(col[0],1) ^ rot(col[1],2) ^ rot(col[2],1)
    return newcol

UsedMixColumns = MixColumns_M43
def MixColumns(state):
    mixed_state = [0 for _ in range(16)]
    for i in range(4):
        incol = [state[0+i], state[4+i], state[8+i], state[12+i]]
        outcol = UsedMixColumns(incol)
        mixed_state[0+i], mixed_state[4+i], mixed_state[8+i], mixed_state[12+i] = outcol
    return mixed_state

def PermuteTweak(tweak):
    return [tweak[i] for i in tweak_permutation]

def PermuteState(state, inverse):
    if inverse:
        return [state[i] for i in state_permutation_inv]
    else:
        return [state[i] for i in state_permutation]

def TweakLFSR(tweak):
    for b in [0,1,3,4,8,11,13]:
        t = tweak[b]
        b3,b2,b1,b0 = (t>>3)&1,(t>>2)&1,(t>>1)&1,(t>>0)&1
        tweak[b] = ((b0^b1)<<3) | (b3 << 2) | (b2<<1) | (b1<<0)
    return tweak

def CalcTweak(tweak, r):
    tweak_r = tweak
    for i in range(r):
        tweak_r = PermuteTweak(tweak_r)
        tweak_r = TweakLFSR(tweak_r)
    return tweak_r

def CalcRoundTweakey(tweak, r, k0, backwards):
    tweakey = CalcTweak(tweak,r)
    tweakey = XorBlocks(tweakey, k0)
    tweakey = XorBlocks(tweakey, round_constants[r])
    if backwards:
       tweakey = XorBlocks(tweakey, alpha)
    return tweakey


def Round(state, tweakey, r, backwards):

    #short round 0
    if not backwards:
        state = XorBlocks(state, tweakey)
        if r != 0:
            state = PermuteState(state,False)
            state = MixColumns(state)
        state = SubBytes(state,False)
        return state
    else:
        state = SubBytes(state,True)
        if r != 0:
            state = MixColumns(state)
            state = PermuteState(state,True)
        state = XorBlocks(state, tweakey)
        return state


def MiddleRound(state, k1):
    state = PermuteState(state, False)
    state = MixColumns(state)
    state = XorBlocks(state, k1)
    state = PermuteState(state, True)
    return state

def qarma64(plaintext, tweak, key, encryption=True, rounds=5):
    w0,k0 = key[:16], key[16:]
    w0_int = int(w0, 16)
    w1_int = ((w0_int >>1) | ((w0_int & 1) <<63)) ^ (w0_int >> 63)
    w1 = hex(w1_int)[2:]
    if w1[-1] == "L": w1 = w1[:-1]
    w1 = w1.rjust(16,"0")

    w0,w1,k0 = HexToBlock(w0), HexToBlock(w1), HexToBlock(k0)
    p,t = HexToBlock(plaintext), HexToBlock(tweak)

    if encryption:
        k1 = k0
    else:
        w0,w1 = w1,w0
        k1 = MixColumns(k0)
        k0 = XorBlocks(k0, alpha)

    state = XorBlocks(p, w0)
    for i in range(rounds):
        tweakey = CalcRoundTweakey(t, i, k0, False)
        state = Round(state, tweakey, i, False)

    tweakey = CalcTweak(t, rounds)
    state = Round(state, XorBlocks(w1, tweakey), rounds, False)
    state = MiddleRound(state,k1)
    state = Round(state, XorBlocks(w0, tweakey), rounds, True)

    for i in reversed(range(rounds)):
        tweakey = CalcRoundTweakey(t, i, k0, True)
        state = Round(state, tweakey, i, True)

    cipher = XorBlocks(state, w1)

    return BlockToHex(cipher)


if __name__ == "__main__":

    #Testing official test vectors

    P  = "fb623599da6e8127"
    T  = "477d469dec0b8762"
    w0 = "84be85ce9804e94b"
    k0 = "ec2802d4e0a488e9"

    C5 = qarma64(P, T, w0+k0)
    C6 = qarma64(P, T, w0+k0,rounds=6)
    C7 = qarma64(P, T, w0+k0,rounds=7)

    print "5 rounds"
    print "Expected:   3ee99a6c82af0c38"
    print "Calculated: " + C5

    print "6 rounds"
    print "Expected:   9f5c41ec525603c9"
    print "Calculated: " + C6

    print "7 rounds"
    print "Expected:   bcaf6c89de930765"
    print "Calculated: " + C7
