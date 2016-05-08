from MiniNero import *
from PaperWallet import *
from RingCT2 import *

def ecdhMultiEncode(receiverPks):
    i = 0
    n = len(receiverPks)
    rv = [None] * n
    epass = [None] * n
    
    e, E = skpkGen()
    ep, Ep = skpkGen()
    
    for i in range(0, n):
        rv[i] = scalarmultKey(receiverPks[i], ep)
        epass[i] = 
    return rv, ep, Ep

def InitiateFill(ParticipantPubs, InitiatorSk, InitiatorPk):
    sk, pk = ctskpkGen
    
    return 0
    
def ParticipateFill():
    return 0
    
def VerifyFill():
    return 0
    
def InitiateSpend():
    return 0
    
def ParticipateSpend():
    return 0
    
def VerifySpend():
    
