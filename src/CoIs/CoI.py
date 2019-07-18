#!/usr/bin/env python
###############################################################################################
# (c) 2014, COmputer SEcurity (COSEC) - Universidad Carlos III de Madrid. All rights reserverd.
# Main Author: Guillermo Suarez de Tangil - guillermo.suarez.tangil@uc3m.es
###############################################################################################

import sys, math, os

from sets import Set
#from PIL import Image
from tempfile import mkstemp
from subprocess import Popen, PIPE, STDOUT, call


# ------------------

class CoI(object):
    def __init__(self, apk):
        self.type = None
        self.apk = apk

    def get_apk(self):
        return self.apk

    def get_type(self):
        return self.type


    '''
    Returns the Shannon Entropy of the input
    '''
    def shannonEntropy(self, input_string):
        
        # calculate the frequency of each symbol in the string
        inputStrList = list(input_string)
        alphabet = list(Set(inputStrList))
        freqList = []
        for symbol in alphabet:
            ctr = 0
            for sym in inputStrList:
                if sym == symbol:
                    ctr += 1
            freqList.append(float(ctr) / len(inputStrList))

        # Shannon entropy
        ent = 0.0
        for freq in freqList:
            ent = ent + freq * math.log(freq, 2)
        ent = -ent
        
        return ent


'''
    def shannonEntropyImageFile(self, img_file_path):
        
        #Snannon Entropy for Red, Green, Blue:
        im = Image.open(img_file_path)
        rgbHistogram = im.histogram()
        ent_rgb = []
        for rgb in range(3):
            totalPixels = sum(rgbHistogram[rgb * 256 : (rgb + 1) * 256])
            ent = 0.0
            for col in range(rgb * 256, (rgb + 1) * 256):
                freq = float(rgbHistogram[col]) / totalPixels
                if freq > 0:
                    ent = ent + freq * math.log(freq, 2)
            ent = -ent
            ent_rgb.append(ent)
        return ent_rgb
'''