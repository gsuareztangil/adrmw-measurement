#!/usr/bin/env python
###############################################################################################
# (c) 2014, COmputer SEcurity (COSEC) - Universidad Carlos III de Madrid. All rights reserverd.
# Main Author: Guillermo Suarez de Tangil - guillermo.suarez.tangil@uc3m.es
###############################################################################################

import sys, os, uuid
from CoI import CoI


try:
    sys.path.append(os.environ['ANDROGUARD_HOME'])
    import androguard
    from androguard.core.androgen import *
    from androguard.core.bytecodes import apk, dvm
    from androguard.core.analysis import analysis, ganalysis
    from androguard.core import androconf
except Exception as e:
    print str(e)
    print "ANDROGUARD_HOME is not set. Try export ANDROGUARD_HOME=/path/to/library"
    sys.exit(-1)

class FileCoI(CoI):
    def __init__(self, apk, file_name, extension, magic_key, magic_description, path, crc):
        CoI.__init__(self, apk)
        #super(CoI,self).__init__(apk)
        self.type = "FileCoI"
        self.file_name = file_name
        self.extension = extension
        self.magic_key = magic_key
        self.magic_description = magic_description
        self.path = path
        self.crc = crc
        self.extra = ""
    
    def toString(self):
        return self.path + " - " + self.magic_key + ". " + self.extra
    
    def get_attributes(self):
        return [self.apk, self.type, self.extension, self.magic_key, self.magic_description, self.path, self.crc]
    
    def get_file_name(self):
        return self.file_name
    
    def get_extension(self):
        return self.extension

    def get_magic_key(self):
        return self.magic_key

    def get_magic_description(self):
        return self.magic_description

    def get_path(self):
        return self.path
    
    def get_crc(self):
        return self.crc
    
    def get_extra(self):
        return self.extra



# ------------------

'''
    ImageFileMatch: Returns True if the magic number of the file is an image
'''
class ImageFileMatch(FileCoI):
    
    file_extensions = ["PNG", "JPG",  "PEG", "GIF", "EXIF", "TIFF", "TIF", "RAW", "ARI", "R3D", "BMP", "PPM", "PGM", "PBM", "PNM", "PFM", "PAM", "WEBP"]
    
    def get_sub_type(self):
        return self.__class__.__name__
    
    def check(self):
        if "image" in self.magic_description and self.extension.replace(".", "").upper() in self.file_extensions:
            return True
        else:
            return False

# ------------------

'''
    Image File Extension Mismatch: Returns True when the extension of the file-component suggest that the file is an image but magic number manifest the contrary.
'''
class ImageFileExtensionMismatch(FileCoI):
    
    file_extensions = ["PNG", "JPG",  "PEG", "GIF", "EXIF", "TIFF", "TIF", "RAW", "ARI", "R3D", "BMP", "PPM", "PGM", "PBM", "PNM", "PFM", "PAM", "WEBP"]
    
    def get_sub_type(self):
        return self.__class__.__name__

    def check(self):
        if not "image" in self.magic_description and self.extension.replace(".", "").upper() in self.file_extensions:
            return True
        else:
            return False

# ------------------

'''
    APK File Extension Mismatch: Returns True when the magic number of the file-component suggest that the file is an APK but extension manifest the contrary.
    '''
class APKFileExtensionMismatch(FileCoI):
       
    def get_sub_type(self):
        return self.__class__.__name__
    
    def check(self):
        if self.magic_key.upper() ==  "APK" and not self.extension.replace(".", "").upper() == "APK":
            return True
        elif self.magic_key.upper() ==  "DEX" and not self.extension.replace(".", "").upper() == "DEX":
            return True
        else:
            return False
                
# ------------------

'''
    TextScriptMatch: Returns True if the magic number of the file matches with "Text executable"
'''
class TextScriptMatch(FileCoI):
    
    def get_sub_type(self):
        return self.__class__.__name__
    
    def check(self):
        if "TEXT EXECUTABLE" == self.magic_key.upper():
            return True
        else:
            return False


# ------------------

'''
    ELFExecutableMatch: Returns True if the magic number of the file matches with "ELF Executable"
'''
class ELFExecutableMatch(FileCoI):
    
    def get_sub_type(self):
        return self.__class__.__name__
    
    def check(self):
        if "ELF" is self.magic_key:
            return True
        else:
            return False


# ------------------

'''
    DEXFileMatch: Returns True if the magic number of the file matches with "DEX"
'''
class DEXFileMatch(FileCoI):
    
    def get_sub_type(self):
        return self.__class__.__name__
    
    def check(self):
        if "DEX" == self.magic_key and "classes.dex" != self.path:
            return True
        else:
            return False


# ------------------

'''
    APKFileMatch: Returns True if the magic number of the file matches with "APK"
'''
class APKFileMatch(FileCoI):
    
    def get_sub_type(self):
        return self.__class__.__name__
    
    def check(self):
        if "APK" == self.magic_key:
            return True
        else:
            return False


# ------------------

'''
    Encrypted or compressed file according to Shannon Entropy
'''
class EncryptedOrCompressedMatch(FileCoI):
    
    def get_sub_type(self):
        return self.__class__.__name__
    
    def check(self):
        if self.shannonEntropy(self.apk.get_file(self.path)) > 3.95:
            return True
        else:
            return False


#class Test(FileCoI):
#
#    def get_sub_type(self):
#        return self.__class__.__name__
#    
#    def check(self):
#
#        keep = False
#        
#        if "APK" == self.magic_key.upper():
#            keep = True
#
#        if "DEX" == self.magic_key.upper():
#            keep = True
#            
#        if "ELF" == self.magic_key.upper():
#            keep = True
#            
#        if "DOS" == self.magic_key.upper():
#            keep = True
#            
#        if "COM" == self.magic_key.upper():
#            keep = True
#            
#        if self.magic_key.upper().startswith('PE'):
#            keep = True
#            
#        if "TEXT EXECUTABLE" == self.magic_key.upper():
#            keep = True
#            
#        if keep:            
#            print '=====', self.magic_key, '-', self.magic_description
#            print '++++++++++', self.path
#            #content = self.apk.get_file(self.path)
#            #with open(os.path.join('/media/jsons/files', str(uuid.uuid4()) + '.' + os.path.basename(self.file_name) + '.' + self.magic_key  + self.extension), 'wb') as thefile:
#            #    thefile.write(content)
#
#        return keep




# ------------------

'''
AdvancedCodeFound: Returns True if the "APK" or the "DEX" component has advanced code such as Native, Dynamic or Reflexion code.
Warning: This CoI slows down the analysis
'''
class AdvancedCodeFound(FileCoI):
    
    def get_sub_type(self):
        return self.__class__.__name__
    
    def analyze(self, d):
        
        ret = False
        dvmx = analysis.VMAnalysis(d)
        
        if analysis.is_native_code(dvmx):
            ret = True
            self.extra += "NativeCodeFound; "
        
        if analysis.is_dyn_code(dvmx):
            ret = True
            self.extra += "DynCodeFound; "
        
        if analysis.is_reflection_code(dvmx):
            ret = True
            self.extra += "ReflexionCodeFound; "
        
        #if analysis.is_ascii_obfuscation(d):
            #ret = True
            #self.extra + "AsciiObfuscationCodeFound; "
        
        #if analysis.is_crypto_code(d):
            #ret = True
            #self.extra + "AsciiObfuscationCodeFound; "
        
        return ret
    
    def check(self):
        ret = False
        if "DEX" is self.magic_key:
            d = dvm.DalvikVMFormat(self.apk.get_file(self.path))
            return self.analyze(d)
        elif "APK" is self.magic_key:
            app = apk.APK(self.apk.get_file(self.path), raw=True)
            d = dvm.DalvikVMFormat( app.get_dex() )
            return self.analyze(d)
        else:
            return False


# ------------------

'''
    
'''
class TemplateFileCheck(FileCoI):
    
    def get_sub_type(self):
        return self.__class__.__name__
    
    def check(self):
        return False
