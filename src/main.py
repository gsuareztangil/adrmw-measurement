#!/usr/bin/env python
import sys, os, re, traceback, csv
from os import path
from optparse import OptionParser
import hashlib
from collections import Counter
import md5
import math
import copy
import random

import settings

import threading
from threading import Thread
import multiprocessing
from multiprocessing import Process, Manager
from multiprocessing import Lock
from multiprocessing.pool import ThreadPool
from functools import partial

import datetime
from timeit import default_timer
import numpy as np

import cPickle as pickle
import json

import CoIs
from CoIs import *

from readelf import ReadElf
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.descriptions import describe_sh_flags
from elftools.common.exceptions import *

try:
    sys.path.append(os.environ['ANDROGUARD_HOME'])
    from androguard.core.bytecodes import apk, dvm
    from androguard.core import androconf
    from androguard.core.analysis import analysis, ganalysis
except Exception as e:
    print str(e)
    print "ANDROGUARD_HOME is not set. Try export ANDROGUARD_HOME=/path/to/library"
    sys.exit(-1)


RATIO = 30
DEBUG = False
INCOGNITO_EXPERIMENT = True
MIN_NUM_SAMPLES = 7

'''
There are about 12/25 families (282/542 samples) where all their methods appear 
in all/most samples of the family (i.e.: pure malware or repackaging the same goodware). 
We set a cutoff of 90\%. 
'''
blacklist_families = ['goodware-play.google.com' , 'wpredirect', 'taocall', 'malmix', 'hiddenap', 'fareac', 'drgtwa', 'coab', 'cbook', 'afour', 'aewj', 'aecw', 'adzu', 'hmir', 'axnr', 'tucysms', 'dkienp', 'dqmedb', 'fakebkupt', 'aaaaaaaddo', 'avgh', 'eenoez', 'gvfy', 'kinpa', 'gxocr', 'dxsotf']

option_1 = { 'name' : ('-v', '--version'), 'help' : 'version of the API', 'action' : 'count' }
option_2 = { 'name' : ('-p', '--preprocess'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_3 = { 'name' : ('-e', '--postprocess'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_4 = { 'name' : ('-s', '--stats'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_5 = { 'name' : ('-t', '--timeline'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_6 = { 'name' : ('-l', '--libraries'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_7 = { 'name' : ('-r', '--resources'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_8 = { 'name' : ('', '--resourcesstats'), 'help' : 'file : use this filename', 'nargs' : 1 }
option_9 = { 'name' : ('-d', '--debug'), 'help' : 'Debug', 'action' : 'count' }
option_10 = { 'name' : ('-c', '--casestudy'), 'help' : 'file : use this filename', 'nargs' : 1 }
#option_2 = { 'name' : ('-d', '--directory'), 'help' : 'directory : use this directory', 'nargs' : 1 }

options = [option_1, option_2, option_3, option_4, option_5, option_6, option_7, option_8, option_9, option_10]

#Ljavax/crypto/
#Ljava/security/spec/
#Ljava/lang/reflect/Method


sensitive_API = { # We extract all API calls, but we keep this ones when running final stats
    'SmsManager:sendTextMessage': 0,
    'URL:openConnection': 0,
    'TelephonyManager:getDeviceId': 0,
    'TelephonyManager:getLine1Number': 0,
    'HttpURLConnection:connect': 0,
    'URLConnection:getInputStream': 0,
    'TelephonyManager:getSubscriberId': 0,
    'WifiManager:getConnectionInfo': 0,
    'TelephonyManager:getSimSerialNumber': 0,
    'ConnectivityManager:getActiveNetworkInfo': 0,
    'LocationManager:getLastKnownLocation': 0,
    'LocationManager:requestLocationUpdate': 0,
    'TelephonyManager:getCellLocation': 0,
    # ------------------------------------
    'ContentResolver:insert': 0,
    'ContentResolver:delete': 0,
    'ContentResolver:query': 0,
    'Context:getFilesDir': 0,
    'Context:openFileOuput': 0,
    'Context:getApplicationInfo': 0,
    'Intent:setDataAndType': 0,
    'Intent:setFlags': 0,
    'Intent:addFlags': 0,
    'Intent:setDataAndType': 0,
    'ActivityManager:getRunningServices': 0,
    'ActivityManager:getMemoryInfo': 0,
    'ActivityManager:restartPackage': 0,
    'PackageManager:getInstalledPackages': 0,
    'TelephonyManager:getNetworkOperator': 0,
    'Process:myPid': 0,
    'Process:killProcess': 0,
    'File:mkdir': 0,
    'File:delete': 0,
    'File:exists': 0,
    'File:ListFiles': 0,
    'WifiManager:isWifiEnabled' : 0,
    'WifiManager:getIpAddress' : 0,
    'ClassLoader:DexClassLoader' : 0,
    'Class:getClassLoader' : 0,
    'System:loadLibrary' : 0,
    'Runtime:exec' : 0,
    'crypto:':0
    }

sh_commands = [ "/system/bin/su",
                "/system/bin/sh",
                "dalvik-cache",
                "/data/log/",
                "/data/data",
                "/data",
                "/system/app",
                "/system/xbin",
                "/system/bin/pm",
                "/system/bin/am",
                "/etc/init.d",
                "/sdcard",
                "Superuser.apk",
                "busybox",
                "chown",
                "chmod",
                "fstab",
                "getprop",
                "grep",
                "install",
                "mkpartfs",
                "mkdir",
                "mount",
                "parted",
                "reboot",
                "remount",
                "rm",
                "root",
                "setprop",
                "start",
                "toolbox",
                "tune2fs"]

class Dataset():

    def __init__(self, name=None):
        self.name = name
        self.families = []

class Family():

    def __init__(self, name=None):
        self.name = name
        self.apks = []


class APK():

    def __init__(self, samplehash=None):
        self.___version = 0
        self.hash = samplehash
        self.methods = []  # Not repeated
        self.num_original_methods = 0
        self.num_incognito_methods = 0
        self.num_libraries = 0
        self.package_name = None
        self.version_code = None

class Method():

    def __init__(self, sig=None):
        self.signature = sig
        self.class_name = ''
        self.name = ''
        self.const_string_intent = [] 
        self.object_intents = []
        #self.APIs = set()
        self.sensitive_APIs = []
        self.tags = []
        self.incognito = False
        self.reflection = False
        self.native = False

    def __hash__(self):
        return hash(self.signature) + hash(tuple(self.tags)) + hash(tuple(self.sensitive_APIs))
        #return listcat([hash(self.signature), hash(tuple(self.tags)), hash(tuple(self.sensitive_APIs))])
        #return long("{0}{1}{2}".format(str(hash(self.signature)), str(hash(tuple(self.tags))), str(hash(tuple(self.sensitive_APIs)))))


class Resource():

    def __init__(self, filename=None, name=None, extension=None, md5=None, crc=None, content=None):
        self.filename = filename
        self.name = name
        self.extension = extension
        self.md5 = md5
        self.crc = crc
        self.content = content


def numcat(x, y):
    a = math.floor(math.log10(y))
    return int(x*10**(1+a)+y)

def listcat(l):
    prev = 0 
    for num in l:
        prev = numcat(prev, num)
    return prev


def get_dalvik_analysis(filename, raw=False) :

    app = apk.APK(filename, raw)        

    # parses classes.dex file of an Android application (APK).
    d = dvm.DalvikVMFormat( app.get_dex() )

    # analyze a dex
    dvmx = analysis.VMAnalysis( d )

    # control flow graph
    gvmx = ganalysis.GVMAnalysis( dvmx, None )

    # setup references
    d.set_vmanalysis( dvmx )
    d.set_gvmanalysis( gvmx )

    # create xref/dref
    d.create_xref()
    d.create_dref()

    return app, d, dvmx, gvmx



def get_dalvik_analysis_dex(dexfile) :

    # parses classes.dex file of an Android application (APK).
    d = dvm.DalvikVMFormat( dexfile )

    # analyze a dex
    dvmx = analysis.VMAnalysis( d )

    # control flow graph
    gvmx = ganalysis.GVMAnalysis( dvmx, None )

    # setup references
    d.set_vmanalysis( dvmx )
    d.set_gvmanalysis( gvmx )

    # create xref/dref
    d.create_xref()
    d.create_dref()

    return d, dvmx, gvmx


def get_apk_signature_batch(_dvm, _dvmx, hash_md5, incognito = False): 

    seen_apps =  {}

    apk = APK(hash_md5)

    for i in _dvmx.get_methods():
        m = i.get_method()
        s = _dvmx.get_method_signature(m, predef_sign = analysis.SIGNATURE_L0_0)
        if s:
            method = Method(m)
            method.incognito = incognito
            method.signature = s.get_string()

            i.create_tags()
            if not i.tags.empty():
                method.tags = i.tags.get_list()

            if m.get_access_flags() & 0x100:
                # https://github.com/androguard/androguard/blob/master/androguard/decompiler/dad/util.py
                method.native = True
                #print i.get_class_name(), i.get_name(), i.get_descriptor()

            code = m.get_code()
            if code is not None:
                method.class_name = m.get_class_name()
                method.name = m.get_name()

                instructions = code.get_bc().get_instructions()
                for i in instructions:
                    try:
                        tkind = i.get_translated_kind()
                        var = str(m.get_class_name()) + " => " + str(m.get_name()) + " => " + str(i.get_name()) + " => " + str(tkind)
                        #print '---------', var
                        if 'object' in i.get_name() and 'intent' in tkind:
                            method.object_intents.append(i.get_name())
                        if  'const-string' in i.get_name() and '.intent.' in tkind:
                            method.const_string_intent.append(i.get_name())

                        if tkind.startswith('Ljava/lang/reflect'):
                            method.reflection = True

                        #method.APIs.add(tkind) 

                        for sapi in sensitive_API:
                            sapi_split = sapi.split(':')
                            pckg = sapi_split[0]
                            mthd = sapi_split[1]
                            if pckg in tkind and mthd in tkind:
                                method.sensitive_APIs.append(sapi)

                    except AttributeError:
                        pass

            # Discard repeated methods
            current_method_hash = hash(method)
            if not current_method_hash in seen_apps:
                seen_apps[current_method_hash] = 0
                apk.methods.append(method)  
            seen_apps[current_method_hash] += 1
            
        else: 
            print "No signature for method", m
        
    return apk


def get_resources(app, filterout=True):

    resources = {}

    files=app.get_files_types()
    files_crc=app.get_files_crc32()
    for f in files:
        # ------ File extension #
        fileName, fileExtension = os.path.splitext(f)
        crc = files_crc[f]
        content = app.get_file(f)
        m = md5.new()
        m.update(content)
        hash_md5 = m.hexdigest()

        if filterout:

            import magic
            try:
                ms = magic.Magic()
                ftype = magic.from_buffer(content)
                #ftype = magic.from_file(path_file)
            except TypeError:
                ms = magic.open(magic.MAGIC_NONE)
                ms.load()
                ftype = ms.buffer(content)
                #ftype = magic.from_file(path_file)

            if not (("text" in ftype and "executable" in ftype) or ("ELF" in ftype and "executable" in ftype)): 
               continue

        resource = Resource(filename=f, name=fileName, extension=fileExtension, md5=hash_md5, crc=crc, content=content)

        if hash_md5 not in resources:
            resources[resource.md5] = resource

    return resources


def get_incognito(app):

    incognito_apk = []
    incognito_dex = []
    incognito_sh = []
    incognito_elf = []

    coi_modules = {'APKFileMatch', 'DEXFileMatch', 'TextScriptMatch', 'ELFExecutableMatch'} #"AdvancedCodeFound", 'ELFExecutableMatch', 'DEXFileMatch', 'APKFileMatch', "EncryptedOrCompressedMatch"
    data = {}
    file_type_key = {"Text Executable":["text", "executable"], "ELF Executable":["ELF", "executable"], "font":["font"], "APK":["Android", "application", "package", "file"], "DEX":["Dalvik", "dex",  "file"]}
    types={}
    extensions={}
    components_of_interest=[]
    num_componenets_of_interest = {}

    # COMPONENTS: assets and resources components
    files=app.get_files_types()
    for f in files:
        # ------ File extension #
        fileName, fileExtension = os.path.splitext(f)
        try:
            extensions[fileExtension] = extensions[fileExtension] + 1
        except KeyError:
            extensions[fileExtension] = 1
        
        # ------ Magic number extension 
        try:
            #print files[f]
            file_type = None
            for key in file_type_key:
                match = 0
                for token in file_type_key[key]:
                    if token in files[f]:
                        match = match + 1
                if len(file_type_key[key]) is match:
                    file_type = key
            if file_type == None:
                file_type = files[f].split(" ")[0]
            types[file_type] = types[file_type] + 1
        except KeyError:
            types[file_type] = 1

        # ------ Components of interest 
        crc = app.get_files_crc32()[f]
        for sub_class_name in FileCoI.FileCoI.__subclasses__():
            coi_type = sub_class_name.__name__
            if coi_type in coi_modules:
                sub_class = sub_class_name(app, fileName, fileExtension, file_type, files[f], f, crc)
                if sub_class.check():
                    components_of_interest.append(sub_class)
                    try:
                        count = num_componenets_of_interest[coi_type] + 1
                    except KeyError: 
                        count = 1
                    num_componenets_of_interest[coi_type] = count

        if file_type == 'APK':
            incognito_apk.append(f)

        if file_type == 'DEX' and 'classes' != fileName:
            incognito_dex.append(f)

        if file_type == 'ELF':
            incognito_elf.append(f)

        if file_type == "Text Executable":
            incognito_sh.append(f)


    #text_executable_commands = {}
    #if incognito_sh:
    #    regexp = '|'.join(sh_commands)
    #    pattern = re.compile(regexp)
    #    for file_path in incognito_sh:
    #        content = app.get_file(file_path)
    #        matches = pattern.findall(content)
    #        for match in matches:
    #            try:
    #                count = text_executable_commands[match]
    #            except KeyError:
    #                count = 0
    #            text_executable_commands[match] = count + 1
    #if text_executable_commands:
    #    data['text_executable_commands'] = text_executable_commands

    if types:
        data['file'] = types

    if num_componenets_of_interest:
        data['CoIs'] = num_componenets_of_interest

    # TODO: KNOWN SECTIONS: http://link.springer.com/article/10.1007/s10115-011-0393-5#/page-1

    #for file_path in incognito_elf:
    #    content = app.get_file(file_path)
    #    parse_elf(content, data)

    return incognito_apk, incognito_dex, incognito_sh, incognito_elf


'''
  # feature | description | example
  ---------------------------------
  ========== File Header ==========
  data['e_ehsize']:      Size of this header:               52 (bytes)
  data['e_phentsize']:   Size of program headers:           32 (bytes)
  data['e_phnum']:       Number of program headers:         5
  data['e_shentsize']:   Size of section headers:           40 (bytes)
  data['e_shnum']:       Number of section headers:         21
  data['e_shstrndx']:    Section header string table index: 18
  ==========  Sections ==========
  section['sh_flags']:     Flags of a given section:
      W (write), A (alloc), X (execute), M (merge), S (strings)
      I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
      O (extra OS processing required) o (OS specific), p (processor specific)
  ==========  Shared Libraries ==========
  data['symbols_shared_libraries']: Relocation information for PLT (Position Independent Code): ioctl, fork, etc.
'''
def parse_elf(content, data):

    import StringIO
    steam_content = StringIO.StringIO()
    steam_content.write(content)
    try: 
        readelf = ReadElf(steam_content, sys.stdout) #stream
    except Exception, e:
        print 'WARNING: cannot read elf', str(e), app.get_filename(), file_path
        readelf = None

    if readelf: 
        data['e_ehsize'] = readelf.elffile.header['e_ehsize']
        data['e_phentsize'] = readelf.elffile.header['e_phentsize']
        data['e_phnum'] = readelf.elffile.header['e_phnum']
        data['e_shentsize'] = readelf.elffile.header['e_shentsize']
        data['e_shnum'] = readelf.elffile.header['e_shnum']
        data['e_shstrndx'] = readelf.elffile.header['e_shstrndx']

        symbols_shared_libraries = [] # Relocation information for PLT (Position Independent Code)
        sections_flags = {}   
        try:     
            for nsec, section in enumerate(readelf.elffile.iter_sections()):
                
                # ---------- Relocation information for PLT (Position Independent Code) ----------
                if isinstance(section, RelocationSection):

                    try:

                        # The symbol table section pointed to in sh_link
                        symtable = readelf.elffile.get_section(section['sh_link'])
                        for rel in section.iter_relocations():
                            if rel['r_info_sym'] == 0:
                                continue

                            symbol = symtable.get_symbol(rel['r_info_sym'])
                            # Some symbols have zero 'st_name', so instead what's used is
                            # the name of the section they point at
                            if symbol['st_name'] == 0:
                                symsec = readelf.elffile.get_section(symbol['st_shndx'])
                                symbol_name = symsec.name
                            else:
                                symbol_name = symbol.name

                            #if symbol_name in elf_symbols_white_list:
                            symbols_shared_libraries.append(symbol_name)

                    except ELFParseError, e:
                        if data and 'package' in data:
                            print 'Warning ELFParseError for', data['package']
                        else:
                            print 'Warning ELFParseError', str(e)
                            exc_type, exc_value, exc_traceback = sys.exc_info()
                            traceback.print_tb(exc_traceback)


                # ---------- Flags from the section ----------   

                flag = describe_sh_flags(section['sh_flags'])
                if not flag:
                    continue
                try:
                    count = sections_flags[flag]
                except KeyError:
                    count = 0
                sections_flags[flag] = count + 1

            if sections_flags:
                data['e_sh_flags'] = sections_flags

            if symbols_shared_libraries:
                data['symbols_shared_libraries'] = symbols_shared_libraries   

        except Exception, e:
            print 'Warning ELFParseError', str(e)


def storeResources(family_folder, resources):
    family_folder = os.path.join(settings.resources_results, family_name)

    if not os.path.exists(family_folder) and len(resources) > 0: 
        os.mkdir(family_folder)  

    for resource in resources:
        filename = resource.md5 + '-' + resource.filename.replace('/', '.') ## FIXME, only keep one file
        filepath = os.path.join(family_folder, filename)
        with open (filepath, 'w') as outfile:
            outfile.write(resource.content)
        outfile.close()
        resource.content = None


def resources_one_file(file_name, family_name):

    print "- Processing: %s at %s ..." % (family_name, file_name)


    resources = None
    if androconf.is_android( file_name ) == "APK" :

        try:
            _apk, _dvm, _dvmx, _gvmx = get_dalvik_analysis(file_name)
            resources = get_resources(_apk)
            storeResources(family_name, resources)

        except Exception as details:
            print " *** Error analyzing the apk: ", details
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback)

    return resources



def preprocess_one_file_batch(file_name, family_name):

    apk = None
    endtime = None

    print "- Processing: %s at %s ..." % (family_name, file_name)
    start = default_timer()

    if androconf.is_android( file_name ) == "APK" :

        try:
            # Main APK
            hash_md5 = hashlib.md5(open(file_name, 'rb').read()).hexdigest()
            _apk, _dvm, _dvmx, _gvmx = get_dalvik_analysis(file_name)
            apk = get_apk_signature_batch(_dvm, _dvmx, hash_md5)

            apk.num_libraries = len(_apk.get_libraries()) # This was inverted
            apk.package_name = _apk.get_package() # This was inverted
            apk.version_code = _apk.get_androidversion_code()

            if INCOGNITO_EXPERIMENT: 

                # Incognito APKs
                incognito_apk, incognito_dex, incognito_sh, incognito_elf = get_incognito(_apk)

                print '\t Incognito:', incognito_apk, incognito_dex, incognito_sh, incognito_elf

                for file_path in incognito_apk:
                    content = _apk.get_file(file_path)
                    _apk2, _dvm2, _dvmx2, _gvmx2 = get_dalvik_analysis(content, True)
                    apk_incognito = get_apk_signature_batch(_dvm2, _dvmx2, hash_md5, True)
                    apk.num_original_methods = len(apk.methods)
                    apk.num_incognito_methods = len(apk_incognito.methods)
                    print '>>>>>>', len(apk.methods)
                    apk.methods.extend(apk_incognito.methods)
                    print '>>>>>>', len(apk.methods)

                for file_path in incognito_dex:
                    content = _apk.get_file(file_path)
                    _dvm2, _dvmx2, _gvmx2 = get_dalvik_analysis_dex(content)
                    apk_incognito = get_apk_signature_batch(_dvm2, _dvmx2, hash_md5, True)
                    apk.num_original_methods = len(apk.methods)
                    apk.num_incognito_methods = len(apk_incognito.methods)
                    print '>>>>>>', len(apk.methods)
                    apk.methods.extend(apk_incognito.methods)
                    print '>>>>>>', len(apk.methods)

            # Measure time here
            endtime = default_timer() - start

            if not os.path.exists(settings.intermediate_results):
                raise Exception('Error: intermediate_results doesnt exist', settings.intermediate_results)

            # Storing intermediate results
            family_folder = os.path.join(settings.intermediate_results, family_name)
            if not os.path.exists(family_folder): 
                os.mkdir(family_folder)

            basefilename = os.path.basename(file_name)
            result_file = os.path.join(family_folder, basefilename + '.pickle')

            print 'Dumping intermediate results at', result_file

            with open(result_file, "wb") as f:
                pickle.dump(apk, f) #, -1)
            f.close()

        except Exception as details:
            print " *** Error analyzing the apk: ", details
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback)

    return endtime


def preprocess_selectedfamilies(directory, families):

    families_filtered = []

    TASKS_PARAMS = []

    for family_name in os.listdir(directory): 
        if family_name not in families:
            continue
        src_family_path = os.path.join(directory, family_name)
        dst_family_path = os.path.join(settings.intermediate_results, family_name)

        for apk in os.listdir(src_family_path):
            task_path = os.path.join(src_family_path, apk)
            result_path = os.path.join(dst_family_path, apk) + '.pickle'
            if os.path.isfile(result_path):
                continue

            TASKS_PARAMS.append([task_path, family_name])
             
    # ---- Pool all tasks
    print 'Creating pool with %d processes' % settings.n_procs    
    pool = multiprocessing.Pool(settings.n_procs) #, maxtasksperchild=100                

    # ---- Run all tasks
    start = default_timer()
    try:
        results = [pool.apply_async(preprocess_one_file_batch, [real_filename, family_name]) for real_filename, family_name in TASKS_PARAMS]
    finally:
        pool.close()
        pool.join()

    # ---- Get terminated  
    overall_overhead = default_timer() - start
    print "Extraction: %.2f seconds" % (overall_overhead)

    overhead = []
    # ---- Process all results
    for result in results:
        result = result.get()
        if result:
            overhead.append(result)

        else:
            print 'ERROR processing result', result

    print "PreprocessingTime = ",  overhead
    print "MeanPreprocessingTime", np.mean(overhead)



def preprocess_directory(directory):

    families_filtered = []

    size_family = {}

    TASKS = {}

    TASKS_PARAMS = []
    for root, dirs, files in os.walk(directory, followlinks=True):
        if files != [] :
            apps_family = []
            for fileName in files :
                real_filename = root
                if real_filename[-1] != "/" :
                    real_filename += "/"
                real_filename += fileName

                if os.path.isdir(real_filename):
                    continue

                family_name = os.path.basename(os.path.dirname(real_filename))

                #if family_name in blacklist_families:
                #    continue

                if family_name not in families_filtered:

                    # Filter out samples with intermediate results
                    family_folder_for_intermediate_results = os.path.join(settings.intermediate_results, family_name)
                    filterout = []
                    if os.path.exists(family_folder_for_intermediate_results):
                        filterout = [f.replace('.pickle', '') for f in os.listdir(family_folder_for_intermediate_results) if os.path.isfile(os.path.join(family_folder_for_intermediate_results, f))]
                    families_filtered.append(family_name)

                if not fileName in filterout:
                    if not (hash(fileName) % settings.distributed_jobs == settings.distributed_machine):
                        continue
                    
                    #TASKS_PARAMS.append([real_filename, family_name])
                    if family_name not in TASKS:
                        TASKS[family_name] = []
                    TASKS[family_name].append(real_filename)

                    if family_name not in size_family:
                        size_family[family_name] = 0
                    size_family[family_name] += 1
    
    # Sorting TASKs by family size
    #random.shuffle(TASKS_PARAMS)
    for item in sorted(size_family.items(), key=lambda samples:samples[1]):
        family_name = item[0]
        cSize = item[1]
        for real_filename in TASKS[family_name]:
            TASKS_PARAMS.append([real_filename, family_name])

    print TASKS_PARAMS

    # ---- Pool all tasks
    print 'Creating pool with %d processes' % settings.n_procs    
    pool = multiprocessing.Pool(settings.n_procs) #, maxtasksperchild=100                

    # ---- Run all tasks
    start = default_timer()
    try:
        results = [pool.apply_async(preprocess_one_file_batch, [real_filename, family_name]) for real_filename, family_name in TASKS_PARAMS]
    finally:
        pool.close()
        pool.join()

    # ---- Get terminated  
    overall_overhead = default_timer() - start
    print "Extraction: %.2f seconds" % (overall_overhead)

    overhead = []
    # ---- Process all results
    for result in results:
        result = result.get()
        if result:
            overhead.append(result)

        else:
            print 'ERROR processing result', result

    print "PreprocessingTime = ",  overhead
    print "MeanPreprocessingTime", np.mean(overhead)




def compare_methods(method1, method2):

    # Signature similarity 
    similarity_degree = 0
    if len(method1.signature) > 0 and method1.signature == method2.signature:
        similarity_degree += 100

        # Use of reflection is considered suspicious (potentially similar)
        if method1.reflection or method2.reflection: 
            similarity_degree += 1000


    # Sensitive_API similarity --- order should matter...
    if len(method1.sensitive_APIs) == len(method2.sensitive_APIs) > 0:
        api_similarity = True
        for api in method1.sensitive_APIs: 
            if not api in method2.sensitive_APIs:
                api_similarity = False
                break
        if api_similarity:
            similarity_degree += 10        

    # Tag similarity --- order should matter...
    if len(method1.tags) == len(method2.tags) > 0:
        tag_similarity = True
        for tag in method1.tags: 
            if not tag in method2.tags:
                tag_similarity = False
                break
        if tag_similarity:
            similarity_degree += 1

    return similarity_degree



def test_inter_app_similarity(path_to_file, family_name):

    try: 

        if DEBUG: print "- Postprocessing: {0} at {1} ...".format(family_name, path_to_file)

        start = default_timer()

        apk = None
        with open(path_to_file, "rb") as f:
            apk = pickle.load(f)
        f.close()

        for i in range(len(apk.methods)): 
            for j in range(len(apk.methods)): 
                if i < j: # We don't want to compare unncessarily 
                    method1 = apk.methods[i]
                    method2 = apk.methods[j]

                    method_similarity_degree = compare_methods(method1, method2)

                    if method_similarity_degree > 0:
                        print method_similarity_degree, '\t', method1.class_name, method1.name, '\t', method2.class_name, method2.name                 


        return default_timer() - start

    except Exception as details:
        print " *** Error analyzing the pickle: ", path_to_file
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_tb(exc_traceback)
        return None




def postprocess_one_apk(path_to_file, family_name, methods, seen_apps):

    seen_hashes_in_this_app = []
    try: 
        if DEBUG: print "- Postprocessing: {0} at {1} ...".format(family_name, path_to_file)

        tryit = True
        tryit_count = 0
        while tryit:
            try:
                apk = None
                with open(path_to_file, "rb") as f:
                    apk = pickle.load(f)
                f.close()
                tryit = False
            except IOError:
                # This is due to the fucking NAS failing
                if tryit_count % 60 == 0:
                    print 'Warning IOError retrying', path_to_file
                tryit_count += 1
                time.sleep(60)

        for method in apk.methods:
            current_method_hash = hash(method)
            if current_method_hash in seen_hashes_in_this_app:
                # With this we limit the search and we only acount for the number of apps in which a method (hash) has been seen
                # rather than the number of times a method (hash) has been seen overall.
                # Basically this avoids counting when a method is seen several times in the same app 
                break 
            seen_hashes_in_this_app.append(current_method_hash)
            if not current_method_hash in seen_apps:
                seen_apps[current_method_hash] = 0
                methods[current_method_hash] = method
            seen_apps[current_method_hash] += 1
        return False

    except Exception as details:
        print " *** Error analyzing the pickle: ", path_to_file
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_tb(exc_traceback)
        return True



def postprocess_one_apk_keeptrack(path_to_file, family_name, methods, seen_apps):

    seen_hashes_in_this_app = []
    try: 
        if DEBUG: print "- Postprocessing: {0} at {1} ...".format(family_name, path_to_file)

        tryit = True
        tryit_count = 0
        while tryit:
            try:
                apk = None
                with open(path_to_file, "rb") as f:
                    apk = pickle.load(f)
                f.close()
                tryit = False
            except IOError:
                # This is due to the fucking NAS failing
                if tryit_count % 60 == 0:
                    print 'Warning IOError retrying', path_to_file
                tryit_count += 1
                time.sleep(60)

        for method in apk.methods:
            current_method_hash = hash(method)
            if current_method_hash in seen_hashes_in_this_app:
                # With this we limit the search and we only acount for the number of apps in which a method (hash) has been seen
                # rather than the number of times a method (hash) has been seen overall.
                # Basically this avoids counting when a method is seen several times in the same app 
                break 
            seen_hashes_in_this_app.append(current_method_hash)
            if not current_method_hash in seen_apps:
                seen_apps[current_method_hash] = []
                methods[current_method_hash] = method
            seen_apps[current_method_hash].append(apk.hash)
        return False

    except Exception as details:
        print " *** Error analyzing the pickle: ", path_to_file
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_tb(exc_traceback)
        return True



def postprocess_setsamples(list_path_samples, category):

    methods = {}
    seen_apps =  {}

    num_samples = 0
    numApps_seen_method = []
    numApps_seen_method_with_sensitiveAPIs = []
    common_hashes_with_sensitiveAPIs = [] 

    numApps_seen_method_with_sensitiveTAGs = []
    common_hashes_with_sensitiveTAGs = [] 

    s = category.split('-')
    family  = s[0]
    quarter = s[1]

    for path_to_file in list_path_samples: 
        if path_to_file.endswith('.pickle'):  
            print 'postprocess_setsamples:', path_to_file  
            error = postprocess_one_apk(path_to_file, category, methods, seen_apps)
            if error:
                print 'Warning error processing', path_to_file
        else:
            print 'Warning file does not exist', path_to_file

    num_common_methods = 0
    for current_method_hash in seen_apps:

        if seen_apps[current_method_hash] <= 1:
            continue

        numApps_seen_method.append(seen_apps[current_method_hash])

        method = methods[current_method_hash]

        if len(method.sensitive_APIs) != 0:
            numApps_seen_method_with_sensitiveAPIs.append(seen_apps[current_method_hash])
            common_hashes_with_sensitiveAPIs.append(current_method_hash)

        if len(method.tags) != 0:
            numApps_seen_method_with_sensitiveTAGs.append(seen_apps[current_method_hash])
            common_hashes_with_sensitiveTAGs.append(current_method_hash)


    stats = {}
    for cRATIO in [90, 50, 30]:

        stats[cRATIO] = {'family': family, 'incognito': False, 'reflection': False, 'native': False, 'methods': 0}

        # List methods shared by RATIO % of the samples
        cutoff = cRATIO * num_samples / 100

        #print "Listing CCC for methods seen in {0}/{1} ({2}%) apps".format(cutoff, num_samples, cRATIO) 

        sensitive_APIs = []
        sensitive_TAGSs = []
        for current_method_hash in seen_apps:
            if seen_apps[current_method_hash] < cutoff: # We don't want to compare unpopular methods 
                continue
            method = methods[current_method_hash]

            stats[cRATIO]['methods'] += 1

            if method.incognito:
                stats[cRATIO]['incognito'] = True
            if method.reflection:
                stats[cRATIO]['reflection'] = True
            if method.native:
                stats[cRATIO]['native'] = True

            sensitive_APIs.extend(method.sensitive_APIs)
            sensitive_TAGSs.extend(method.tags)

        stats[cRATIO]['sensitive_APIs'] = set(sensitive_APIs)
        stats[cRATIO]['sensitive_TAGs'] = set(sensitive_TAGSs)

    print 'Done', category

    return stats, quarter


def postprocess_family_no_index_keeptrack(path_to_folder): 

    index = os.path.abspath(path_to_folder) + '.pickle'

    methods = {}
    seen_apps =  {}

    num_samples = 0
    numApps_seen_method = []

    numApps_seen_method_with_sensitiveAPIs = []
    common_hashes_with_sensitiveAPIs = [] 

    numApps_seen_method_with_sensitiveTAGs = []
    common_hashes_with_sensitiveTAGs = [] 
 
    family_name = os.path.basename(path_to_folder)

    if 'goodware-play.google.com' in family_name:
        return None, None

    files = os.listdir(path_to_folder)
    for f in files:
        num_samples += 1
        path_to_file = os.path.join(path_to_folder, f)
        if path_to_file.endswith('.pickle'):
            print 'postprocess_setsamples:', path_to_file  
            error = postprocess_one_apk_keeptrack(path_to_file, family_name, methods, seen_apps)
            if error:
                print 'Warning error processing', path_to_file
        else:
            print 'Warning file does not exist', path_to_file


    num_common_methods = 0
    for current_method_hash in seen_apps:

        if len(seen_apps[current_method_hash]) <= 1:
            continue

        numApps_seen_method.append(len(seen_apps[current_method_hash]))

        method = methods[current_method_hash]

        if len(method.sensitive_APIs) != 0: 
            numApps_seen_method_with_sensitiveAPIs.append(len(seen_apps[current_method_hash]))
            common_hashes_with_sensitiveAPIs.append(current_method_hash)

        if len(method.tags) != 0:
            numApps_seen_method_with_sensitiveTAGs.append(len(seen_apps[current_method_hash]))
            common_hashes_with_sensitiveTAGs.append(current_method_hash)


    stats = {}
    for cRATIO in [100, 90, 50, 30]:

        stats[cRATIO] = {'num_samples': num_samples, 'family': family_name, 'incognito': False, 'reflection': False, 'native': False, 'methods': 0, 'samples': {'incognito': [], 'native': [], 'reflection': []}, 'samples_tags':{}}

        # List methods shared by RATIO % of the samples
        cutoff = cRATIO * num_samples / 100

        #print "Listing CCC for methods seen in {0}/{1} ({2}%) apps".format(cutoff, num_samples, cRATIO) 

        sensitive_APIs = []
        tags = []
        for current_method_hash in seen_apps:
            if len(seen_apps[current_method_hash]) < cutoff: # We don't want to compare unpopular methods 
                continue
            method = methods[current_method_hash]

            stats[cRATIO]['methods'] += 1

            #I keep track of all the apps in a family that exhibit a certain feature (e.g.: incognito, sAPI, etc.)
            if method.incognito:
                stats[cRATIO]['incognito'] = True
                stats[cRATIO]['samples']['incognito'].extend(seen_apps[current_method_hash])
            if method.reflection:
                stats[cRATIO]['reflection'] = True
                stats[cRATIO]['samples']['reflection'].extend(seen_apps[current_method_hash])
            if method.native:
                stats[cRATIO]['native'] = True
                stats[cRATIO]['samples']['native'].extend(seen_apps[current_method_hash])

            for sAPI in method.sensitive_APIs:
                if sAPI not in stats[cRATIO]['samples']:
                    stats[cRATIO]['samples'][sAPI] = []
                stats[cRATIO]['samples'][sAPI].extend(seen_apps[current_method_hash])

            for tag in method.tags:
                if tag not in stats[cRATIO]['samples_tags']:
                    stats[cRATIO]['samples_tags'][tag] = []
                stats[cRATIO]['samples_tags'][tag].extend(seen_apps[current_method_hash])

            sensitive_APIs.extend(method.sensitive_APIs)
            tags.extend(method.tags)

        stats[cRATIO]['sensitive_APIs'] = set(sensitive_APIs)
        stats[cRATIO]['tags'] = set(tags)

    return stats, family_name




def resources_family(path_to_folder):
    assert os.path.exists(settings.resources_results), 'settings.resources_results doesnt exist'

    try:
        resources_family = {}
        map_resource_samples = {}
        samples = []

        #Intemediate folder for resouces
        family_name = os.path.basename(path_to_folder)
        family_folder = os.path.join(settings.resources_results, family_name)

        if os.path.isfile(family_folder + '.pickle'):
            return

        if 'goodware-play.google.com' in family_name:
            return 

        print 'resources_family', family_name, path_to_folder

        TASKS = [] 

        #All apps in a family
        for f in os.listdir(path_to_folder):
            path_sample = os.path.join(path_to_folder, f)
            if os.path.isfile(path_sample):

                #Fetch resources for an app
                TASKS.append([path_sample, family_name])
                samples.append(f)
                #resources = resources_one_file(path_sample, family_name)

        num_samples = len(samples)

        # ---- Pool all tasks
        print 'Creating pool with %d processes' % settings.n_procs    
        pool = multiprocessing.Pool(settings.n_procs) #, maxtasksperchild=100    

        try:
            results = [pool.apply_async(resources_one_file, [path_sample, family_name]) for path_sample, family_name in TASKS]
        finally:
            pool.close()
            pool.join()

        # ---- Process all results
        for result in results:
            result = result.get()
            if result:
                resources = result

                for resource_hash in resources:
                    resource = resources[resource_hash]
                    if not resource:
                        continue
                    #Keep global track of the resources
                    if resource.md5 not in resources_family:
                        resources_family[resource.md5] = resource
                    #Build stats for all samples in the family
                    if resource.md5 not in map_resource_samples:
                        map_resource_samples[resource.md5] = []
                    map_resource_samples[resource.md5].append(f)
                resources = None # No needed anymore 

        print '\t Analyzing', num_samples, len(map_resource_samples)

        ##Minimum threshold used to filter out irrelevant resources
        #cRATIO = 30
        #cutoff = cRATIO * num_samples / 100
        #available_resources = False
        #for resource_hash in map_resource_samples:
        #    #Free memory up...
        #    if len(map_resource_samples[resource_hash]) < cutoff:
        #        #... by getting rid off unpopular resources 
        #        del resources_family[resource_hash]
        #    else:
        #        if not os.path.exists(family_folder) and not available_resources: 
        #            os.mkdir(family_folder)  
        #            available_resources = True          
        #        #... by dumping to disk popular resources 
        #        resource = resources_family[resource_hash]
        #        filename = resource.md5 + '-' + resource.filename.replace('/', '.') ## FIXME, only keep one file
        #        filepath = os.path.join(family_folder, filename)
        #        with open (filepath, 'w') as outfile:
        #            outfile.write(resource.content)
        #        outfile.close()
        #        resource.content = None
        #if not available_resources:
        #    return

        #Keep metafile for resources shared by RATIO % of the samples
        for cRATIO in [90, 50, 30]:
            cutoff = cRATIO * num_samples / 100
            metafile = family_folder + '.' + str(cRATIO) + '.txt'
            outfile = open (metafile, 'w')
            for resource_hash in resources_family:
                if len(map_resource_samples[resource_hash]) < cutoff: # We don't want to compare unpopular methods 
                    continue
                resource = resources_family[resource_hash]
                filename = resource.md5 + '-' + resource.filename.replace('/', '.')
                outfile.write(filename + '\n')
            outfile.close()

        #Keep resources
        filename = family_folder + '.pickle'
        with open(filename, "wb") as outfile:
            pickle.dump(num_samples, outfile) #, -1)
            pickle.dump(resources_family, outfile) #, -1)
            pickle.dump(map_resource_samples, outfile) #, -1)
            pickle.dump(samples, outfile) #, -1)
        outfile.close()

    except Exception, e:
        print "Error at ", path_to_folder, ":", str(e)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_tb(exc_traceback)

    return



'''
Get stats from resources
'''
def load_resources_family(family_resources, ratio):

    try:

        metapath = family_resources + '.pickle'

        map_texec_name = {}
        map_texec_path = {}
        map_texec_bash = {}

        map_elf_name = {}
        map_elf_path = {}
        map_elf_libs = {}

        with open(metapath) as infile:

            family_name = os.path.basename(family_resources)

            num_samples = pickle.load(infile)
            resources_family = pickle.load(infile)
            map_resource_samples = pickle.load(infile)
            samples = pickle.load(infile)

            if not os.path.isfile(metapath):
                print 'WARNING: pickle not found', family_resources
                return

            infile = open(metapath)
            num_samples = pickle.load(infile)
            resources_family = pickle.load(infile)
            map_resource_samples = pickle.load(infile)
            samples = pickle.load(infile)

            regexp = '|'.join(sh_commands)
            pattern = re.compile(regexp)

            if num_samples < 7:
                print 'SKIPPING: families with few samples', family_resources
                return

            for resource_hash in map_resource_samples:
                cutoff = ratio * num_samples / 100
                if len(map_resource_samples[resource_hash]) < cutoff: # We don't want to compare unpopular resources
                    continue 
                resource = resources_family[resource_hash]
                filename = resource.md5 + '-' + resource.filename.replace('/', '.') #See FIXME

                path_file = os.path.join(family_resources, filename)

                import magic
                fbuffer = open(path_file).read()
                try:
                    ms = magic.Magic()
                    ftype = magic.from_buffer(fbuffer)
                    #ftype = magic.from_file(path_file)
                except TypeError:
                    ms = magic.open(magic.MAGIC_NONE)
                    ms.load()
                    ftype = ms.buffer(fbuffer)
                    #ftype = magic.from_file(path_file)

                name = os.path.basename(resource.filename)

                # We print text executables 
                if "text" in ftype and "executable" in ftype: 

                    if not family_name in map_texec_name:
                        map_texec_name[family_name] = []
                    map_texec_name[family_name].append(name)

                    if not family_name in map_texec_path:
                        map_texec_path[family_name] = []
                    map_texec_path[family_name].append(filename)

                    if not family_name in map_texec_bash:
                        map_texec_bash[family_name] = {}

                    matches = pattern.findall(fbuffer)
                    for match in matches:
                        try:
                            count = map_texec_bash[family_name][match]
                        except KeyError:
                            count = 0
                        map_texec_bash[family_name][match] = count + 1


                if "ELF" in ftype and "executable" in ftype: 

                    if not family_name in map_elf_name:
                        map_elf_name[family_name] = []
                    map_elf_name[family_name].append(name)

                    if not family_name in map_elf_path:
                        map_elf_path[family_name] = []
                    map_elf_path[family_name].append(filename)

                    if not family_name in map_elf_libs:
                        map_elf_libs[family_name] = {}

                    data = {}
                    parse_elf(fbuffer, data)
                    if 'symbols_shared_libraries' in data:
                        for match in data['symbols_shared_libraries']:
                            try:
                                count = map_elf_libs[family_name][match]
                            except KeyError:
                                count = 0
                            map_elf_libs[family_name][match] = count + 1


        print "######################"
        print "##\t", family_name,"\t##"
        print "######################"

        if family_name in map_texec_bash:
            print map_texec_bash[family_name]
        if family_name in map_elf_libs:
            print map_elf_libs[family_name]

        return family_name, map_texec_name, map_texec_path, map_texec_bash, map_elf_name, map_elf_path, map_elf_libs

    except Exception, e:
        print "Error at ", family_resources, ":", str(e)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_tb(exc_traceback)
        return


def postprocess_family(path_to_folder, verbose=False, keeptrack=True):

    start = default_timer() 

    track_keyword = ''
    if keeptrack:
        track_keyword = '_withsamples'

    index = os.path.abspath(path_to_folder) + track_keyword + '.pickle'
    methods, seen_apps, num_samples, common_hashes_with_sensitiveAPIs, numApps_seen_method, numApps_seen_method_with_sensitiveAPIs, numApps_seen_method_with_sensitiveTAGs, common_hashes_with_sensitiveTAGs = load_index_if_available(index)
    index_available = num_samples > 0
    common_available = common_hashes_with_sensitiveAPIs != None 
    numApps_available = numApps_seen_method != None  and numApps_seen_method_with_sensitiveAPIs != None

    family_name = os.path.basename(path_to_folder)

    if 'goodware-play.google.com' in family_name:
        print 'Warning Skipping', family_name
        return default_timer() - start

    if not index_available:
        files = os.listdir(path_to_folder)
        for f in files:
            num_samples += 1
            path_to_file = os.path.join(path_to_folder, f)
            if path_to_file.endswith('.pickle'):
                if keeptrack:
                    error = postprocess_one_apk_keeptrack(path_to_file, family_name, methods, seen_apps)
                else:
                    error = postprocess_one_apk(path_to_file, family_name, methods, seen_apps)
                if not error:
                    if num_samples % 500 == 0:
                        make_index_available(index, methods, seen_apps, num_samples)
                        print 'Done {}/{} for {}'.format(num_samples, len(files), family_name)

    if not index_available or not common_available or not numApps_available: 
        if not keeptrack:
            num_common_methods = 0
            for current_method_hash in seen_apps:
                if seen_apps[current_method_hash] <= 1:
                    continue
                numApps_seen_method.append(seen_apps[current_method_hash])
                method = methods[current_method_hash]
                if len(method.sensitive_APIs) != 0:
                    numApps_seen_method_with_sensitiveAPIs.append(seen_apps[current_method_hash])
                    common_hashes_with_sensitiveAPIs.append(current_method_hash)
                if len(method.tags) != 0:
                    numApps_seen_method_with_sensitiveTAGs.append(seen_apps[current_method_hash])
                    common_hashes_with_sensitiveTAGs.append(current_method_hash)

        else: 

            num_common_methods = 0
            for current_method_hash in seen_apps:
                if len(seen_apps[current_method_hash]) <= 1:
                    continue
                numApps_seen_method.append(len(seen_apps[current_method_hash]))
                method = methods[current_method_hash]
                if len(method.sensitive_APIs) != 0: 
                    numApps_seen_method_with_sensitiveAPIs.append(len(seen_apps[current_method_hash]))
                    common_hashes_with_sensitiveAPIs.append(current_method_hash)
                if len(method.tags) != 0:
                    numApps_seen_method_with_sensitiveTAGs.append(len(seen_apps[current_method_hash]))
                    common_hashes_with_sensitiveTAGs.append(current_method_hash)
                
        make_index_available(index, methods, seen_apps, num_samples, common_hashes_with_sensitiveAPIs, numApps_seen_method, numApps_seen_method_with_sensitiveAPIs, numApps_seen_method_with_sensitiveTAGs, common_hashes_with_sensitiveTAGs)

    print 'postprocessed', family_name

    if verbose:

        print "######################"
        print "##\t", family_name,"\t##"
        print "######################"

        # List methods shared by RATIO % of the samples
        cutoff = RATIO * num_samples / 100
        seen_hashes_list = seen_apps.keys()

        print "Listing CCC for methods seen in {0}/{1} ({2}%) apps".format(cutoff, num_samples, RATIO) 

        num_common_methods = 0
        for current_method_hash in methods:
            #current_method_hash = hash(method)

            if keeptrack:
                mylen = len(seen_apps[current_method_hash])
            else:
                mylen = seen_apps[current_method_hash]

            if mylen < cutoff: # We don't want to compare unpopular methods 
                continue

            #if not 'crypto:' in methods[current_method_hash].sensitive_APIs:
            #    num_common_methods += 1
            #    continue

            method = methods[current_method_hash]
            print "\tMethod-{} ({}...):".format(str(num_common_methods), method.signature[:10])
            if len(method.sensitive_APIs) != 0 or len(method.tags) != 0 or method.incognito or method.reflection or method.native:
                print "\t\t Class Name:", method.class_name
                print "\t\t Method name:", method.name
                print "\t\t Tags:", str(method.tags)
                print "\t\t sAPIs:", str(method.sensitive_APIs)
                print "\t\t Obf (ing, ref, nat):", method.incognito, method.reflection, method.native
                print "\t\t Const String Intents:", str(method.const_string_intent)
                print "\t\t Object Intents:", str(method.object_intents)
                if not keeptrack:
                    print "\t\t Seen Hashes", seen_apps[current_method_hash]
                else:
                    print "\t\t Seen Hashes", len(seen_apps[current_method_hash])
            num_common_methods += 1

        print '\t === #CCC', num_common_methods, "(out of", len(methods), ")==="

    methods = seen_apps = num_samples = common_hashes_with_sensitiveAPIs = numApps_seen_method = numApps_seen_method_with_sensitiveAPIs = None

    return default_timer() - start



def load_index_if_available(index):
    methods = {}
    seen_apps =  {}
    num_samples = 0
    common_hashes_with_sensitiveAPIs = [] 
    numApps_seen_method = []
    numApps_seen_method_with_sensitiveAPIs = []
    numApps_seen_method_with_sensitiveTAGs = []
    common_hashes_with_sensitiveTAGs = []

    if os.path.isfile(index): 

        with open(index, "rb") as f:
            methods = pickle.load(f) 
            seen_apps = pickle.load(f) 
            num_samples = pickle.load(f) 
            common_hashes_with_sensitiveAPIs = pickle.load(f) 
            numApps_seen_method = pickle.load(f) 
            numApps_seen_method_with_sensitiveAPIs = pickle.load(f) 

            try:
                numApps_seen_method_with_sensitiveTAGs = pickle.load(f) 
                common_hashes_with_sensitiveTAGs = pickle.load(f) 
            except EOFError:
                print 'Warning - OLD pickle: numApps_seen_method_with_sensitiveTAGs, common_hashes_with_sensitiveTAGs not found'
                pass

            f.close()  

    return methods, seen_apps, num_samples, common_hashes_with_sensitiveAPIs, numApps_seen_method, numApps_seen_method_with_sensitiveAPIs, numApps_seen_method_with_sensitiveTAGs, common_hashes_with_sensitiveTAGs


def make_index_available(index, methods, seen_apps, num_samples, common_hashes_with_sensitiveAPIs = [], numApps_seen_method = [], numApps_seen_method_with_sensitiveAPIs = [], numApps_seen_method_with_sensitiveTAGs = [], common_hashes_with_sensitiveTAGs = []):

    with open(index, "wb") as f:
        pickle.dump(methods, f) 
        pickle.dump(seen_apps, f) 
        pickle.dump(num_samples, f) 
        pickle.dump(common_hashes_with_sensitiveAPIs, f) 
        pickle.dump(numApps_seen_method, f) 
        pickle.dump(numApps_seen_method_with_sensitiveAPIs, f) 
        pickle.dump(numApps_seen_method_with_sensitiveTAGs, f) 
        pickle.dump(common_hashes_with_sensitiveTAGs, f) 
        f.close()    


'''
 Returns those methods that appear in at least 'top_percent' of the apps. 
 By default it will return those methods that appear in at least 10% of the apps
'''
def get_top_methods(path_to_folder, top_percent=10, resume=None):

    #index = os.path.abspath(path_to_folder) + '.pickle'
    index = os.path.abspath(path_to_folder) + '_withsamples.pickle'
    methods, seen_apps, num_samples, common_hashes_with_sensitiveAPIs, numApps_seen_method, numApps_seen_method_with_sensitiveAPIs, numApps_seen_method_with_sensitiveTAGs, common_hashes_with_sensitiveTAGs = load_index_if_available(index)
    index_available = num_samples > 0

    family_name = os.path.basename(path_to_folder)

    if not index_available or resume:
        files = os.listdir(path_to_folder)
        for f in files:
            num_samples += 1
            if num_samples <= resume: # resume index
                continue
            path_to_file = os.path.join(path_to_folder, f)
            if path_to_file.endswith('.pickle'):
                error = postprocess_one_apk(path_to_file, family_name, methods, seen_apps)
                if not error:
                    if num_samples % 1000 == 0:
                        make_index_available(index, methods, seen_apps, num_samples)
                        print 'Done {}/{} for {}'.format(num_samples, len(files), family_name)

    print 'Computing top methods for {} in {}'.format(num_samples, family_name)
    hash_top_methods = [k for k, v in seen_apps.iteritems() if v >= num_samples*(top_percent)/100]

    top_methods = {}
    seen_hashes_top_methods = {}
    for current_method_hash in hash_top_methods:
        top_methods[current_method_hash] = methods[current_method_hash]
        seen_hashes_top_methods[current_method_hash] = seen_apps[current_method_hash]

    return top_methods, seen_hashes_top_methods


def get_stats_family_commonMethods(path_to_folder, lock = None):

    num_methods_common = None

    #index = os.path.abspath(path_to_folder) + '.pickle'
    index = os.path.abspath(path_to_folder) + '_withsamples.pickle'
    methods, seen_apps, num_samples, common_hashes_with_sensitiveAPIs, numApps_seen_method, numApps_seen_method_with_sensitiveAPIs, numApps_seen_method_with_sensitiveTAGs, common_hashes_with_sensitiveTAGs = load_index_if_available(index)
    index_available = num_samples > 0
    common_available = common_hashes_with_sensitiveAPIs != None 
    numApps_available = numApps_seen_method != None  and numApps_seen_method_with_sensitiveAPIs != None

    family_name = os.path.basename(path_to_folder)

    if 'goodware-play.google.com' in family_name:
        return None

    if num_samples >= MIN_NUM_SAMPLES: 

        #with open(stats_filename, 'w') as outfile:   
        #if lock: lock.acquire()
        #print '%// ------ Results for {} ({} samples) ------ '.format(family_name,  num_samples)
        #print family_name + '_numApps_seen_method =', str(sorted(numApps_seen_method, reverse=True)).replace(',', '') + ';'
        #print family_name + '_numApps_seen_method_with_sensitiveAPIs = ', str(sorted(numApps_seen_method_with_sensitiveAPIs, reverse=True)).replace(',', '') + ';'
        #print family_name + '_num_methods =', len(seen_apps)
        #print family_name + '_num_samples =', num_samples
        #print 
        #if lock: lock.release()

        num_methods_common = {90: 0, 50: 0, 30: 0, 100: 0}
        num_methods = len(numApps_seen_method)

        for cRATIO in num_methods_common:
            
            cutoff = num_samples*cRATIO/100.0
            counter = 0
            for e in numApps_seen_method:
                if e >= cutoff:
                    counter += 1
            num_methods_common[cRATIO] = float(counter)/num_methods*100.0

    return num_methods_common, num_samples




def get_stats_family_withLock(lock, path_to_folder):
    return get_stats_family(path_to_folder, lock)

def get_stats_family(path_to_folder, lock = None):

    #index = os.path.abspath(path_to_folder) + '.pickle'
    index = os.path.abspath(path_to_folder) + '_withsamples.pickle'
    methods, seen_apps, num_samples, common_hashes_with_sensitiveAPIs, numApps_seen_method, numApps_seen_method_with_sensitiveAPIs, numApps_seen_method_with_sensitiveTAGs, common_hashes_with_sensitiveTAGs = load_index_if_available(index)
    index_available = num_samples > 0
    common_available = common_hashes_with_sensitiveAPIs != None 
    numApps_available = numApps_seen_method != None  and numApps_seen_method_with_sensitiveAPIs != None

    family_name = os.path.basename(path_to_folder)

    if not index_available:
        files = os.listdir(path_to_folder)

        for f in files:
            num_samples += 1
            path_to_file = os.path.join(path_to_folder, f)
            if path_to_file.endswith('.pickle'):
                error = postprocess_one_apk(path_to_file, family_name, methods, seen_apps)
                if not error:
                    if num_samples % 1000 == 0:
                        make_index_available(index, methods, seen_apps, num_samples)
                        print 'Done {}/{} for {}'.format(num_samples, len(files), family_name)

    seen_hashes_list = seen_apps.keys()

    if not index_available or not common_available or not numApps_available: 

        num_common_methods = 0
        for current_method_hash in seen_apps:

            if seen_apps[current_method_hash] <= 1:
                continue

            numApps_seen_method.append(seen_apps[current_method_hash])

            method = methods[current_method_hash]

            if len(method.sensitive_APIs) != 0:
                numApps_seen_method_with_sensitiveAPIs.append(seen_apps[current_method_hash])
                common_hashes_with_sensitiveAPIs.append(current_method_hash)
            if len(method.tags) != 0:
                numApps_seen_method_with_sensitiveTAGs.append(seen_apps[current_method_hash])
                common_hashes_with_sensitiveTAGs.append(current_method_hash)

        make_index_available(index, methods, seen_apps, num_samples, common_hashes_with_sensitiveAPIs, numApps_seen_method, numApps_seen_method_with_sensitiveAPIs, numApps_seen_method_with_sensitiveTAGs, common_hashes_with_sensitiveTAGs)

    if num_samples >= MIN_NUM_SAMPLES: 

        #with open(stats_filename, 'w') as outfile:   
        if lock: lock.acquire()
        print '%// ------ Results for {} ({} samples) ------ '.format(family_name,  num_samples)
        print family_name + '_numApps_seen_method =', str(sorted(numApps_seen_method, reverse=True)).replace(',', '') + ';'
        print family_name + '_numApps_seen_method_with_sensitiveAPIs = ', str(sorted(numApps_seen_method_with_sensitiveAPIs, reverse=True)).replace(',', '') + ';'
        print family_name + '_num_methods =', len(seen_apps)
        print family_name + '_num_samples =', num_samples
        print 
        if lock: lock.release()

    return family_name


def get_detection_AndrozooLatest():

    csv_file_meta = "/home/gtangil/AndroZooCrawler/latest.csv" 
    vt_detections = {}

    with open(csv_file_meta, 'rb') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=',')
        for row in reader:
            vt_detections[str(row["sha256"]).lower()] = row["vt_detection"]
            #vt_detections[str(row["md5"]).lower()] = row["vt_detection"]

    return vt_detections

def get_detection_VT(): 

    REPORTS_FOLDER = '/data1/gtangil/AndroZoo-VT/reports'
    vt_detections_sha256 = {}
    vt_detections_md5 = {}

    for report in os.listdir(REPORTS_FOLDER):
        if report.endswith('report'):

            path = os.path.join(REPORTS_FOLDER, report)
            #print '[i] fetch_dataset_metainfo: processing', path
            json_report = pickle.load(open(path, "rb" ))

            if 'sha256' in json_report:
                sample = json_report['sha256']
                vt_detections_sha256[sample] = json_report['positives']
            if 'md5' in json_report:
                sample = json_report['md5']
                vt_detections_md5[sample] = json_report['positives']

    return vt_detections_sha256


def get_samples(path_to_folder):
    samples = []
    for filename in os.listdir(path_to_folder):
        if filename.endswith('.apk.pickle.gz'):
            samples.append(filename[:-len('.apk.pickle.gz')].lower())
    return samples



def get_num_detections_family(path_to_folder, vt_detections):

    family_name = os.path.basename(path_to_folder)
    samples = get_samples(path_to_folder)

    detections = []
    min_detections = None
    if len(samples) >= MIN_NUM_SAMPLES: 
        
        for sample in samples:
            if not sample in vt_detections:
                continue

            if not min_detections:
                min_detections = vt_detections[sample]
            if vt_detections[sample] < min_detections:
                min_detections = vt_detections[sample]
            if vt_detections[sample]:
                detections.append(int(vt_detections[sample]))
            #print sample, vt_detections[sample]

    return min_detections, detections


def get_stats_commonAPIs(path_to_folder):
    #index = os.path.abspath(path_to_folder) + '.pickle'
    index = os.path.abspath(path_to_folder) + '_withsamples.pickle'
    methods, seen_apps, num_samples, common_hashes_with_sensitiveAPIs, numApps_seen_method, numApps_seen_method_with_sensitiveAPIs, numApps_seen_method_with_sensitiveTAGs, common_hashes_with_sensitiveTAGs = load_index_if_available(index)
    index_available = num_samples > 0
    common_available = common_hashes_with_sensitiveAPIs != None 
    numApps_available = numApps_seen_method != None  and numApps_seen_method_with_sensitiveAPIs != None

    if num_samples < MIN_NUM_SAMPLES: 
        return None, None

    family_name = os.path.basename(path_to_folder)

    if 'goodware-play.google.com' in family_name:
        return None, None

    print 'Processing', family_name, 'at', index

    '''
    stats = {}
    for cRATIO in [90, 50, 30]:

        stats[cRATIO] = {'num_samples': num_samples, 'incognito': False, 'reflection': False, 'native': False, 'methods': 0, 'libraries': []}

        # List methods shared by RATIO % of the samples
        cutoff = cRATIO * num_samples / 100

        sensitive_APIs = []
        tags = []
        for current_method_hash in methods:
            #current_method_hash = hash(method)
            if seen_apps[current_method_hash] < cutoff: # We don't want to compare unpopular methods 
                continue
            method = methods[current_method_hash]

            if method.incognito:
                stats[cRATIO]['incognito'] = True
            if method.reflection:
                stats[cRATIO]['reflection'] = True
            if method.native:
                stats[cRATIO]['native'] = True

            if not method.class_name in stats[cRATIO]['libraries']: 
                stats[cRATIO]['libraries'].append(method.class_name)

            sensitive_APIs.extend(method.sensitive_APIs)
            tags.extend(method.tags)
            stats[cRATIO]['methods'] += 1

        stats[cRATIO]['sensitive_APIs'] = set(sensitive_APIs)
        stats[cRATIO]['tags'] = set(tags)

    '''

    stats = {}
    for cRATIO in [100, 90, 50, 30]:

        stats[cRATIO] = {'num_samples': num_samples, 'family': family_name, 'incognito': False, 'reflection': False, 'native': False, 'methods': 0, 'samples': {'incognito': [], 'native': [], 'reflection': []}, 'samples_tags':{}}

        # List methods shared by RATIO % of the samples
        cutoff = cRATIO * num_samples / 100

        #print "Listing CCC for methods seen in {0}/{1} ({2}%) apps".format(cutoff, num_samples, cRATIO) 

        sensitive_APIs = []
        tags = []
        for current_method_hash in seen_apps:
            if len(seen_apps[current_method_hash]) < cutoff: # We don't want to compare unpopular methods 
                continue
            method = methods[current_method_hash]

            stats[cRATIO]['methods'] += 1

            #I keep track of all the apps in a family that exhibit a certain feature (e.g.: incognito, sAPI, etc.)
            if method.incognito:
                stats[cRATIO]['incognito'] = True

                seen_apps[current_method_hash]

                stats[cRATIO]['samples']['incognito'].extend(seen_apps[current_method_hash])
                stats[cRATIO]['samples']['incognito'] = list(set(stats[cRATIO]['samples']['incognito']))  # To alleviate RAM preasure
            if method.reflection:
                stats[cRATIO]['reflection'] = True
                stats[cRATIO]['samples']['reflection'].extend(seen_apps[current_method_hash])
                stats[cRATIO]['samples']['reflection'] = list(set(stats[cRATIO]['samples']['reflection'])) # To alleviate RAM preasure
            if method.native:
                stats[cRATIO]['native'] = True
                stats[cRATIO]['samples']['native'].extend(seen_apps[current_method_hash])
                stats[cRATIO]['samples']['native'] = list(set(stats[cRATIO]['samples']['native']))         # To alleviate RAM preasure

            for sAPI in method.sensitive_APIs:
                if sAPI not in stats[cRATIO]['samples']:
                    stats[cRATIO]['samples'][sAPI] = []
                stats[cRATIO]['samples'][sAPI].extend(seen_apps[current_method_hash])
                stats[cRATIO]['samples'][sAPI] = list(set(stats[cRATIO]['samples'][sAPI]))                 # To alleviate RAM preasure

            for tag in method.tags:
                if tag not in stats[cRATIO]['samples_tags']:
                    stats[cRATIO]['samples_tags'][tag] = []
                stats[cRATIO]['samples_tags'][tag].extend(seen_apps[current_method_hash])
                stats[cRATIO]['samples_tags'][tag] = list(set(stats[cRATIO]['samples_tags'][tag]))         # To alleviate RAM preasure

            sensitive_APIs.extend(method.sensitive_APIs)
            sensitive_APIs = list(set(sensitive_APIs))         # To alleviate RAM preasure

            tags.extend(method.tags)
            tags = list(set(tags))                             # To alleviate RAM preasure

        stats[cRATIO]['sensitive_APIs'] = set(sensitive_APIs)
        stats[cRATIO]['tags'] = set(tags)


    return stats, family_name





'''
 FUNCTIONALITY - Macropersepective (opverall state):
 Number of families/samples where a feature is seen in most (90\% cutoff) of the apps in the family 
 together with the total number of subfamilies for different cutoffs (30\% and 10\%)
 This method is used to create Table \ref{tab:functionality:macro}
'''
def get_statsCommonAPIs_dataset(path_to_folder, paralell=True):
    path_to_families = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder) if (os.path.isdir(os.path.join(path_to_folder, f)) and not os.path.basename(os.path.join(path_to_folder, f)) in blacklist_families)]

    families = {}
    if not paralell:
        for path_to_family in path_to_families:
            family_name = os.path.basename(path_to_family)
            try:
                stats_family, family_name = get_stats_commonAPIs(path_to_family)
                #stats_family, family_name = postprocess_family_no_index_keeptrack(path_to_family)
                if not stats_family:
                    continue
                families[family_name] = stats_family
            except Exception, e:
                print "Error at ", path_to_family, ":", str(e)
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback.print_tb(exc_traceback)  
    else:

        # ---- Pool all tasks
        print 'Creating pool with %d processes' % settings.n_procs    
        pool = multiprocessing.Pool(settings.n_procs) #, maxtasksperchild=100    

        try:
            #results = [pool.apply_async(postprocess_family_no_index_keeptrack, [path_to_family]) for path_to_family in path_to_families]
            results = [pool.apply_async(get_stats_commonAPIs, [path_to_family]) for path_to_family in path_to_families]
        finally:
            pool.close()
            pool.join()

        # ---- Process all results
        for result in results:
            result = result.get()
            if result and len(result) == 2:
                stats_family = result[0]
                family_name = result[1]
                if not stats_family:
                    continue
                families[family_name] = stats_family
            else:
                print 'ERROR processing result', result


    sensitive_API2 = {}
    for sapi in sensitive_API: 
      sensitive_API2[sapi] = []
    tags = set()

    stats = {100: {'num_families_tag': {}, 'num_families_incognito': 0, 'num_families_reflection': 0, 'num_families_native': 0, 'num_families_sensitive_API': copy.deepcopy(sensitive_API),     'num_samples_tag':{}, 'num_samples_incognito': [], 'num_samples_reflection': [], 'num_samples_native': [], 'num_samples_sensitive_API': copy.deepcopy(sensitive_API2)}, 
              90: {'num_families_tag': {}, 'num_families_incognito': 0, 'num_families_reflection': 0, 'num_families_native': 0, 'num_families_sensitive_API': copy.deepcopy(sensitive_API),     'num_samples_tag':{}, 'num_samples_incognito': [], 'num_samples_reflection': [], 'num_samples_native': [], 'num_samples_sensitive_API': copy.deepcopy(sensitive_API2)}, 
              50: {'num_families_tag': {}, 'num_families_incognito': 0, 'num_families_reflection': 0, 'num_families_native': 0, 'num_families_sensitive_API': copy.deepcopy(sensitive_API),     'num_samples_tag':{}, 'num_samples_incognito': [], 'num_samples_reflection': [], 'num_samples_native': [], 'num_samples_sensitive_API': copy.deepcopy(sensitive_API2)}, 
              30: {'num_families_tag': {}, 'num_families_incognito': 0, 'num_families_reflection': 0, 'num_families_native': 0, 'num_families_sensitive_API': copy.deepcopy(sensitive_API),     'num_samples_tag':{}, 'num_samples_incognito': [], 'num_samples_reflection': [], 'num_samples_native': [], 'num_samples_sensitive_API': copy.deepcopy(sensitive_API2)}}
    
    num_samples = 0
    for family_name in families:
        stats_family = families[family_name]
        num_samples += stats_family[90]['num_samples'] 
        for cRATIO in stats_family:
            if stats_family[cRATIO]['incognito']:
                stats[cRATIO]['num_families_incognito'] += 1
                if 'samples' in stats_family[cRATIO]:
                    stats[cRATIO]['num_samples_incognito'].extend(stats_family[cRATIO]['samples']['incognito'])
            if stats_family[cRATIO]['reflection']:
                stats[cRATIO]['num_families_reflection'] += 1
                if 'samples' in stats_family[cRATIO]:
                    stats[cRATIO]['num_samples_reflection'].extend(stats_family[cRATIO]['samples']['reflection'])
            if stats_family[cRATIO]['native']:
                stats[cRATIO]['num_families_native'] += 1
                if 'samples' in stats_family[cRATIO]:
                    stats[cRATIO]['num_samples_native'].extend(stats_family[cRATIO]['samples']['native'])

            for sapi in stats_family[cRATIO]['sensitive_APIs']:
                stats[cRATIO]['num_families_sensitive_API'][sapi] += 1
                if sapi not in stats[cRATIO]['num_samples_sensitive_API']:
                    stats[cRATIO]['num_samples_sensitive_API'][sapi] = []
                if 'samples' in stats_family[cRATIO]:
                    if sapi in stats_family[cRATIO]['samples']:
                        stats[cRATIO]['num_samples_sensitive_API'][sapi].extend(stats_family[cRATIO]['samples'][sapi])

            for tag in stats_family[cRATIO]['tags']:
                if tag not in stats[cRATIO]['num_families_tag']:
                    stats[cRATIO]['num_families_tag'][tag] = 0
                stats[cRATIO]['num_families_tag'][tag] += 1
                if tag not in stats[cRATIO]['num_samples_tag']:
                    stats[cRATIO]['num_samples_tag'][tag] = []
                if 'samples_tags' in stats_family[cRATIO]: 
                    if tag in stats_family[cRATIO]['samples_tags']:
                        stats[cRATIO]['num_samples_tag'][tag].extend(stats_family[cRATIO]['samples_tags'][tag])
                tags.add(tag)

            
    print 'FAMILIES'
    print '{} \t &  \t {} \t &  \t {} \t &  \t {} \\\\'.format('Feature', '90\%', '50\%', '30')
    print '\hline'
    print '\hline'
    print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\% \\\\'.format('Incognito',   round(float(stats[90]['num_families_incognito'])/float(len(families))*100, 1),  round(float(stats[50]['num_families_incognito'])/float(len(families))*100, 1),  round(float(stats[30]['num_families_incognito'])/float(len(families))*100, 1))
    print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\% \\\\'.format('Reflection',  round(float(stats[90]['num_families_reflection'])/float(len(families))*100, 1), round(float(stats[50]['num_families_reflection'])/float(len(families))*100, 1), round(float(stats[30]['num_families_reflection'])/float(len(families))*100, 1))
    print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\% \\\\'.format('Native',      round(float(stats[90]['num_families_native'])/float(len(families))*100, 1),     round(float(stats[50]['num_families_native'])/float(len(families))*100, 1),     round(float(stats[30]['num_families_native'])/float(len(families))*100, 1))
    print '\hline' 
    for sapi in sorted(sensitive_API):
        print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\% \\\\'.format(sapi,      round(float(stats[90]['num_families_sensitive_API'][sapi])/float(len(families))*100, 1), round(float(stats[50]['num_families_sensitive_API'][sapi])/float(len(families))*100, 1), round(float(stats[30]['num_families_sensitive_API'][sapi])/float(len(families))*100, 1))
    print '\hline' 
    print '\hline' 
    for tag in sorted(tags):
        if not tag in stats[90]['num_families_tag']:
            stats[90]['num_families_tag'][tag] = 0
        if not tag in stats[50]['num_families_tag']:
            stats[50]['num_families_tag'][tag] = 0
        if not tag in stats[30]['num_families_tag']:
            stats[30]['num_families_tag'][tag] = 0
        print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\% \\\\'.format(tag,      round(float(stats[90]['num_families_tag'][tag])/float(len(families))*100, 1), round(float(stats[50]['num_families_tag'][tag])/float(len(families))*100, 1), round(float(stats[30]['num_families_tag'][tag])/float(len(families))*100, 1))
    print '\hline' 
    

    print 
    print 
    print 

    print 'FAMILIES'
    print '{} \t &  \t {} \t &  \t {} \t &  \t {} \\\\'.format('Feature', '90\%', '50\%', '30\%')
    print '\hline'
    print '\hline'
    print '{} \t &  \t {} ({}\%) \t &  \t {} ({}\%) \t &  \t {} ({}\%) \\\\'.format('Incognito',  stats[90]['num_families_incognito'],   round(float(stats[90]['num_families_incognito'])/float(len(families))*100, 1),  stats[50]['num_families_incognito'],  round(float(stats[50]['num_families_incognito'])/float(len(families))*100, 1),  stats[30]['num_families_incognito'],  round(float(stats[30]['num_families_incognito'])/float(len(families))*100, 1))
    print '{} \t &  \t {} ({}\%) \t &  \t {} ({}\%) \t &  \t {} ({}\%) \\\\'.format('Reflection', stats[90]['num_families_reflection'],  round(float(stats[90]['num_families_reflection'])/float(len(families))*100, 1), stats[50]['num_families_reflection'], round(float(stats[50]['num_families_reflection'])/float(len(families))*100, 1), stats[30]['num_families_reflection'], round(float(stats[30]['num_families_reflection'])/float(len(families))*100, 1))
    print '{} \t &  \t {} ({}\%) \t &  \t {} ({}\%) \t &  \t {} ({}\%) \\\\'.format('Native',     stats[90]['num_families_native'],      round(float(stats[90]['num_families_native'])/float(len(families))*100, 1),     stats[50]['num_families_native'],     round(float(stats[50]['num_families_native'])/float(len(families))*100, 1),     stats[30]['num_families_native'],     round(float(stats[30]['num_families_native'])/float(len(families))*100, 1))
    print '\hline' 
    for sapi in sorted(sensitive_API):
        print '{} \t &  \t {} ({}\%) \t &  \t {} ({}\%) \t &  \t {} ({}\%) \\\\'.format(sapi,     stats[90]['num_families_sensitive_API'][sapi], round(float(stats[90]['num_families_sensitive_API'][sapi])/float(len(families))*100, 1), stats[50]['num_families_sensitive_API'][sapi], round(float(stats[50]['num_families_sensitive_API'][sapi])/float(len(families))*100, 1), stats[30]['num_families_sensitive_API'][sapi], round(float(stats[30]['num_families_sensitive_API'][sapi])/float(len(families))*100, 1))
    print '\hline' 
    print '\hline' 
    for tag in sorted(tags):
        if not tag in stats[90]['num_families_tag']:
            stats[90]['num_families_tag'][tag] = 0
        if not tag in stats[50]['num_families_tag']:
            stats[50]['num_families_tag'][tag] = 0
        if not tag in stats[30]['num_families_tag']:
            stats[30]['num_families_tag'][tag] = 0

        print '{} \t &  \t {} ({}\%) \t &  \t {} ({}\%) \t &  \t {} ({}\%) \\\\'.format(tag,     stats[90]['num_families_tag'][tag], round(float(stats[90]['num_families_tag'][tag])/float(len(families))*100, 1), stats[50]['num_families_tag'][tag], round(float(stats[50]['num_families_tag'][tag])/float(len(families))*100, 1), stats[30]['num_families_tag'][tag], round(float(stats[30]['num_families_tag'][tag])/float(len(families))*100, 1))
    print '\hline' 

    print 
    print 
    print 

    print 'FAMILIES AND SAMPLES'
    print '{} \t &  \t {} \t &  \t {} \t &  \t {} &  \t {} \t &  \t {} \t &  \t {} \\\\'.format('Feature', '90\%', '50\%', '30\%', '90\%', '50\%', '30\%')
    print '\hline'
    print '\hline'
    print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\%  &  \t {}\% \t &  \t {}\% \t &  \t {}\% \\\\'.format('Incognito',   round(float(stats[90]['num_families_incognito'])/float(len(families))*100, 1),  round(float(stats[50]['num_families_incognito'])/float(len(families))*100, 1),  round(float(stats[30]['num_families_incognito'])/float(len(families))*100, 1),      round(float(len(set(stats[90]['num_samples_incognito'])))/float((num_samples))*100, 1),  round(float(len(set(stats[50]['num_samples_incognito'])))/float((num_samples))*100, 1),  round(float(len(set(stats[30]['num_samples_incognito'])))/float((num_samples))*100), 1  )
    print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\% &  \t {}\% \t &  \t {}\% \t &  \t {}\%  \\\\'.format('Reflection',  round(float(stats[90]['num_families_reflection'])/float(len(families))*100, 1), round(float(stats[50]['num_families_reflection'])/float(len(families))*100, 1), round(float(stats[30]['num_families_reflection'])/float(len(families))*100, 1),     round(float(len(set(stats[90]['num_samples_reflection'])))/float((num_samples))*100, 1), round(float(len(set(stats[50]['num_samples_reflection'])))/float((num_samples))*100, 1), round(float(len(set(stats[30]['num_samples_reflection'])))/float((num_samples))*100, 1)  )
    print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\% &  \t {}\% \t &  \t {}\% \t &  \t {}\%  \\\\'.format('Native',      round(float(stats[90]['num_families_native'])/float(len(families))*100, 1),     round(float(stats[50]['num_families_native'])/float(len(families))*100, 1),     round(float(stats[30]['num_families_native'])/float(len(families))*100, 1),         round(float(len(set(stats[90]['num_samples_native'])))/float((num_samples))*100, 1),     round(float(len(set(stats[50]['num_samples_native'])))/float((num_samples))*100, 1),     round(float(len(set(stats[30]['num_samples_native'])))/float((num_samples))*100, 1)   )
    print '\hline' 
    for sapi in sorted(sensitive_API):
        print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\%  &  \t {}\% \t &  \t {}\% \t &  \t {}\% \\\\'.format(sapi,      round(float(stats[90]['num_families_sensitive_API'][sapi])/float(len(families))*100, 1), round(float(stats[50]['num_families_sensitive_API'][sapi])/float(len(families))*100, 1), round(float(stats[30]['num_families_sensitive_API'][sapi])/float(len(families))*100, 1),    round(float(len(set(stats[90]['num_samples_sensitive_API'][sapi])))/float((num_samples))*100, 1), round(float(len(set(stats[50]['num_samples_sensitive_API'][sapi])))/float((num_samples))*100, 1), round(float(len(set(stats[30]['num_samples_sensitive_API'][sapi])))/float((num_samples))*100, 1)  )
    print '\hline' 
    print '\hline' 
    for tag in sorted(tags):
        if not tag in stats[90]['num_families_tag']:
            stats[90]['num_families_tag'][tag] = 0
        if not tag in stats[50]['num_families_tag']:
            stats[50]['num_families_tag'][tag] = 0
        if not tag in stats[30]['num_families_tag']:
            stats[30]['num_families_tag'][tag] = 0

        if not tag in stats[90]['num_samples_tag']:
            stats[90]['num_samples_tag'][tag] = 0
        if not tag in stats[50]['num_samples_tag']:
            stats[50]['num_samples_tag'][tag] = 0
        if not tag in stats[30]['num_samples_tag']:
            stats[30]['num_samples_tag'][tag] = 0

        try:
            print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\%  &  \t {}\% \t &  \t {}\% \t &  \t {}\% \\\\'.format(tag,      round(float(stats[90]['num_families_tag'][tag])/float(len(families))*100, 1), round(float(stats[50]['num_families_tag'][tag])/float(len(families))*100, 1), round(float(stats[30]['num_families_tag'][tag])/float(len(families))*100, 1),    round(float(len(set(stats[90]['num_samples_tag'][tag])))/float((num_samples))*100, 1), round(float(len(set(stats[50]['num_samples_tag'][tag])))/float((num_samples))*100, 1), round(float(len(set(stats[30]['num_samples_tag'][tag])))/float((num_samples))*100, 1)  )
        except TypeError:
            print '%TypeError, Skipping', tag
    print '\hline' 


    print 'FAMILIES (SAMPLES)'
    print '{} \t &  \t {} \t &  \t {} \t &  \t {} &  \t {} \t &  \t {} \t &  \t {} \\\\'.format('Feature', '90\%', '50\%', '30\%', '90\%', '50\%', '30\%')
    print '\hline'
    print '\hline'
    print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\%  &  \t {}\% \t &  \t {}\% \t &  \t {}\% \\\\'.format('Incognito',   round(float(stats[90]['num_families_incognito'])/float(len(families))*100, 1),  round(float(stats[50]['num_families_incognito'])/float(len(families))*100, 1),  round(float(stats[30]['num_families_incognito'])/float(len(families))*100, 1),      round(float(len(set(stats[90]['num_samples_incognito'])))/float((num_samples))*100, 1),  round(float(len(set(stats[50]['num_samples_incognito'])))/float((num_samples))*100, 1),  round(float(len(set(stats[30]['num_samples_incognito'])))/float((num_samples))*100, 1)  )
    print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\% &  \t {}\% \t &  \t {}\% \t &  \t {}\%  \\\\'.format('Reflection',  round(float(stats[90]['num_families_reflection'])/float(len(families))*100, 1), round(float(stats[50]['num_families_reflection'])/float(len(families))*100, 1), round(float(stats[30]['num_families_reflection'])/float(len(families))*100, 1),     round(float(len(set(stats[90]['num_samples_reflection'])))/float((num_samples))*100, 1), round(float(len(set(stats[50]['num_samples_reflection'])))/float((num_samples))*100, 1), round(float(len(set(stats[30]['num_samples_reflection'])))/float((num_samples))*100, 1)  )
    print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\% &  \t {}\% \t &  \t {}\% \t &  \t {}\%  \\\\'.format('Native',      round(float(stats[90]['num_families_native'])/float(len(families))*100, 1),     round(float(stats[50]['num_families_native'])/float(len(families))*100, 1),     round(float(stats[30]['num_families_native'])/float(len(families))*100, 1),         round(float(len(set(stats[90]['num_samples_native'])))/float((num_samples))*100, 1),     round(float(len(set(stats[50]['num_samples_native'])))/float((num_samples))*100, 1),     round(float(len(set(stats[30]['num_samples_native'])))/float((num_samples))*100, 1)   )
    print '\hline' 
    for sapi in sorted(sensitive_API):
        print '{} \t &  \t {}\% \t &  \t {}\% \t &  \t {}\%  &  \t {}\% \t &  \t {}\% \t &  \t {}\% \\\\'.format(sapi,      round(float(stats[90]['num_families_sensitive_API'][sapi])/float(len(families))*100, 1), round(float(stats[50]['num_families_sensitive_API'][sapi])/float(len(families))*100, 1), round(float(stats[30]['num_families_sensitive_API'][sapi])/float(len(families))*100, 1),    round(float(len(set(stats[90]['num_samples_sensitive_API'][sapi])))/float((num_samples))*100), round(float(len(set(stats[50]['num_samples_sensitive_API'][sapi])))/float((num_samples))*100), round(float(len(set(stats[30]['num_samples_sensitive_API'][sapi])))/float((num_samples))*100)  )
    print '\hline' 
    print '\hline' 
    for tag in sorted(tags):
        if not tag in stats[90]['num_families_tag']:
            stats[90]['num_families_tag'][tag] = 0
        if not tag in stats[50]['num_families_tag']:
            stats[50]['num_families_tag'][tag] = 0
        if not tag in stats[30]['num_families_tag']:
            stats[30]['num_families_tag'][tag] = 0

        if not tag in stats[90]['num_samples_tag']:
            stats[90]['num_samples_tag'][tag] = 0
        if not tag in stats[50]['num_samples_tag']:
            stats[50]['num_samples_tag'][tag] = 0
        if not tag in stats[30]['num_samples_tag']:
            stats[30]['num_samples_tag'][tag] = 0

        try:
            print '{0} \t &  \t {1}\% ({4}\%) \t &  \t {2}\% ({5}\%) \t &  \t {3}\% ({6}\%) \\\\'.format(tag,      round(float(stats[90]['num_families_tag'][tag])/float(len(families))*100, 1), round(float(stats[50]['num_families_tag'][tag])/float(len(families))*100, 1), round(float(stats[30]['num_families_tag'][tag])/float(len(families))*100, 1),    round(float(len(set(stats[90]['num_samples_tag'][tag])))/float((num_samples))*100, 1), round(float(len(set(stats[50]['num_samples_tag'][tag])))/float((num_samples))*100, 1), round(float(len(set(stats[30]['num_samples_tag'][tag])))/float((num_samples))*100, 1)  )
        except TypeError:
            print '%TypeError, Skipping', tag
    print '\hline' 



'''
 Common methods per family: Number of methods common to (x%) samples in a family. 
 This is used to plot Figure \ref{fig:commonMethods} and \ref{fig:commonMethodsSamples}
'''
def get_statsCommonMethods_dataset(path_to_folder):
    path_to_families = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder) if os.path.isdir(os.path.join(path_to_folder, f))]

    print '%//Number of methods seen in a given family'
    print

    num_apps_per_family = {}

    common_methods_per_family_100 = []
    common_methods_per_family_90 = []
    common_methods_per_family_50 = []
    common_methods_per_family_30 = []
    for path_to_family in path_to_families:
        family_name = os.path.basename(path_to_family)
        try:
            num_methods_common, num_apps = get_stats_family_commonMethods(path_to_family)
            if not num_methods_common:
                continue
            num_apps_per_family[family_name] = num_apps
            common_methods_per_family_100.append((num_methods_common[100], family_name))
            common_methods_per_family_90.append((num_methods_common[90], family_name))
            common_methods_per_family_50.append((num_methods_common[50], family_name))
            common_methods_per_family_30.append((num_methods_common[30], family_name))
        except Exception, e:
            print "Error at ", path_to_family, ":", str(e)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback)      
    
    smethods = [tuple[0] for tuple in sorted(common_methods_per_family_100)] 
    snames = [tuple[1] for tuple in sorted(common_methods_per_family_100)] 
    print 'snames_100 =', snames
    print 'common_methods_per_family_100 =', str(smethods)
    print 'common_methods_per_family_100 =', str(smethods).replace(',', '') + ';'
    print 'num_samples_100 =', str([num_apps_per_family[n] for n in snames]).replace(',', '') + ';'
    
    smethods = [tuple[0] for tuple in sorted(common_methods_per_family_90)] 
    snames = [tuple[1] for tuple in sorted(common_methods_per_family_90)] 
    print 'snames_90 =', snames
    print 'common_methods_per_family_90 =', str(smethods)
    print 'common_methods_per_family_90 =', str(smethods).replace(',', '') + ';'
    print 'num_samples_90 =', str([num_apps_per_family[n] for n in snames]).replace(',', '') + ';'

    smethods = [tuple[0] for tuple in sorted(common_methods_per_family_50)] 
    snames = [tuple[1] for tuple in sorted(common_methods_per_family_50)] 
    print 'snames_50 =', snames
    print 'common_methods_per_family_50 =', str(sorted(smethods))
    print 'common_methods_per_family_50 =', str(sorted(smethods)).replace(',', '') + ';'
    print 'num_samples_50 =', str([num_apps_per_family[n] for n in snames]).replace(',', '') + ';'
    
    smethods = [tuple[0] for tuple in sorted(common_methods_per_family_30)] 
    snames = [tuple[1] for tuple in sorted(common_methods_per_family_30)] 
    print 'snames_30 =', snames
    print 'common_methods_per_family_30 =', str(sorted(smethods))
    print 'common_methods_per_family_30 =', str(sorted(smethods)).replace(',', '') + ';'
    print 'num_samples_30 =', str([num_apps_per_family[n] for n in snames]).replace(',', '') + ';'



def get_statsDetections_dataset_vt(path_to_folder, vt_detections):
    
    #path_to_families = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder) if os.path.isdir(os.path.join(path_to_folder, f))]
    path_to_families = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder) if (os.path.isdir(os.path.join(path_to_folder, f)) and not os.path.basename(os.path.join(path_to_folder, f)) in blacklist_families)]

    detections_all = []
    detections_min = []
    min_detections_all = None
    for path_to_family in path_to_families:
        try:
            min_detections_family, detections_family = get_num_detections_family(path_to_family, vt_detections)
            if min_detections_family:
                detections_min.append(min_detections_family)
            detections_all.extend(detections_family)
            if not min_detections_all:
                min_detections_all = min_detections_family
            if min_detections_family < min_detections_all:
                min_detections_all = min_detections_family
        except Exception, e:
            print "Error at ", path_to_family, ":", str(e)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback)      
    print 'detections_all =', detections_all
    print 'detections_min =', detections_min
    if len(detections_all) > 0:
        print 'mean_all =', str(sum(detections_all)/len(detections_all))
    print min_detections_all

def get_statsDetections_dataset(path_to_folder):
    
    print '# get_detection_VT'
    vt_detections_virusTotal = get_detection_VT()
    get_statsDetections_dataset_vt(path_to_folder, vt_detections_virusTotal)

    print '# get_detection_AndrozooLatest'
    vt_detections_AndroZoo = get_detection_AndrozooLatest()
    get_statsDetections_dataset_vt(path_to_folder, vt_detections_AndroZoo)

    print '# get_detection VT||AndrozooLatest'
    vt_detections = {}
    for sha256 in vt_detections_virusTotal: 
        vt_detections[sha256] = vt_detections_virusTotal[sha256]
    for sha256 in vt_detections_AndroZoo:
        # Keepting VT detections over AndroZoo's  
        if not sha256 in vt_detections: 
            vt_detections[sha256] = vt_detections_AndroZoo[sha256]
    get_statsDetections_dataset_vt(path_to_folder, vt_detections)


'''
 Prevalence of methods across apps from top 10 most popular families.
 This method is used to plot general Figure \ref{fig:statsTop10}.
'''
def get_statsTop10_dataset(path_to_folder):
    path_to_families = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder) if os.path.isdir(os.path.join(path_to_folder, f))]

    print '%//Number of apps seen in a given method'
    print

    top_largest = ["jiagu", "dowgin", "artemis", "revmob", "youmi", "kuguo", "adwo", "airpush", "leadbolt", "droidkungfu"]
    top_prevalent = ["hippo", "jsmshider", "basebridge", "fakeflash", "safekidzone", "ginmaster", "plankton", "rooter", "gpspy", "golddream"]
    top_viral = ["spyforw", "genpua", "deng", "appsgeyser", "utchi", "anydown", "admobads", "startapp", "admogo", "wapsx"]
    top_stealthy = ["lockad", "kazy", "pirates", "jumptapiads", "skymobi", "revmobads", "viser", "malform", "vdloader", "waps"]

    top = []
    top.extend(top_largest)
    top.extend(top_prevalent)
    top.extend(top_viral)
    top.extend(top_stealthy)

    families = []
    for path_to_family in path_to_families:
        if os.path.basename(path_to_family) not in top:
            continue
        try:
            family_name = get_stats_family(path_to_family)
            families.append(family_name)
        except Exception, e:
            print "Error at ", path_to_family, ":", str(e)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback)      
    print    
    print 'hold on'
    for family_name in families:
        print "plot(" + family_name + "_numApps_seen_method/" + family_name + "_num_samples, 'DisplayName', '" + family_name.replace('_', '-') + "')"
    print "legend('show')"


def get_statsTop10_dataset_batch(path_to_folder):

    path_to_families = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder) if os.path.isdir(os.path.join(path_to_folder, f))]

    print '%//Number of apps seen in a given method'
    print 

    #pool = multiprocessing.Pool(settings.n_procs) #, maxtasksperchild=100    
    pool = ThreadPool(settings.n_procs)  
    lock = Lock()  
    batch_func = partial(get_stats_family_withLock, lock)
    

    try:
        #results = [pool.apply_async(get_stats_family, [path_to_family]) for path_to_family in path_to_families]
        results = [pool.map(batch_func, [path_to_family]) for path_to_family in path_to_families]
    except Exception, e:
        print "Error", str(e)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_tb(exc_traceback)
    finally:
        if lock.acquire(False):
            lock.release()        
        pool.close()
        pool.join()

    families = []
    # ---- Process all results
    for result in results:
        #result = result.get()
        result = result[0]
        if result:
            families.append(result)            
        else:
            print 'ERROR processing result', result

    print 'hold on'
    for family_name in families:
        print "plot(" + family_name + "_numApps_seen_method/" + family_name + "_num_samples, 'DisplayName', " + family_name.replace('_', '-') + ")"
    print "legend('show')"


def postprocess_dataset(path_to_folder):

    path_to_families = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder) if os.path.isdir(os.path.join(path_to_folder, f))]
                 
    # ---- Pool all tasks
    print 'Creating pool with %d processes' % settings.n_procs    
    pool = multiprocessing.Pool(settings.n_procs) #, maxtasksperchild=100    

    start = default_timer()
    try:
        results = [pool.apply_async(postprocess_family, [path_to_family, False, True]) for path_to_family in path_to_families]
    finally:
        pool.close()
        pool.join()

    # ---- Get terminated  
    overall_overhead = default_timer() - start
    print "Extraction: %.2f seconds" % (overall_overhead)

    overhead = []
    # ---- Process all results
    for result in results:
        result = result.get()
        if result:
            overhead.append(result)

        else:
            print 'ERROR processing result', result

    print "PreprocessingTime = ",  overhead
    print "MeanPreprocessingTime", np.mean(overhead)



'''
Percentage of families in each querter of a year where their members share a feature in common with 90%.
This method is used to plot Figure \ref{fig:timeline}.
'''

def get_timeline_dataset(path_to_folder):
    
    path_to_families = []

    # evolution_families_in_quarter-cutoff_7.json evolution_samples_in_quarter-cutoff_7.json
    with open('evolution_samples_in_family_per_quarter-cutoff_7.json') as infile: 
        samples_in_family_per_quarter = json.load(infile)

    path_samples_in_family_per_quarter = {}

    for family_quarter in samples_in_family_per_quarter:
        s = family_quarter.split('-')
        family  = s[0]
        quarter = s[1]

        if family in blacklist_families:
            print 'Ignoring blacklisted family', family
            continue

        if family_quarter not in path_samples_in_family_per_quarter:
            path_samples_in_family_per_quarter[family_quarter] = []

        for sample in samples_in_family_per_quarter[family_quarter]:
            path = os.path.join(path_to_folder, family, sample) + '.apk.pickle'
            if os.path.isfile(path):
                path_samples_in_family_per_quarter[family_quarter].append(path)

    '''    
    for family_quarter in path_samples_in_family_per_quarter:
        path_samples = path_samples_in_family_per_quarter[family_quarter] 
        print 'Processing {} samples in {}'.format(len(path_samples), family_quarter)
        stats = postprocess_setsamples(path_samples, family_quarter)
        print stats
    '''
    
    # ---- Pool all tasks
    print 'Creating pool with %d processes' % settings.n_procs    
    pool = multiprocessing.Pool(settings.n_procs) #, maxtasksperchild=100    

    try:
        results = [pool.apply_async(postprocess_setsamples, [path_samples_in_family_per_quarter[family_quarter], family_quarter]) for family_quarter in path_samples_in_family_per_quarter]
    finally:
        pool.close()
        pool.join()    
    
    print 'Processing results' 

    stats_per_quarter = {}
    # ---- Process all results
    for result in results:
        stats_family, quarter = result.get()
        if stats_family:
            if quarter not in stats_per_quarter: 
                stats_per_quarter[quarter] = []
            stats_per_quarter[quarter].append(stats_family)        

        else:
            print 'ERROR processing result', result


    all_quarters_ordered = ['2009Q1', '2009Q2', '2009Q3', '2009Q4', 
                        '2010Q1', '2010Q2', '2010Q3', '2010Q4',
                        '2011Q1', '2011Q2', '2011Q3', '2011Q4',
                        '2012Q1', '2012Q2', '2012Q3', '2012Q4',
                        '2013Q1', '2013Q2', '2013Q3', '2013Q4',
                        '2014Q1', '2014Q2', '2014Q3', '2014Q4',
                        '2015Q1', '2015Q2', '2015Q3', '2015Q4',
                        '2016Q1', '2016Q2', '2016Q3', '2016Q4',
                        '2017Q1', '2017Q2', '2017Q3', '2017Q4']

    num_incognito_per_quarter = []
    num_reflection_per_quarter = []
    num_native_per_quarter = []
    num_sensitive_API_quarter = np.zeros((len(sensitive_API), len(all_quarters_ordered)))
    for quarter_index in range(len(all_quarters_ordered)):

        quarter = all_quarters_ordered[quarter_index]

        stats = {90: {'num_incognito': 0, 'num_reflection': 0, 'num_native': 0, 'num_sensitive_API': copy.copy(sensitive_API)}, 
                 50: {'num_incognito': 0, 'num_reflection': 0, 'num_native': 0, 'num_sensitive_API': copy.copy(sensitive_API)}, 
                 30: {'num_incognito': 0, 'num_reflection': 0, 'num_native': 0, 'num_sensitive_API': copy.copy(sensitive_API)}}
   
        if quarter in stats_per_quarter:
            num_families_per_quarter = len(stats_per_quarter[quarter])
            for stats_family in stats_per_quarter[quarter]:
                for cRATIO in stats_family:
                    if stats_family[cRATIO]['incognito']:
                        stats[cRATIO]['num_incognito'] += 1.0/num_families_per_quarter
                    if stats_family[cRATIO]['reflection']:
                        stats[cRATIO]['num_reflection'] += 1.0/num_families_per_quarter
                    if stats_family[cRATIO]['native']:
                        stats[cRATIO]['num_native'] += 1.0/num_families_per_quarter

                    for sapi in stats_family[cRATIO]['sensitive_APIs']:
                        stats[cRATIO]['num_sensitive_API'][sapi] += 1.0/num_families_per_quarter
                

        #We are only interested in stats[90] for now... 
        num_incognito_per_quarter.append(stats[90]['num_incognito'])
        num_reflection_per_quarter.append(stats[90]['num_reflection'])
        num_native_per_quarter.append(stats[90]['num_native'])

        for api_index in range(len(sensitive_API.keys())):
            api = sensitive_API[sensitive_API.keys()[api_index]]
            num_sensitive_API_quarter[api_index][quarter_index] = stats[90]['num_sensitive_API'][sensitive_API.keys()[api_index]]

    print 'numIncognitoPerQuarter =', str(num_incognito_per_quarter).replace(',', '') + ';'
    print 'numReflectionPerQuarter =', str(num_reflection_per_quarter).replace(',', '') + ';'
    print 'numNativePerQuarter =', str(num_native_per_quarter).replace(',', '') + ';'
    for api_index in range(len(sensitive_API.keys())):
        api = sensitive_API.keys()[api_index]
        vector = []
        for value in num_sensitive_API_quarter[api_index]:
            vector.append(value)
        print '' + api.replace(':', '_').replace('Manager', '') + ' =', str(vector).replace(',', '') + ';'

    print "plot(numIncognitoPerQuarter, 'DisplayName', 'Incognito', 'MarkerSize', 8.0)"
    print "plot(numReflectionPerQuarter, 'DisplayName', 'Reflection', 'MarkerSize', 8.0)"
    print "plot(numNativePerQuarter, 'DisplayName', 'Native', 'MarkerSize', 8.0)"

    specifiers = ['+', '*', '.', 'x', 's', 'd', '^', 'v', '>', '<', 'p', 'h', 'o']
    sindex = 0
    for api_index in range(len(sensitive_API.keys())):
        api = sensitive_API.keys()[api_index]
        variablename = api.replace(':', '_').replace('Manager', '')
        displayname = api.replace(':', '.').replace('Manager', '')
        print "plot(" + variablename + ", '" + specifiers[sindex] + "', 'DisplayName', '" + displayname + "', 'MarkerSize', 8.0)"
        sindex += 1
        if sindex % len(specifiers) == 0:
            sindex = 0

    print 'xticklabels({', str(all_quarters_ordered)[1:-1] + '})'


def get_statsLibraries_dataset(path_to_folder):

    path_to_families = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder) if os.path.isdir(os.path.join(path_to_folder, f))]
    
    families = {}
    for path_to_family in path_to_families:
        family_name = os.path.basename(path_to_family)
        try:
            stats_family, family_name = get_stats_commonAPIs(path_to_family)
            if not stats_family:
                continue
            families[family_name] = stats_family

        except Exception, e:
            print "Error at ", path_to_family, ":", str(e)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback)    

    good_libs = []
    #path_lib1 = "CommonLibraries-master/libraries/ad_1050.txt"
    #path_lib2 = "CommonLibraries-master/libraries/cl_94.txt"
    path_lib1 = "CommonLibraries-master/libraries/ad_240.txt"
    path_lib2 = "CommonLibraries-master/libraries/cl_61.txt"


    with open(path_lib1, 'r') as libfile:
        good_libs.extend(libfile.read().splitlines())
    libfile.close()
    with open(path_lib2, 'r') as libfile:
        good_libs.extend(libfile.read().splitlines())
    libfile.close()

    num_methods_known_librariy_90 = {}
    num_methods_known_librariy_50 = {}
    num_methods_known_librariy_30 = {}

    for family_name in families:
        stats_family = families[family_name]
        for cRATIO in stats_family:
            for library in stats_family[cRATIO]['libraries']:
                library = library[1:-1].split('$')[0]
                s = library.split('/')
                subpackage_index = 3
                if len(s) < 3: 
                     subpackage_index = len(s) 
                lib_cname = '.'.join(s[:subpackage_index])

                if lib_cname in good_libs:
                    if cRATIO == 90:
                        if family_name not in num_methods_known_librariy_90:
                            num_methods_known_librariy_90[family_name] = 0
                        num_methods_known_librariy_90[family_name] += 1
                    if cRATIO == 50:
                        if family_name not in num_methods_known_librariy_50:
                            num_methods_known_librariy_50[family_name] = 0
                        num_methods_known_librariy_50[family_name] += 1
                    if cRATIO == 30:
                        if family_name not in num_methods_known_librariy_30:
                            num_methods_known_librariy_30[family_name] = 0
                        num_methods_known_librariy_30[family_name] += 1
                    print 'Match', cRATIO, family_name, lib_cname, stats_family[cRATIO]['methods']

    print 'Done'
    print 'num_methods_known_librariy_90 =', num_methods_known_librariy_90
    print 'num_methods_known_librariy_50 =', num_methods_known_librariy_50
    print 'num_methods_known_librariy_40 =', num_methods_known_librariy_40


def get_statsResouces_dataset(path_to_folder):

    path_to_families = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder) if os.path.isdir(os.path.join(path_to_folder, f))]
                 
    # ---- Pool all tasks
    print 'Creating pool with %d processes' % settings.n_procs 
    #print path_to_families   
    pool = multiprocessing.Pool(settings.n_procs) #, maxtasksperchild=100    

    start = default_timer()
    try:
        results = [pool.apply_async(load_resources_family, [path_to_family, 30]) for path_to_family in path_to_families]
    finally:
        pool.close()
        pool.join() 

    map_texec_name = {}
    map_texec_path = {}
    map_texec_bash = {}
    map_elf_name = {}
    map_elf_path = {}
    map_elf_libs = {}
    family_names = []

    for result in results:
        if not result:
            continue
        result = result.get()
        if result and len(result) == 7:
            family_name = result[0]
            tmp_map_texec_name = result[1]
            tmp_map_texec_path = result[2]
            tmp_map_texec_bash = result[3]
            tmp_map_elf_name = result[4]
            tmp_map_elf_path = result[5]
            tmp_map_elf_libs = result[6]

            map_texec_name.update(tmp_map_texec_name)
            map_texec_path.update(tmp_map_texec_path)
            map_texec_bash.update(tmp_map_texec_bash)
            map_elf_name.update(tmp_map_elf_name)
            map_elf_path.update(tmp_map_elf_path)
            map_elf_libs.update(tmp_map_elf_libs)
            family_names.append(family_name)

        else:
            print 'ERROR processing result', result

    print 'map_texec_name = ', map_texec_name   
    print 'map_texec_path = ', map_texec_path   
    print 'map_texec_bash = ', map_texec_bash   
    print 'map_elf_name = '  , map_elf_name   
    print 'map_elf_path = '  , map_elf_path   
    print 'map_elf_libs = '  , map_elf_libs   
    print 'family_names = ', family_names


def preprocessResouces_dataset(path_to_folder):

    path_to_families = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder) if os.path.isdir(os.path.join(path_to_folder, f)) and (hash(f) % settings.distributed_jobs == settings.distributed_machine)]
    
    #random.shuffle(path_to_families) 
    
    size_family = {}
    family_path = {}
    for path_to_family in path_to_families:
        num_samples = len([name for name in os.listdir(path_to_family) if os.path.isfile(os.path.join(path_to_family, name))])
        family_name = os.path.basename(path_to_family)
        size_family[family_name] = num_samples
        family_path[family_name] = path_to_family

    #sorted(size_family.items(), key=lambda samples:samples[1])
    ordered_families = [item[0] for item in sorted(size_family.items(), key=lambda samples:samples[1])]

    for family in ordered_families:
        resources_family(family_path[family])

    # ---- Pool all tasks
    #print 'Creating pool with %d processes' % settings.n_procs    
    #pool = multiprocessing.Pool(settings.n_procs) #, maxtasksperchild=100    
    #try:
    #    results = [pool.apply_async(resources_family, [path_to_family]) for path_to_family in path_to_families]
    #finally:
    #    pool.close()
    #    pool.join()

def get_package_names(path_to_folder):

        package_names = []
        files = os.listdir(path_to_folder)

        family_name = os.path.basename(path_to_folder)

        num_samples = 0
        for f in files:
            num_samples += 1
            path_to_file = os.path.join(path_to_folder, f)
            if path_to_file.endswith('.pickle'):

                apk = None
                with open(path_to_file, "rb") as f:
                    apk = pickle.load(f)
                    f.close()

                #package_names.append(apk.package_name)
                package_names.append(apk.num_libraries)
                
        print '#num_samples: ', family_name, num_samples 
        print family_name, '=', package_names


def case_study(path_to_folder):

    path_to_families = []

    new_in_2017Q1 = [u'aaaaaaadmr', u'ggsot', u'hiddenap', u'dtim', u'opska', u'ehhs', u'ljua', u'aaaaaaadij', u'kyvu', u'teldown', u'aaaaaaadkc', u'syapp', u'gewlc', u'gxofa', u'gxzio', u'ghhig', u'feifanpay', u'dxsozu', u'lustfishingmoney', u'axmda', u'forv', u'ghhin', u'gkkylngzsj', u'ekaddq', u'karr', u'swli', u'raidum', u'axmg', u'dzlewa', u'htfad', u'pgwu', u'axbjg', u'cuxw', u'sexplayer', u'applvin', u'axblj', u'gxaun', u'onyowhwolqd', u'opsk', u'agenty', u'axbnp', u'wtwy', u'hqie', u'cbtopa', u'wohis', u'dnotua', u'egame', u'doudouad', u'extensionmismatch', u'opsl', u'ejacmv', u'aaaaaaadou', u'boogr', u'eiorlc', u'opdda', u'mixi', u'gewpn', u'strealer', u'axbtk', u'cbtfo', u'autosig', u'ggsod', u'gxavw', u'hooj', u'ilulg', u'dutt', u'gewou', u'hatk']
    new_in_2016Q4 = [u'asbol', u'fakeind', u'repack', u'spyforw', u'cuxs', u'asacub', u'dzszvj', u'yiwanshortcut', u'cuaa', u'ewvba', u'rscja', u'gxavg', u'gxauh', u'ggsoj', u'amahzpz', u'noicon', u'ymsdk', u'gxzik', u'gxocr', u'rjzca', u'gxzja', u'dxspgt', u'gdhuq', u'aaaaaaadzt', u'gxzib', u'ggsoa', u'aaaaaaadvj', u'mjsys', u'sockbot', u'aaaaaaaduj', u'gxaty', u'opsqb', u'karaa', u'confopb', u'egddlp', u'pefk', u'gxbxy', u'ajje', u'cobcorm', u'cuxm', u'ajka', u'clarda', u'mfsdo', u'gxzij']
    new_in_2016Q3 = [u'eefjsb', u'tkgfstealinf', u'pokead', u'tscope', u'asmalwrg', u'eenono', u'lotusid', u'mobdown', u'ghhet', u'edqmtx', u'ebryat', u'aaaaaaaddo', u'aaaaaaadkt', u'sysn', u'cwzgqs', u'shedunxd', u'cbtse', u'smsregcw', u'eexeas', u'yimob', u'ebdbsb', u'rgjw', u'sypay', u'edoiuo', u'ghhfi', u'aqcv', u'adpop', u'dyxyrp', u'whitetiger', u'axbgh', u'gxziy', u'akzh', u'axbih', u'cogl', u'sdi', u'eenoik', u'malctvu', u'gxwev', u'efdoao', u'axbia', u'eeiyqz', u'mobilepay', u'juliet', u'axbje', u'fishsms', u'smsbotv', u'axbic', u'losd', u'maskapp', u'dygp', u'cocopush', u'efllbj', u'axbfj', u'eftyqd', u'cbtmga', u'gxoff', u'ghhes', u'qexvmi', u'axvp', u'grti', u'badpkg', u'mobby', u'elfan', u'axbk', u'edlqpg', u'axbcb', u'sxoe', u'vktihs', u'gxatp', u'duju', u'amfy', u'appad', u'adxiaohua', u'ghher', u'hrxi', u'dsteau', u'karg', u'ggske', u'reconyc', u'cbtsia', u'appinvent', u'gxxsa', u'scamad', u'gxweo', u'qlyspy', u'batmob', u'syrr', u'suprangen', u'guiji', u'lirose', u'eeirqa', u'gxaqc', u'activeinject', u'nativemob', u'opdfa', u'eenomz', u'ednx', u'gxatt', u'wplocker', u'gsay', u'gxaql', u'edwbqq', u'gxbxa', u'gfove', u'gxats', u'basser', u'kggydlwbxti', u'axmea', u'finefocusad', u'grse', u'zkhvfxpypf', u'wdse', u'axbrb', u'adwrccd', u'gxpoj', u'airh', u'bxpay', u'dzmthc', u'eeha', u'fakemonitor', u'wurp', u'gxaqs', u'newheur', u'gxofj', u'eenoez', u'ayxd', u'auga', u'ajbc', u'obad', u'hytu', u'gxyyk', u'ahel', u'cbteg', u'mmvideo', u'gxoen', u'lockad', u'browback', u'jpay', u'tgpush', u'fishingmoneygame', u'syhp', u'socksbot', u'gxaqy', u'edojaa', u'gxoyu', u'forav', u'smssnow', u'ebri', u'najin', u'gxato', u'gmkif', u'aowl', u'damaopush', u'hsja', u'mgyunroot', u'shuame', u'cnil', u'vemnotiba', u'zhibispy', u'mimdage', u'boyad', u'penghucn', u'coab', u'adkh', u'ghhfy', u'egijft', u'chfi', u'htvo', u'dzomnz', u'soulra', u'smsregzi', u'axbda', u'axmxk', u'mailstealer', u'ulpm', u'athi', u'juhestealer', u'gxxqo', u'gxwef', u'gewld', u'sysservice', u'gxpov', u'grir', u'rootmoni', u'gxwmy', u'modou', u'edmnpm', u'gxpri', u'cbtrda', u'binka', u'vnoktak', u'kkplugin', u'anzr', u'aaaaaaadtt', u'shelad', u'gxaqi', u'gxapn', u'gxauy', u'cbtvka', u'iapppay', u'agke', u'gxoeg', u'ghhev', u'gxwiz', u'flightad', u'gxaqq', u'hupc', u'axbaa', u'gxbxi', u'ebqk', u'madvertise', u'clgy', u'gfovg', u'ebqf', u'senter', u'wvum', u'gxwku', u'smsroot', u'edwcgp', u'vxys', u'jwsdnjzooc', u'gxapm', u'gxauw', u'wwed', u'gxatv', u'axbvd', u'usiahqemevm', u'cbtep', u'cbtot', u'dkmmzp', u'fadeb', u'atvx', u'genericad', u'yuyou', u'axbwh', u'contactstealer', u'ednp', u'gluper', u'epay', u'swal', u'ddlions', u'redtubesex', u'aveasms', u'opdd', u'cbtne', u'bankleak', u'drguau', u'axbva', u'axmla', u'shelma', u'dkfzbd', u'ecede', u'loadbanad', u'softguide', u'egikbb', u'tekown', u'dyfx', u'ehro', u'gxzko', u'gxzla', u'ejpe', u'gxzhi', u'applesrv', u'showvideo', u'gxxug', u'axbp', u'gxzim', u'axbmb', u'gxytf', u'sisnit', u'ssarpovy', u'gewlq', u'cbtpca', u'imgpad', u'wozm', u'cbtiy', u'acua', u'gxzih', u'axbbj', u'efkl', u'eeem', u'oyos', u'amcu', u'botpanda', u'cpru', u'fishingmoneyapp', u'aaaaaafc', u'ammobi', u'gxxra', u'dzbmbt', u'cbtfa', u'ansupv', u'faldr', u'slockerhv', u'efun', u'gxpku', u'sipush', u'gxapb', u'gxozd', u'gqhu', u'gxoer', u'dncxpv', u'afoynq', u'cbtyf', u'swut', u'efky', u'sogps', u'syrz', u'unionpay', u'gndownld', u'offcamp', u'ahod', u'plugingame', u'wrqp', u'aotc', u'gxapu', u'gxapp', u'ackn', u'appfour', u'hnla', u'sndrjqqgzbb', u'gxocj', u'unionsy', u'dzto', u'bloodzob', u'tayv', u'floatad', u'axbpb', u'eamm', u'scriptpe', u'phgu', u'gxyyj', u'shastro', u'gxauk', u'ecjr', u'andcore', u'gxwfa', u'ajlv', u'gnzdi', u'ahyc', u'dvzu', u'gfovn', u'cbttha', u'axbuj', u'sxeb', u'eaxwri', u'gxocx', u'eextra', u'dyds', u'gxate', u'ggdpo', u'fakhdvido', u'rontkbr', u'bayimob', u'axboj', u'dmhpeu', u'gxwee', u'gxyyo', u'yawagent', u'hool', u'gxbop', u'gewla', u'apay', u'ebht', u'pefv', u'gxwea', u'cbtmia', u'adinfo', u'jopsik', u'gxzee', u'agbl', u'akfo', u'gectams', u'gxwek', u'pfad', u'axbhg', u'gmkii', u'angc', u'monst', u'ehhw', u'kuurnn', u'congur', u'eeirgm', u'pgdo']
    new_in_2016Q2 = [u'asscpth', u'ecfqay', u'inazigram', u'ebfzeh', u'bbax', u'edurun', u'bawb', u'delayload', u'mmbilling', u'sodsack', u'edurqu', u'ebfyze', u'repacked', u'finefocus', u'edurvj', u'gxxue', u'gxxuk', u'gxxud', u'tatic', u'gxoyy', u'avagent', u'edlqpq', u'gxath', u'kalfere', u'igamo', u'snailcut', u'yangmei', u'gxweb', u'gxxqa', u'arpush', u'ebypje', u'regdev', u'unofficialapp', u'floatgame', u'nisemono', u'edkalv', u'gxxui', u'pavq', u'isoa', u'gxaqz', u'ebgx', u'ysapk', u'ctfa', u'atsx', u'badjoke', u'lovefraud', u'adiwky', u'ageneric', u'gxapw', u'becou', u'axbfc', u'gxaou', u'gxaor', u'ijiami', u'azload', u'gxwdo', u'hypay', u'gxaov', u'cmhkug', u'grsa', u'gxwen', u'hiddenad', u'edlqqq', u'recoms', u'gibdy', u'gxatn', u'gxatg', u'gxatl', u'aliyuncs', u'razy', u'genericbludger', u'gxlyr', u'edhnrs', u'hmad', u'nestedobj', u'amfr', u'hrys', u'feiwodown', u'egamefee', u'szva', u'datouniao', u'grsy', u'gxxuj', u'ecdlow', u'ebcsox', u'gxxum', u'objectdata', u'axen', u'mobiad', u'leapp', u'loodos', u'msbgion', u'oveead', u'aycm', u'gxwfe', u'gxaot', u'bbie', u'gxwel', u'atmp', u'opsa', u'systeen', u'gxasd', u'cata', u'efkk', u'ebbkqa', u'btcmine', u'gxxqe', u'adleak', u'gxxun', u'flexleak', u'altcha', u'gorv', u'lnep', u'txprotect', u'cqih', u'ebcsfj', u'gxxuo', u'cliy', u'ecdlqx', u'hideicon', u'uzcore', u'gxxul', u'gxxqy', u'aswb', u'gxarz', u'vnsexy', u'amfe', u'gxxup', u'gxapl', u'xmad', u'atqr', u'bayy', u'sysupldate', u'ckym', u'wbna', u'batad', u'adviator', u'remotescript', u'gxaio', u'adwtb', u'inmob', u'pidief', u'hoxn', u'qbbe', u'edurpm', u'coyo', u'ebsamp', u'loaderpsuh', u'adnfoo', u'vnetone', u'gidleak', u'wifiservice', u'cwsi', u'gxatm', u'axbab', u'bemx', u'ebfyzk', u'pornclicker', u'gxapf', u'efbb', u'atsd', u'ebitlv', u'gxwic', u'augs', u'caoweb', u'asonic', u'gxajw', u'ebcseb', u'gxzci', u'hqwar', u'gxass', u'fakflashnom', u'gxxoi', u'axmn', u'usafea', u'asgb', u'gxapy', u'vkpass', u'awof', u'cbtba', u'toorch', u'gxapo', u'gxatz', u'teslacrypt', u'daikuan', u'atdj', u'gxaoq', u'avpass', u'commname', u'axbhc', u'dnqbxr', u'axbo', u'ajch', u'loki', u'andgalaxy', u'axbpa', u'penepes', u'gxwiy', u'forgonal', u'dzxghk', u'mimob', u'gxarv', u'gxata', u'atlc', u'cboa', u'hbtsa', u'gxzed', u'eatijn', u'gxatj', u'awfd', u'hzdo', u'gxapc', u'axbeb', u'kortalk', u'katrep', u'flur', u'eers', u'gxajy', u'zzcollector', u'simpletemai', u'axblb', u'gxzgy', u'grsi', u'gxatk', u'abloshec', u'megall', u'gxasr', u'gxxon', u'adpay', u'azdn', u'dzmtcw', u'civb', u'hola', u'gxwha', u'gxzel', u'gxati', u'brzy', u'iqiad', u'notifad', u'usafe', u'chuc', u'gxaij', u'gxwep', u'dqzqyv', u'akov', u'cleo', u'eatxlg', u'smsreghq', u'triangleroot', u'pfji', u'originxz', u'aues', u'avos', u'untrusteddev', u'yekrand', u'gxzha', u'cbtgba', u'gxoye', u'szvy', u'gxzeg', u'sexpay', u'gxoyf', u'fidmyc', u'lqfa', u'goodyes', u'gxast', u'getcode', u'asyw', u'misopen', u'gxaqf', u'gruo', u'eckl', u'auda', u'instapp', u'cunk', u'axbac', u'dqcbbh', u'amwl', u'gxxuc', u'ngen', u'glodream', u'aalz', u'akyn', u'gxapx', u'axbfa', u'buic', u'gxapj', u'adgnum', u'flyjule', u'daoyoudao', u'skynet', u'sopes', u'grte', u'abpn', u'gxzgo', u'gxwfu', u'gxapk', u'dollrooter', u'gxask', u'gxzem', u'axbsa', u'dpaijr', u'gxxua', u'avrr']

    new = []
    new.extend(new_in_2017Q1)
    new.extend(new_in_2016Q4)
    new.extend(new_in_2016Q3)
    new.extend(new_in_2016Q2)

    top_largest = ['jiagu', 'dowgin', 'artemis', 'revmob', 'youmi', 'kuguo', 'adwo', 'airpush', 'leadbolt', 'droidkungfu']
    top_prevalent = ['hippo',  'jsmshider', 'basebridge', 'fakeflash', 'safekidzone', 'ginmaster', 'plankton', 'rooter', 'gpspy', 'golddream']
    top_viral = ['spyforw',  'genpua', 'deng', 'appsgeyser', 'utchi', 'anydown', 'admobads', 'startapp', 'admogo', 'wapsx']
    top_stealthy = ['lockad',  'kazy', 'pirates', 'jumptapiads', 'skymobi', 'revmobads', 'viser', 'malform', 'vdloader', 'waps']

    top = []
    top.extend(top_largest)
    top.extend(top_prevalent)
    top.extend(top_viral)
    top.extend(top_stealthy)


    
    others = ['kazy', 'pirates'] 
    ransomeware = ['jisut', 'simplocker', 'slocker', 'gepew', 'svpeng', 'artemis']
    #gen and many others ending in locker
    

    ##### !!!!! 
    #all_cases = []
    #all_cases.extend(new)
    #all_cases.extend(top)
    #settings.intermediate_results = '/data1/gtangil/AndroidMeasurements_intermediate_results_newAPIs'
    #preprocess_selectedfamilies('/data1/gtangil/AndroZoo', all_cases) # new all_cases
    ##### !!!!! 

    keeptrack = False
    if '_newAPIs' in path_to_folder:
        keeptrack = True

    print ':::::::: LATEST :::::::'
    for family in new:
        print 'preparing case_study for:', family
        path_to_family = os.path.join(path_to_folder, family)
        path_to_families.append(path_to_family)
        try:
            postprocess_family(path_to_family, True, keeptrack)
        except OSError, e:
            print 'Skipping FamilyNotFound', family
        except Exception, e:
            print 'Skipping UnknownError', family
            print e

    print ':::::::: TOP ::::::::::'
    for family in top:
        print 'preparing case_study for:', family
        path_to_family = os.path.join(path_to_folder, family)
        path_to_families.append(path_to_family)
        try:
            postprocess_family(path_to_family, True, keeptrack)
        except Exception, e:
            print 'Skipping UnknownError', family
            print e

    print ':::::::: RANSOMEWARE ::::::::::'
    for family in ransomeware:
        print 'preparing case_study for:', family
        path_to_family = os.path.join(path_to_folder, family)
        path_to_families.append(path_to_family)
        try:
            postprocess_family(path_to_family, True, keeptrack)
        except Exception, e:
            print 'Skipping UnknownError', family
            print e

    print ':::::::: OTHERS ::::::::::'
    for family in others:
        print 'preparing case_study for:', family
        path_to_family = os.path.join(path_to_folder, family)
        path_to_families.append(path_to_family)
        try:
            postprocess_family(path_to_family, True, keeptrack)
        except Exception, e:
            print 'Skipping UnknownError', family
            print e
    #try:
    #    results = [pool.apply_async(postprocess_family, [path_to_family, True]) for path_to_family in path_to_families]
    #finally:
    #    pool.close()
    #    pool.join()

def cont_progress():

    path_to_family = []
    samples_old = {}
    samples_new = {}
    intres_old = '/data/gtangil/AndroidMeasurements_intermediate_results/'
    intres_new = '/data/gtangil/AndroidMeasurements_intermediate_results_newAPIs/'
    for family_name in os.listdir(intres_old): 
        if family_name in blacklist_families:
            continue
        if '.pickle' in family_name:
            continue
        path_to_family_old = os.path.join(intres_old, family_name)
        path_to_family_new = os.path.join(intres_new, family_name)
        if os.path.isdir(path_to_family_old):
            num_samples = len(os.listdir(path_to_family_old))
            if num_samples < 7:
                continue
            samples_old[family_name] = num_samples
        else:
            samples_old[family_name] = 0
            continue
        if os.path.isdir(path_to_family_new):
            samples_new[family_name] = len(os.listdir(path_to_family_new))
        else:
            samples_new[family_name] = 0
        if samples_new[family_name] >= samples_old[family_name]:
            if (hash(family_name) % settings.distributed_jobs == settings.distributed_machine):
                path_to_family.append(path_to_family_new)
        print family_name, float(samples_old[family_name] - samples_new[family_name])/samples_old[family_name]*100
    print 'samples_old =', samples_old
    print 'samples_new =', samples_new
    incomplete_families = {}
    missing_samples = {}
    complete_families = []
    for family_name in samples_old.keys():
        if samples_old[family_name] == samples_new[family_name]:
            complete_families.append(family_name)
        else:
            incomplete_families[family_name] = 100 - float(samples_old[family_name] - samples_new[family_name])/samples_old[family_name]*100
            missing_samples[family_name] = samples_old[family_name] - samples_new[family_name]
    print 'missing_samples =', missing_samples
    print 'incomplete_families = ', incomplete_families
    print 'num_complete_families =', len(complete_families)
    print 'num_incomplete_families =', len(incomplete_families)

    return path_to_family



def count_methods_per_family(path_to_folder, keeptrack=False):

    start = default_timer() 

    track_keyword = ''
    if keeptrack:
        track_keyword = '_withsamples'

    index = os.path.abspath(path_to_folder) + track_keyword + '.pickle'
    methods, seen_apps, num_samples, common_hashes_with_sensitiveAPIs, numApps_seen_method, numApps_seen_method_with_sensitiveAPIs, numApps_seen_method_with_sensitiveTAGs, common_hashes_with_sensitiveTAGs = load_index_if_available(index)

    family_name = os.path.basename(path_to_folder)
    num_methods = len(methods)
    print family_name, num_methods, num_samples

    return family_name, num_methods, num_samples


def count_methods(path_to_folder):

    path_to_families = [os.path.join(path_to_folder, f) for f in os.listdir(path_to_folder) if (os.path.isdir(os.path.join(path_to_folder, f)) and not os.path.basename(os.path.join(path_to_folder, f)) in blacklist_families)]

    # ---- Pool all tasks
    print 'Creating pool with %d processes' % settings.n_procs    
    pool = multiprocessing.Pool(settings.n_procs) #, maxtasksperchild=100    

    try:
        results = [pool.apply_async(count_methods_per_family, [path_to_family]) for path_to_family in path_to_families]
    finally:
        pool.close()
        pool.join()

    all_num_methods = 0
    all_num_samples = 0

    # ---- Process all results
    for result in results:
        result = result.get()
        if result and len(result) == 3:
            family_name = result[0]
            num_methods = result[1]
            num_samples = result[2]

            all_num_methods += num_methods
            all_num_samples += num_samples

        else:
            print 'ERROR processing result', result

    print 'all_num_methods = ', all_num_methods
    print 'all_num_samples = ', all_num_samples


def main(options, arguments) :

    if options.preprocess != None :

        preprocess_directory(options.preprocess)

    elif options.postprocess != None :

        postprocess_dataset(options.postprocess) #postprocess_directory(options.postprocess) #postprocess_directory_paralell(options.postprocess)

    elif options.timeline != None :

        get_timeline_dataset(options.timeline)

    elif options.stats != None :

        get_statsDetections_dataset(options.stats)
        sys.exit()

        #get_statsTop10_dataset(options.stats)
        get_statsCommonAPIs_dataset(options.stats)
        #get_statsCommonAPIs_dataset(options.stats, False)
        #get_statsCommonMethods_dataset(options.stats)

    elif options.libraries != None :

        get_statsLibraries_dataset(options.libraries)

    elif options.resources != None :

        preprocessResouces_dataset(options.resources)

    elif options.resourcesstats != None :

        get_statsResouces_dataset(options.resourcesstats)

    elif options.casestudy != None :

        case_study(options.casestudy)

    elif options.debug != None :
        data = {}
        methods = {} 
        seen_apps = {}

        #preprocess_one_file_batch('/data1/gtangil/AndroZoo/dowgin/A5EAA8333C1B1EEB1D5BC3AAC4BE40EBE384D3C134B14113EA14AE6515E01F40.apk', 'dowgin')
        #preprocess_one_file_batch('/data1/gtangil/AndroZoo/drpxhi/FDD9E021D3F8774742965D518DE362BB1608A86D366FDF9D16296182FADA8A7B.apk', 'drpxhi')
        #preprocess_one_file_batch('Malgenome1/ADRD/f4fc04c1e1566c80875160236641cd5b84f7da57.apk', 'ADRD')
        #preprocess_one_file_batch('APKTest/stegomalware/DexLoadTest-Stegomalware.apk', 'stegomalware')
        #postprocess_one_apk('intermediate_results/stegomalware/DexLoadTest-Stegomalware.apk.pickle', 'stegomalware', methods, seen_apps)
        
        #preprocess_one_file_batch('APKTest/nativeJNI/app-debug.apk', 'nativeJNI')
        #postprocess_one_apk('intermediate_results/nativeJNI/app-debug.apk.pickle', 'stegomalware', methods, seen_apps)
        
        #postprocess_one_file_batch('intermediate_results/BaseBridge/fdef4f92752421baa1b5d18dfa6ebbd6a71fb10c.apk.pickle', 'BaseBridge')
        #postprocess_one_apk('intermediate_results/baiduads/57E1F268DFAD891723A4508B6156C0C4F9A0E7FBB08848BE4915E748597E3AFB.apk.pickle', 'baiduads')
        #postprocess_family('intermediate_results/droidkungfu')
        postprocess_family('/data1/gtangil/AndroidMeasurements_intermediate_results_AllMethods_WtProto/lockad')
        #postprocess_family('/data/gtangil/AndroidMeasurements_intermediate_results_newAPIs/spyforw')
        
        #for seen_hash in methods:
        #    method = methods[seen_hash]
        #    print str(method.class_name) + '.' + str(method.name)
        #    print '\t TAGs =', method.tags
        #    print '\t APIs =', method.sensitive_APIs
        #print seen_apps

        #test_inter_app_similarity('intermediate_results/baiduads/F0AA5BE411C5772E03D375488AE61EA6805A743139F66FB6EBD04F03168B0E82.apk.pickle', 'baiduads')
        #get_stats_family('intermediate_results/droidkungfu')
        
        #top_methods, seen_hashes_top_methods = get_top_methods('intermediate_results/droidkungfu')

        #postprocess_family('/data1/gtangil/AndroidMeasurements_intermediate_results/goodware-play.google.com')
        
        #resources_family('APKTest/nativeJNI')
        #resources_family('/data/gtangil/AndroZoo/airpus')
        #print get_stats_family_commonMethods('/data1/gtangil/AndroidMeasurements_intermediate_results/airpus')
        #print get_package_names('/data/gtangil/AndroidMeasurements_intermediate_results/wpredirect')
        #print get_package_names('/data/gtangil/AndroidMeasurements_intermediate_results/tucysms')
        #print get_package_names('/data/gtangil/AndroidMeasurements_intermediate_results/taocall')
        #print get_package_names('/data/gtangil/AndroidMeasurements_intermediate_results/mobisec')
        #print get_package_names('/data/gtangil/AndroidMeasurements_intermediate_results/malmix')
        #print get_package_names('/data/gtangil/AndroidMeasurements_intermediate_results/luahcad')
        #print get_package_names('/data/gtangil/AndroidMeasurements_intermediate_results/gxwbo')


        #print get_package_names('/data/gtangil/AndroidMeasurements_intermediate_results/hiddenap')
        #get_stats_family('/data/gtangil/AndroidMeasurements_intermediate_results/hiddenap')
        #print get_stats_commonAPIs('/data/gtangil/AndroidMeasurements_intermediate_results/hiddenap')

        #print get_package_names('/data/gtangil/AndroidMeasurements_intermediate_results/ggsot')
        #get_stats_family('/data/gtangil/AndroidMeasurements_intermediate_results/ggsot')
        #print get_stats_commonAPIs('/data/gtangil/AndroidMeasurements_intermediate_results/ggsot')

        #postprocess_family('intermediate_results_extended/baiduads', True, False)


        #postprocess_family('/data/gtangil/AndroidMeasurements_intermediate_results/simplocker', verbose=True, keeptrack=True)
        #postprocess_family('/data/gtangil/AndroidMeasurements_intermediate_results/hiddenap', keeptrack=True)

        #parse_elf(open('intermediate_resources_results/nativeJNI/51fb6de8a0d31ebfb72181d52c32348b-lib.x86.libpassword.so').read(), data)
        #print data

        #resources_family('/data1/gtangil/AndroZoo/droidrooter')
        #load_resources_family('/data1/gtangil/AndroidMeasurements_resources_results/simplocker', 90)
        #load_resources_family('/data1/gtangil/AndroidMeasurements_resources_results/hiddenap', 90)
        #load_resources_family('/data1/gtangil/AndroidMeasurements_resources_results/droidrooter', 90)
        #load_resources_family('/data1/gtangil/AndroidMeasurements_resources_results/callflakes', 90)

        #print resources_one_file('/data1/gtangil/AndroZoo/dowgin/A5EAA8333C1B1EEB1D5BC3AAC4BE40EBE384D3C134B14113EA14AE6515E01F40.apk', 'dowgin')

        #get_statsResouces_dataset('/data/gtangil/AndroidMeasurements_resources_results')

        #get_statsCommonAPIs_dataset('intermediate_results', False)

        #resume = 88500 #None
        #top_methods, seen_hashes_top_methods = get_top_methods('/data1/gtangil/AndroidMeasurements_intermediate_results/goodware-play.google.com', resume)
        #top_methods, seen_hashes_top_methods = get_top_methods('/data1/gtangil/AndroidMeasurements_intermediate_results/dowgin')
        #print seen_hashes_top_methods

        #path_to_families = cont_progress()
        ## ---- Pool all tasks
        #print 'Creating pool with %d processes' % settings.n_procs    
        #pool = multiprocessing.Pool(settings.n_procs) #, maxtasksperchild=100    
        #start = default_timer()
        #try:
        #    results = [pool.apply_async(postprocess_family, [path_to_family, False, True]) for path_to_family in path_to_families]
        #finally:
        #    pool.close()
        #    pool.join()

        #count_methods('/data/gtangil/AndroidMeasurements_intermediate_results')



    elif options.version != None :
        print "Androsim version %s" % androconf.ANDROGUARD_VERSION


if __name__ == "__main__" :
    parser = OptionParser()
    for option in options :
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)

    options, arguments = parser.parse_args()
    sys.argv[:] = arguments
    main(options, arguments)