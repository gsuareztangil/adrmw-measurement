# adrmw-measurement

This repository holds resources used for the paper titled [Eight Years of Rider Measurement in the Android Malware Ecosystem: Evolution and Lessons Learned](https://arxiv.org/abs/1801.08115). 


If you make use of these resources, please cite the aforementioned paper. 


### Code

Follow the instructions here: https://code.google.com/p/pythonxy/
 
The steps are as follows:
 
```sh
cd ~/Downloads/

wget http://python.org/ftp/python/2.7.11/Python-2.7.11.tgz

tar -xvf Python-2.7.11.tgz

cd Python-2.7.11

./configure

make

sudo make install
```
 
 
Other dependencies
--------------
 
```sh
sudo apt-get install python-imaging

sudo apt-get install python-magic

sudo apt-get install imagemagick

### Data

The data used to run this measurement can be obtained from [AndroZoo](https://androzoo.uni.lu/).

### Explanatory

For an excerpt of the type of output return by our framework with a subset of the popular malgenome project [Malgenome](results/explanatory_Malgenome.txt). 
We refer to [this blog] post for a high-level understanding of what some of the families do (https://forensics.spreitzenbarth.de/android-malware/).

We also provide a full trace for the following ransomware family used in our case study: [Lockad](results/stats_caseStudy90newAPIs-lockad.txt). 

Note: we are currently updating this repository, stay tunned for more stuff!