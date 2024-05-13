#!/bin/bash

# Fetch ilo3 from HP website
wget https://downloads.hpe.com/pub/softlib2/software1/sc-linux-fw-ilo/p1255562964/v64722/CP014002.scexe 

# Extract archive file from executable script, used binwalk to figure out offset
dd if=CP014002.scexe of=ilo3.tgz bs=32 skip=269

# Extract flash image from archive file
tar -xzvf ilo3.tgz ilo3_120.bin
