#!/usr/local/bin/python3
########################################################################
# Project           : Radare stuff
# Program name      : agx_depth.py
# Author            : Abraham Pasamar @apasamar
# Date created      : 20190113
# Purpose           : Print agx (Cross references graph) with 2 caller levels
# Revision History  :
# Date        Author      Ref    Revision (Date in YYYYMMDD format) 
# 
########################################################################

# Usage: agx_depth.py <binary> <address>
# prints agx (cross reference graph) with 2 caller levels

import r2pipe
import sys
file=sys.argv[1]
addr=sys.argv[2]

def get_xrefs_from_afi_json(result):
  list=[]
  for item in result[0]["codexrefs"]:
    if item["type"]=="C":
  	  list.append("{0:#0{1}x}".format(item["addr"],10))
  return list

#main
r2 = r2pipe.open(file)
result=r2.cmd('aaa')
result=r2.cmdj('afij '+addr)
list=get_xrefs_from_afi_json(result)

result=r2.cmd('s '+addr)
result=r2.cmd('agx')

for c_addr in list:
	result=r2.cmdj('afij '+c_addr)
	list=get_xrefs_from_afi_json(result)
	for item in list:
		result=r2.cmd('agn '+item)
		result=r2.cmd('age '+item+' '+c_addr)
		result=r2.cmd('agg')

result=r2.cmd('agg')
print(result)