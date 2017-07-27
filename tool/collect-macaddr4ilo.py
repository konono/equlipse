#!/usr/bin/python

import pexpect
import re
import sys
from optparse import OptionParser

macs=[]
err=0

op=OptionParser("collect-macaddr4ilo [options] ip")
op.add_option("-l","--log",action="store_true",dest="log",default=False,help="whole logs to stdout")
op.add_option("-u","--user",action="store",dest="user",type="string",default=False,help="access user name")
op.add_option("-p","--password",action="store",dest="password",type="string",default=False,help="access user password")
(ops,ip)=op.parse_args()
if len(ip)!=1 or ops.user==False or ops.password==False :
  op.print_help()
  exit(1)

px=pexpect.spawn("ssh "+ ops.user + "@" +ip[0])
if ops.log==True:
  px.logfile_read=sys.stdout
px.expect("password: ")
px.send(ops.password + "\n")
px.expect("-\> ")
px.send("show /system1/network1/Integrated_NICs\r")
px.expect("-\> ")

for res in px.before.split("\n"):
  m=re.search("Port[0-9]NIC.*",res)
  if m:
    macs.append(m.group())

px.send("exit\r")
px.expect(pexpect.EOF)
if err==0:
  for i in macs:
      print i
else:
  print "ERROR"

