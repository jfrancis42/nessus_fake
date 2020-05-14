#!/usr/bin/python3

import requests
import json
import random
import os
import xmltodict
import time

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Classes
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

# This class holds PCE credentials.
class Creds:
  def __init__(self, login, passwd, pce, port, org, real):
    self.login = login
    self.passwd = passwd
    self.pce = pce
    self.port = port
    self.org = org
    self.real = real
    
  # Return a string with no org_id for use as a base URL.
  def url(self):
    return("https://"+self.login+":"+self.passwd+"@"+self.pce+":"+str(self.port)+"/api/v2/")

  # Return a string including org_id for use as a base URL.
  def urlorg(self):
    return("https://"+self.login+":"+self.passwd+"@"+self.pce+":"+str(self.port)+"/api/v2/"+"orgs/"+str(self.org)+"/")

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Functions
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

# Make a synchronous API call to the PCE. crud must be one of "get",
# "put", "post", or "delete". endpoint is appended to the end of the
# creds.url() to point to the desired REST resource, org is True or
# False (some API endpoints want the org_id, some don't), and payload
# is the optional payload (only useful for "put" and "post"). The
# payload should be a python dictionary. It's automatically converted
# to json by the requests library call. This call returns the JSON
# result of the call, or False (if the call fails for any
# reason). Note that a sync API call in Illumio returns only the first
# 500 items. If you have more than 500 Workloads, for example, you'll
# need to re-write this as an async API call (exercise left to the
# reader).
def sync_pce_api(creds,crud,endpoint,org,payload):
  assert(crud=="get" or crud=="put" or crud=="post" or crud=="delete")
  if(org):
    url=creds.urlorg()+endpoint
  else:
    url=creds.url()+endpoint
  if(crud=="get"):
    r=requests.get(url,auth=(creds.login,creds.passwd),verify=creds.real)
  elif(crud=="put"):
    if payload:
      r=requests.put(url,json=payload,auth=(creds.login,creds.passwd),verify=creds.real)
    else:
      r=requests.put(url,auth=(creds.login,creds.passwd),verify=creds.real)
  elif(crud=="post"):
    if payload:
      r=requests.post(url,json=payload,auth=(creds.login,creds.passwd),verify=creds.real)
    else:
      r=requests.post(url,auth=(creds.login,creds.passwd),verify=creds.real)
  elif(crud=="delete"):
    r=requests.delete(url,auth=(creds.login,creds.passwd),verify=creds.real)
  if(r.status_code==200):
    return(json.loads(r.text))
  else:
    return(False)
    
# Make an asynchronous API call to the PCE. Same as sync_pce_api,
# except much slower (ie, only use when required) and will return all
# (not just the first 500) results from a GET.
def async_pce_api(creds,crud,endpoint,org,payload):
  assert(crud=="get" or crud=="put" or crud=="post" or crud=="delete")
  if(org):
    url=creds.urlorg()+endpoint
  else:
    url=creds.url()+endpoint
  if(crud=="get"):
    r=requests.get(url,auth=(creds.login,creds.passwd),verify=creds.real,headers={'Prefer': 'respond-async'})
  elif(crud=="put"):
    if payload:
      r=requests.put(url,json=payload,auth=(creds.login,creds.passwd),verify=creds.real)
    else:
      r=requests.put(url,auth=(creds.login,creds.passwd),verify=creds.real)
  elif(crud=="post"):
    if payload:
      r=requests.post(url,json=payload,auth=(creds.login,creds.passwd),verify=creds.real)
    else:
      r=requests.post(url,auth=(creds.login,creds.passwd),verify=creds.real)
  elif(crud=="delete"):
    r=requests.delete(url,auth=(creds.login,creds.passwd),verify=creds.real)
  if(r.status_code==202):
    time.sleep(int(r.headers['Retry-After']))
    monitor_url=r.headers['Location']
    status=""
    while(status!="done" and status!="failed"):
      r=sync_pce_api(creds,"get",monitor_url,False,False)
      status=r['status']
      if(status!="done" and status!="failed"):
        time.sleep(1)
    return(sync_pce_api(creds,"get",r["result"]["href"],False,False))
  else:
    return(False)
    
def get_os(hp):
  os=False
  for h in hp:
    if('@name' in h.keys()):
      if(h['@name']=="os"):
        os=h['#text']
  return(os)

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Load credentials from the file.
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

# Read the API key info from the file APIKEY.json in the current
# directory.
with open('APIKEY.json') as f:
  apikey=json.load(f)

max_vulns=apikey['max_vulns']
report_name=apikey['report_name']
out_file=apikey['output_file']
sample_dir=apikey['samples']

# Create a Creds object for use later.
creds=Creds(apikey['auth_username'],apikey['secret'],apikey['pce'],
            apikey['port'],apikey['org'],apikey['self_signed'])

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Pull the ReportItems from the supplied Nessus reports.
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
reportitems={}
nessus=os.listdir(sample_dir)
print("Loading Nessus scan files...")
for n in nessus:
  print("Loading " + n + "...")
  with open(sample_dir + n,"r") as f:
    doc=xmltodict.parse(f.read())
    for rh in doc['NessusClientData_v2']['Report']['ReportHost']:
      os=get_os(rh['HostProperties']['tag'])
      for ri in rh['ReportItem']:
        if(os not in reportitems.keys()):
          reportitems[os]=[]
        reportitems[os].append({'ReportItem':ri})

print()
for k in reportitems.keys():
  print(k + ": ", len(reportitems[k]))

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Go fetch all the workloads, then extract the addresses of all
# network interfaces.
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
print()
print("Fetching IP info from PCE...")
print()
workloads=async_pce_api(creds,"get","/workloads",True,False)
ips=[]
for wl in workloads:
  for iface in wl['interfaces']:
    ips.append(iface['address'])

# De-duplicate the IP list and remove all of the IPv6 addresses.
ips=list(filter(lambda ip: (ip.find(':')<0),(set(ips))))

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Assemble a fake Qualys vuln report.
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
print("Writing fake nessus scan file...")
print()
with open(out_file,"wt") as f:
  print("<?xml version=\"1.0\" ?>", file=f)
  print("<NessusClientData_v2>", file=f)
  print("<Report name=\"" + report_name + "\" xmlns:cm=\"http://www.nessus.org/cm\">", file=f)
  for ip in ips:
    os=random.randint(0,len(reportitems.keys())-1)
    os_name=list(reportitems.keys())[os]
    print("<ReportHost name=\"" + ip + "\"><HostProperties>", file=f)
    print("<tag name=\"os\">" + os_name + "</tag>", file=f)
    print("<tag name=\"host-ip\">" + ip + "</tag>", file=f)
    print("</HostProperties>", file=f)
    for vuln in range(random.randint(0,max_vulns)):
      print(xmltodict.unparse(reportitems[os_name][random.randint(0,len(reportitems[os_name])-1)],
                              full_document=False), file=f)
    print("</ReportHost>", file=f)
  print("</Report>", file=f)
  print("</NessusClientData_v2>", file=f)
print("Done")
