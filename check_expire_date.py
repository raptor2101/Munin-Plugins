#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (C) 2010  Raptor 2101 [raptor2101@gmx.de]
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from datetime import datetime;
import sys,os,re;
from subprocess import Popen
from subprocess import PIPE
openssl = "/usr/bin/openssl"

plugin_name=list(os.path.split(sys.argv[0]))[1];

path = os.environ['path']
#+certFiles = [certFile for certFile in os.listdir(path) if os.path.isfile(certFile)]
certFiles = os.listdir(path)

if len(sys.argv)>1 and sys.argv[1]=="config":
  print "graph_title Cert Expiration";
  print "graph_args --base 1000";
  print "graph_vlabel Valid Days";
  print "graph_category security";
  config = 1;
else:
  config = 0;
  
for certFile in certFiles:
  munin_name = certFile.replace(".","_");

  if(config):
    print "%s.label %s"%(munin_name,certFile);
    print "%s.type GAUGE"%(munin_name);
    print "%s.warning 5:"%(munin_name);
    print "%s.critical 2:"%(munin_name);
  else:
    filePath = os.path.join(path,certFile);
    commandOutput = Popen([openssl, "x509", "-in", filePath, "-noout", "-enddate"],stdout=PIPE).communicate()[0]

    match = re.search(r'\w{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4} \w{3}', commandOutput)
    date = datetime.strptime(match.group(),'%b %d %H:%M:%S %Y %Z').date()
    dateDiff = date-datetime.today().date();
    print "%s.value %d"%(munin_name,dateDiff.days);
