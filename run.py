#!/usr/local/bin/python3

from subprocess import Popen, PIPE, call, DEVNULL
import json
import sys

domain = sys.argv[1]
ports = sys.argv[2]

call(['nikto.pl', '-Display', 'V', '-o', 'results.csv',
      '-Format', 'csv', '-C', 'all', '-h', domain, '-p', ports], stdout=DEVNULL)

p = Popen(['cat', 'results.csv'],
          stdout=PIPE, stderr=PIPE)
out, err = p.communicate()
result = out.decode("utf-8").split('\n')

vulns = []
for res in result:
    if 'Nikto' in res or len(res) < 7:
        continue
    vuln = res.split(',')
    vulnFiltered = (list(map(lambda x: x.replace('"', ''), vuln)))
    if vulnFiltered[3] == '':
        continue
    vulns.append({'title': vulnFiltered[6].split('.')[0],
                  'description': "".join(vulnFiltered[6:]),
                  'status': 'Medium',
                  'solution': '',
                  'tool': 'Nikto',
                  'group': 'Website Security Results'
                  })

print(json.dumps(vulns))
