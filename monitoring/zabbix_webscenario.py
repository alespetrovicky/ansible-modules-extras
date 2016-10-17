#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, Servernamiru.cz
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.
#

DOCUMENTATION = '''
---
module: zabbix_webscenario
short_description: Zabbix web scenario creates/updates/deletes
description:
   - This module allows you to manage web checks
version_added: "2.2"
author:
    - Ales Petrovicky
    - Ladislav Novak
requirements:
    - zabbix-api
    - "python >= 2.6" 
options:
    server_url:
        description:
            - Url of Zabbix server, with protocol (http or https).
              C(url) is an alias for C(server_url).
        required: true
        default: null
        aliases: [ "url" ]
    login_user:
        description:
            - Zabbix user name.
        required: true
        default: null
    login_password:
        description:
            - Zabbix user password.
        required: true
        default: null
    host_name:
        description:
            - Technical name of the host.
            - If the host has already been added, the host name won't be updated.
        required: true
    webscenario_name:
        description:
            - List of host groups to add the host to.
        required: true
    status:
        description:
            - Status and function of the host.
            - 'Possible values are: enabled and disabled'
        required: false
        default: "enabled"
    state:
        description:
            - create/update or delete host.
            - 'Possible values are: present and absent. If the host already exists, and the state is "present", just to update the host.'
        required: false
        default: "present"
    timeout:
        description:
            - The timeout of API request(seconds).
        default: 10
    steps:
        description:
            - List of steps for WebScenario
            - 'Please review the interface documentation for more information on the supported properties:'
            - 'https://www.zabbix.com/documentation/3.0/manual/api/reference/httptest/object#scenario_step'
        required: true
    authentication:
        description:
            - Authentication parameters
            - 'Available parameters are: type(0 - (default) none; 1 - basic HTTP authentication; 2 - NTLM authentication), user, password'
        required: false
        default: {'type': 0}
    ssl:
        description:
            - SSL parameters
            - 'Available parameters are: verify_host (boolean), verify_peer (boolean), cert_file, key_file, key_password'
        required: false
        default: {}
    update_interval:
        description:
            - Number of seconds between checks
        required: false
        default: 60
    attempts:
        description:
            - Number of times a web scenario will try to execute each step before failing
        required: false
        default: 1
    agent:
        description:
            - User agent string that will be used by the web scenario.
        required: false
        default: "Zabbix"
    http_proxy:
        description:
            - Proxy that will be used by the web scenario given as http://[username[:password]@]proxy.example.com[:port].
        required: false
        default: ""
    variables:
        description:
            - Web scenario variables
        required: false
        default: ""
    headers:
        description:
            - HTTP headers that will be sent when performing a request.
        required: false
        default: ""
'''

EXAMPLES = '''
- name: Create a new webscenario or update an existing webscenario's info
  local_action:
    module: zabbix_webscenario
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    webscenario_name: ExampleScenario
    host_name: ExampleHost
    status: enabled
    state: present
    steps:
      - name: 'ExampleName'
        url: 'www.domain.tld'
        status_codes: '200'
        no: '1'
      - name: 'ExampleName2'
        url: 'www.domain2.tld'
        status_codes: '404,403'
        no: '2' # Sequence number of the step in a web scenario.
        follow_redirects: '1' # 1 -follow redirects, 0 - dont follow redirects
        headers: ''
        posts: ''
        required: 'text on page'
        retrieve_mode: '0'  # 0 - only body, 1 - only headers
        timeout: '15' # Request timeout in seconds. 
        variables: '' # Scenario step variables.
'''

RETURN = '''
'''

import logging
import copy
from operator import itemgetter

try:
    from zabbix_api import ZabbixAPI, ZabbixAPISubClass

    HAS_ZABBIX_API = True
except ImportError:
    HAS_ZABBIX_API = False


class DictDiffer(object):
    """
    Calculate the difference between two dictionaries as:
    (1) items added
    (2) items removed
    (3) keys same in both but changed values
    (4) keys same in both and unchanged values
    """
    def __init__(self, current_dict, past_dict):
        self.current_dict, self.past_dict = current_dict, past_dict
        self.current_keys, self.past_keys = [
            set(d.keys()) for d in (current_dict, past_dict)
        ]
        self.intersect = self.current_keys.intersection(self.past_keys)

    def added(self):
        return self.current_keys - self.intersect

    def removed(self):
        return self.past_keys - self.intersect

    def changed(self):
        return set(o for o in self.intersect
                   if self.past_dict[o] != self.current_dict[o])

    def unchanged(self):
        return set(o for o in self.intersect
                   if self.past_dict[o] == self.current_dict[o])


class WebScenario(object):
    def __init__(self, module, zbx):
        self._module = module
        self._zapi = zbx


    def add_webscenario(self, webscenario_name, host_id, status, steps, authentication, ssl, update_interval, attempts, agent, http_proxy, variables, headers):
        
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            application_id = self.get_application_id(host_id)

            # authentication
            authentication_type = authentication['type'] if authentication['type'] else 0
            http_user = authentication['user'] if 'user' in authentication else ''
            http_password = authentication['password'] if 'password' in authentication else ''

            # ssl
            verify_host = 1 if 'verify_host' in ssl and ssl['verify_host'] else 0
            verify_peer = 1 if 'verify_peer' in ssl and ssl['verify_peer'] else 0
            ssl_cert_file = ssl['cert_file'] if 'cert_file' in ssl else ''
            ssl_key_file = ssl['key_file'] if 'key_file' in ssl else ''
            ssl_key_password = ssl['key_password'] if 'key_password' in ssl else ''


            webscenario_list = self._zapi.httptest.create({'name': webscenario_name, 'hostid': host_id, 'applicationid': application_id, 'steps': steps, 
                'status': status, 'delay': update_interval, 'retries': attempts, 'agent': agent, 'http_proxy': http_proxy, 'variables': variables, 
                'headers': headers, 'authentication': authentication_type, 'http_user': http_user, 'http_password': http_password, 
                'ssl_cert_file': ssl_cert_file, 'ssl_key_file': ssl_key_file, 'ssl_key_password': ssl_key_password, 'verify_host': verify_host, 
                'verify_peer': verify_peer })
            if len(webscenario_list) >= 1:
                return webscenario_list['httptestids'][0]
        except Exception as e:
            self._module.fail_json(msg="Failed to create webscenario %s: %s" % (webscenario_name, e))

    def compare_steps(self, current_step, new_step):

        # compare sizes
        if len(current_step) != len(new_step):
            return False;

        # sort lists
        current_step, new_step = [sorted(l, key=itemgetter('no')) 
          for l in (current_step, new_step)]

        for index, step in enumerate(new_step):
            for key, value in step.items():
                if key in current_step[index]:
                    if value != current_step[index][key]:
                        return False
                else:
                    return False
                 
        # no change
        return True;

    def update_webscenario(self, webscenario_name, host_id, status, steps, authentication, ssl, update_interval, attempts, agent, http_proxy, variables, headers):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            application_id = self.get_application_id(host_id)

            # authentication
            authentication_type = str(authentication['type']) if authentication['type'] else '0'
            http_user = authentication['user'] if 'user' in authentication else ''
            http_password = authentication['password'] if 'password' in authentication else ''

            # ssl
            verify_host = '1' if 'verify_host' in ssl and ssl['verify_host'] else '0'
            verify_peer = '1' if 'verify_peer' in ssl and ssl['verify_peer'] else '0'
            ssl_cert_file = ssl['cert_file'] if 'cert_file' in ssl else ''
            ssl_key_file = ssl['key_file'] if 'key_file' in ssl else ''
            ssl_key_password = ssl['key_password'] if 'key_password' in ssl else ''

            current_webscenario = self.get_webscenario(webscenario_name)
            # remove readonly parameters
            del(current_webscenario['nextcheck'])
            del(current_webscenario['templateid'])


            new_webscenario = {'httptestid': current_webscenario['httptestid'], 'name': webscenario_name, 'hostid': host_id, 
                'applicationid': application_id, 'steps': steps, 
                'status': status, 'delay': update_interval, 'retries': attempts, 'agent': agent, 'http_proxy': http_proxy, 'variables': variables, 
                'headers': headers, 'authentication': authentication_type, 'http_user': http_user, 'http_password': http_password, 
                'ssl_cert_file': ssl_cert_file, 'ssl_key_file': ssl_key_file, 'ssl_key_password': ssl_key_password, 'verify_host': verify_host, 
                'verify_peer': verify_peer }



            dd = DictDiffer(current_webscenario, new_webscenario)
            if dd.added()!=set([]) or dd.changed()!=set([]) or dd.removed()!=set([]):
                # check if only steps are changed
                if dd.added() == set([]) and dd.removed()==set([]) and dd.changed()==set(['steps']):
                    # compare steps
                    if self.compare_steps(current_webscenario['steps'], new_webscenario['steps']) == True:
                       self._module.exit_json(changed=False)
                # remove applicationid otherwise update fail with API SQL error
                del(new_webscenario['applicationid'])
                webscenario_list = self._zapi.httptest.update(new_webscenario)
                if len(webscenario_list) >= 1:
                    self._module.exit_json(changed=True, result="Successfully updated Web Scenario %s"  % (webscenario_name))
            else:
                self._module.exit_json(changed=False)    
        except Exception as e:
            self._module.fail_json(msg="Failed to update WebScenario %s: %s" % (webscenario_name, e))

    def get_webscenario(self, webscenario_name):
        webscenario_list = self._zapi.httptest.get({'output': 'extend', "selectSteps": "extend", 'filter': {'name': webscenario_name}})
        return webscenario_list[0]


    def delete_webscenario(self, webscenario_id, webscenario_name):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.httptest.delete([webscenario_id])
        except Exception as e:
            self._module.fail_json(msg="Failed to delete Web Scenario %s: %s" % (webscenario_name, e))

    # get host by host name
    def get_host_by_host_name(self, host_name):
        host_list = self._zapi.host.get({'output': 'extend', 'filter': {'host': [host_name]}})
        if len(host_list) < 1:
            self._module.fail_json(msg="Host not found: %s" % host_name)
        else:
            return host_list[0]


    # get the status of host by host
    def get_host_status_by_host(self, host):
        return host['status']

    def webscenario_exists(self, webscenario_name):
        webscenario_list = self._zapi.httptest.get({'output': 'extend', 'filter': {'name': webscenario_name}})
        if len(webscenario_list) < 1:
            return False
        elif len(webscenario_list) > 1:
            self._module.fail_json(msg="More than one webscenario found for name: %s" % webscenario_name)
        else:
            return True

    def get_application_id(self, hostid):
        application_list = self._zapi.application.get({'output': 'extend', 'filter': {'name': 'Web', 'hostid': hostid}})
        if len(application_list) > 0:
            return application_list[0]['applicationid']
        else:
            #create Web application if does not exists
            application_ids = self._zapi.application.create({'name': 'Web', 'hostid': hostid})
            return int(application_ids['applicationids'][0])



def main():
    module = AnsibleModule(
        argument_spec=dict(
            server_url=dict(required=True, default=None, aliases=['url']),
            login_user=dict(required=True),
            login_password=dict(required=True),
            webscenario_name=dict(required=True),
            host_name=dict(required=True),
            status=dict(default="enabled"),
            state=dict(default="present"),
            timeout=dict(default=10, type='int'),
            steps=dict(required=True, type='list'),
            authentication=dict(required=False, type='dict', default={'type': '0'}),
            ssl=dict(required=False, type='dict', default={}),
            update_interval=dict(required=False, type='str', default='60'),
            attempts=dict(required=False, type='str', default='1'),
            agent=dict(required=False, type='str', default='Zabbix'),
            http_proxy=dict(required=False, type='str', default=''),
            variables=dict(required=False, type='str', default=''),
            headers=dict(required=False, type='str', default='')
        ),
        supports_check_mode=True
    )

    if not HAS_ZABBIX_API:
        module.fail_json(msg="Missing requried zabbix-api module (check docs or install with: pip install zabbix-api)")

    server_url = module.params['server_url']
    login_user = module.params['login_user']
    login_password = module.params['login_password']
    webscenario_name = module.params['webscenario_name']
    host_name = module.params['host_name']
    status = module.params['status']
    state = module.params['state']
    timeout = module.params['timeout']
    steps = module.params['steps']
    authentication = module.params['authentication']
    ssl = module.params['ssl']
    update_interval = module.params['update_interval']
    attempts = module.params['attempts']
    agent = module.params['agent']
    http_proxy = module.params['http_proxy']
    variables = module.params['variables']
    headers = module.params['headers']

    # convert enabled to 0; disabled to 1
    status = '1' if status == "disabled" else '0'

    zbx = None
    # login to zabbix
    try:
        zbx = ZabbixAPI(server_url, timeout=timeout)
        zbx.login(login_user, login_password)
    except Exception as e:
        module.fail_json(msg="Failed to connect to Zabbix server: %s" % e)

    webscenario = WebScenario(module, zbx)
    # check if webscenario exist
    is_webscenario_exist = webscenario.webscenario_exists(webscenario_name)

    # get webscenario host
    zabbix_host_obj = webscenario.get_host_by_host_name(host_name)
    host_id = zabbix_host_obj['hostid']

    if state == "absent":
        if is_webscenario_exist:
            # remove webscenario
            existing_webscenario = webscenario.get_webscenario(webscenario_name)
            webscenario.delete_webscenario(existing_webscenario['httptestid'], existing_webscenario['name'])
            module.exit_json(changed=True, result="Successfully delete Web Scenario %s" % webscenario_name)
        else:
            module.exit_json(changed=False) 
    
    else:
        if is_webscenario_exist:
            # update
            webscenario.update_webscenario(webscenario_name, host_id, status, steps, authentication, ssl, update_interval, attempts, agent, http_proxy, variables, headers)
            module.exit_json(changed=True, result="Successfully added web scenario %s" % (webscenario_name))
            
        else:
            # add
            webscenario.add_webscenario(webscenario_name, host_id, status, steps, authentication, ssl, update_interval, attempts, agent, http_proxy, variables, headers)
            module.exit_json(changed=True, result="Successfully added web scenario %s" % (webscenario_name))


from ansible.module_utils.basic import *
main()

