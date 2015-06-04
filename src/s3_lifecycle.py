#!/usr/bin/python
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: s3_lifecycle
short_description: manage lifecycle policy of objects in S3.
description:
    - This module allows the user to manage S3 buckets and the objects within them. Includes support for creating and deleting both objects and buckets, retrieving objects as files or strings and generating download links. This module has a dependency on python-boto.
version_added: "1.1"
options:
  bucket:
    description:
      - S3 Bucket name
    required: true
    default: null
  s3_url:
    description:
      - S3 URL endpoint for usage with Eucalypus, fakes3, etc.  Otherwise assumes AWS
    default: null
    aliases: [ S3_URL ]
  lifecycle:
    description:
      - list of rule dicts, each containing rule_id, status (enabled|disabled)
        state (present|absent, default: present) and (expiration or transition rules).
        (Optional) prefix value of objects in bucket
        If state is absent or status is disabled then expiration, transition and prefix values are ignored
        See examples for more information
    required: true
    default: null
author: Edwin Chiu
extends_documentation_fragment: aws
'''

EXAMPLES = '''
# Add expiration lifecycle rule for entire bucket
s3_lifecycle:
  bucket: mybucket
  lifecycle:
    - rule_id: rule_name
      expiration: days=90
      status: enabled
      state: present

# add expiration lifecycle rule (90 days) for prefix in bucket
s3_lifecycle:
  bucket: mybucket
  lifecycle:
    - rule_id: rule_name
      prefix: myfolder
      expiration: days=90
      status: enabled
      state: present

# add transition to glacier (after 90 days) for bucket
s3_lifecycle:
  bucket: mybucket
  lifecycle:
    - rule_id: rule_name
      transition: storage_class=glacier days=90
      status: enabled
      state: present

# combined rule
s3_lifecycle:
  bucket: mybucket
  lifecycle:
    - rule_id: transition_and_expiry_rule
      transition: storage_class=glacier days=90
      expiration: days=90
      status: enabled
      state: present

# multiple rules
s3_lifecycle:
  bucket: mybucket
  lifecycle:
    - rule_id: rule_myfolder
      prefix: myfolder
      expiration: days=90
      status: enabled
      state: present
    - rule_id: rule_mytemp
      prefix: mytemp
      expiration: days=30
      status: enabled
      state: present

# disable rule
s3_lifecycle:
  bucket: mybucket
  lifecycle:
    - rule_id: rule_myfolder
      prefix: myfolder
      expiration: days=90
      status: disabled

# delete rule (status/transition/expiration/prefix ignored)
s3_lifecycle:
  bucket: mybucket
  lifecycle:
    - rule_id: rule_myfolder
      state: absent

'''

import urlparse

from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *
from collections import namedtuple

try:
    import boto
    from boto.s3.connection import Location
    from boto.s3.connection import OrdinaryCallingFormat
    from boto.s3.connection import S3Connection
    from boto.s3.lifecycle import Lifecycle, Expiration, Transition, Rule

    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False


def is_fakes3(s3_url):
    """ Return True if s3_url has scheme fakes3:// """
    if s3_url is not None:
        return urlparse.urlparse(s3_url).scheme in ('fakes3', 'fakes3s')
    else:
        return False


def is_walrus(s3_url):
    """ Return True if it's Walrus endpoint, not S3

    We assume anything other than *.amazonaws.com is Walrus"""
    if s3_url is not None:
        o = urlparse.urlparse(s3_url)
        return not o.hostname.endswith('amazonaws.com')
    else:
        return False


def bucket_lookup(module, s3, bucket):
    try:
        result = s3.lookup(bucket)
    except s3.provider.storage_response_error, e:
        module.fail_json(msg=str(e))
    if result:
        return result
    else:
        return False


def validate_lifecycle(module, bucket, lifecycle):
    for rule in lifecycle:
        if 'rule_id' not in rule:
            module.fail_json(msg='rule_id required for bucket %s' % bucket)
            return False
        if 'status' not in rule:
            module.fail_json(msg='status needed for rule_id: %s' % rule['rule_id'])
            return False
        elif rule['status'] != 'enabled' and rule['status'] != 'disabled':
            module.fail_json(msg='invalid status %s for rule_id: %s' % (rule['status'], rule['rule_id']))
            return False
        if 'state' not in rule:
            module.fail_json(msg='state needed for rule_id: %s' % rule['rule_id'])
            return False
        elif rule['state'] != 'present' and rule['state'] != 'absent':
            module.fail_json(msg='invalid state %s for rule_id: %s' % (rule['state'], rule['rule_id']))
            return False
        if rule['state'] != 'absent' and rule['status'] != 'disabled':
            if 'expiration' not in rule and 'transition' not in rule:
                module.fail_json(msg='missing expiration or transition rule for rule_id: %s' % rule['rule_id'])
                return False
            if 'expiration' in rule:
                if 'days' not in rule['expiration'] and 'date' not in rule['expiration']:
                    module.fail_json(msg='missing days or date in expiration rule for rule_id: %s' % rule['rule_id'])
                    return False
                elif 'days' in rule['expiration'] and 'date' in rule['expiration']:
                    module.fail_json(msg='can only have date or days, not both in expiration rule_id: %s' % rule['rule_id'])
                    return False

            if 'transition' in rule:
                if 'days' not in rule['transition'] and 'date' not in rule['transition']:
                    module.fail_json(msg='missing days or date in transition rule for rule_id: %s' % rule['rule_id'])
                    return False
                elif 'days' in rule['transition'] and 'date' in rule['transition']:
                    module.fail_json(msg='can only have date or days, not both in transition rule_id: %s' % rule['rule_id'])
                    return False
                elif 'storage_class' in rule['transition'] \
                        and rule['transition']['storage_class'] != 'glacier':
                    module.fail_json(msg='invalid storage class %s for rule_id: %s' % (rule['transition']['storage_class'], rule['rule_id']))
                    return False
                elif 'transition' in rule and 'storage_class' not in rule['transition']:
                    module.fail_json(msg='missing storage_class in rule_id: %s' % rule['rule_id'])
                    return False

    return True


def is_same_rule(rule_a, rule_b):
    if rule_a.id != rule_b.id:
        return False
    if rule_a.prefix != rule_b.prefix:
        return False
    if rule_a.status != rule_b.status:
        return False
    if (rule_a.expiration is None and rule_b.expiration is not None) or \
       (rule_b.expiration is None and rule_a.expiration is not None):
        return False
    # both have expiration rules
    elif rule_a.expiration is not None and rule_b.expiration is not None:
        exp_a = rule_a.expiration
        exp_b = rule_b.expiration
        if (exp_a.days is None and exp_b.days is not None) or \
           (exp_b.days is None and exp_a.days is not None):
            return False
        elif exp_a.days is not None:
            if exp_a.days != exp_b.days:
                return False
    # TODO transition rule comparison
    if rule_a.transition is not None and rule_b.transition is not None:
        pass

    return True


def create_s3_lc_rule(rule):
    rule_exp = None
    rule_trans = None
    if 'prefix' not in rule: rule['prefix'] = None
    # TODO date expiration
    if 'expiration' in rule and rule['expiration']['days']:
        rule_exp = Expiration(days=rule['expiration']['days'])
    if 'transition' in rule:
        # FIXME: cleanup
        rule_trans = Transition(storage_class='GLACIER', days=rule['transition']['days'])
    if rule['status'] == 'enabled':  rule['status'] = 'Enabled'
    if rule['status'] == 'disabled': rule['status'] = 'Disabled'
    new_rule = Rule(id=rule['rule_id'], prefix=rule['prefix'], status=rule['status'],
                            expiration=rule_exp, transition=rule_trans)
    return new_rule


def get_s3_connection(module, aws_connect_kwargs, region, s3_url=None):
    s3 = None
    # allow eucarc environment variables to be used if ansible vars aren't set
    if not s3_url and 'S3_URL' in os.environ:
        s3_url = os.environ['S3_URL']

    if region in ('us-east-1', '', None):
        # S3ism for the US Standard region
        location = Location.DEFAULT
    else:
        # Boto uses symbolic names for locations but region strings will
        # actually work fine for everything except us-east-1 (US Standard)
        location = region

    # Look at s3_url and tweak connection settings
    # if connecting to Walrus or fakes3
    try:
        if is_fakes3(s3_url):
            fakes3 = urlparse.urlparse(s3_url)
            s3 = S3Connection(
                is_secure=fakes3.scheme == 'fakes3s',
                host=fakes3.hostname,
                port=fakes3.port,
                calling_format=OrdinaryCallingFormat(),
                **aws_connect_kwargs
            )
        elif is_walrus(s3_url):
            walrus = urlparse.urlparse(s3_url).hostname
            s3 = boto.connect_walrus(walrus, **aws_connect_kwargs)
        else:
            s3 = boto.s3.connect_to_region(location, is_secure=True, calling_format=OrdinaryCallingFormat(), **aws_connect_kwargs)
            # use this as fallback because connect_to_region seems to fail in boto + non 'classic' aws accounts in some cases
            if s3 is None:
                s3 = boto.connect_s3(**aws_connect_kwargs)

    except boto.exception.NoAuthHandlerFound, e:
        module.fail_json(msg='No Authentication Handler found: %s ' % str(e))
    except Exception, e:
        module.fail_json(msg='Failed to connect to S3: %s' % str(e))

    if s3 is None: # this should never happen
        module.fail_json(msg ='Unknown error, failed to create s3 connection, no information from boto.')

    return s3

def get_rule_by_id(rule_id, rule_list):
    for rule in rule_list:
        if rule.id == rule_id: return rule
    return None

def calculate_net_rules(existing_rules, ansible_rules):
    updated_lifecycle = False
    new_lifecycle = False

    temp_existing_rules = []   # list of existing rules
    temp_new_rules = []        # list of new rules or updated rules
    rules_to_apply = []

    # if we have same rule_id and they are not the same, update existing rule_id with ansible values
    # if we have a rule_id that does not exist, then add in the ansible rule
    # if we don't have any existing rules, add in all the ansible rules
    if existing_rules is not None:
        for rule in ansible_rules:
            temp_rule = create_s3_lc_rule(rule)
            existing_rule = get_rule_by_id(temp_rule.id, existing_rules)
            if existing_rule is not None:
                # existing rule_id, possibly the same or needs updating
                if is_same_rule(existing_rule, temp_rule):
                    temp_existing_rules.append(existing_rule)
                else:
                    updated_lifecycle = True
                    temp_new_rules.append(temp_rule)
            else:
                # net new rule
                updated_lifecycle = True
                temp_new_rules.append(temp_rule)

        if updated_lifecycle:
            rules_to_apply = temp_existing_rules + temp_new_rules

    else:
        # no existing rules
        new_lifecycle = True
        for rule in ansible_rules:
            rules_to_apply.append(create_s3_lc_rule(rule))

    # check state
    temp_list = []
    if rules_to_apply.__len__() == 0: rules_to_apply = existing_rules
    for x in rules_to_apply:
        remove = False
        for rule in ansible_rules:
            if rule['rule_id'] == x.id and rule['state'] == 'absent':
                remove = True
                updated_lifecycle = True
        if not remove:
            temp_list.append(x)
    rules_to_apply = temp_list

    changed = new_lifecycle | updated_lifecycle
    return namedtuple("set", "changed, rules")(changed=changed, rules=rules_to_apply)

def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
            bucket         = dict(required=True),
            s3_url         = dict(aliases=['S3_URL']),
            lifecycle      = dict(type='list', required=True),
        ),
    )

    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')

    bucket = module.params.get('bucket')
    s3_url = module.params.get('s3_url')
    lifecycle = module.params.get('lifecycle')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module)
    s3 = get_s3_connection(module, aws_connect_kwargs, region, s3_url)

    validate_lifecycle(module, bucket, lifecycle)

    bucket_obj = bucket_lookup(module, s3, bucket)
    if not bucket_obj:
        module.fail_json(msg='Bucket %s does not exist' %bucket)

    lifecycle_config = None
    new_lifecycle = False
    try:
        lifecycle_config = bucket_obj.get_lifecycle_config()
    except boto.exception.S3ResponseError:
        new_lifecycle = True

    results = calculate_net_rules(lifecycle_config, lifecycle)

    if results.changed:
        try:
            if results.rules.__len__() > 0:
                lifecycle_config = Lifecycle()
                for rule in results.rules:
                    lifecycle_config.append(rule)
                bucket_obj.configure_lifecycle(lifecycle_config)
            else:
                bucket_obj.delete_lifecycle_configuration()
                module.exit_json(bucket=bucket, changed=True,
                                 msg='Lifecycle Configuration deleted')
        except boto.exception.S3ResponseError, e:
            module.fail_json(bucket=bucket, changed=results.changed,
                             msg="Error %s: %s" % (e.error_code, e.message),
                             lifecycle_rules=map(lambda x: x.to_xml(), results.rules))

    module.exit_json(bucket=bucket, changed=results.changed,
                     lifecycle_rules=map(lambda x: x.to_xml(), results.rules))

# main
if __name__ == "__main__":
    main()
