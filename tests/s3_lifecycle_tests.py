import unittest
from s3_lifecycle import is_same_rule, create_s3_lc_rule, validate_lifecycle, calculate_net_rules
from mock import Mock


class SameRuleMethodTest(unittest.TestCase):
    def test_same_rule(self):
        rule_a = create_s3_lc_rule({"rule_id": "myrule", "prefix": None,
                                    "status": "enabled", "expiration": {"days": 10}})
        rule_b = create_s3_lc_rule({"rule_id": "myrule", "prefix": None,
                                    "status": "enabled", "expiration": {"days": 10}})
        self.assertTrue(is_same_rule(rule_a, rule_b))

    def test_same_rule_same_prefix(self):
        rule_a = create_s3_lc_rule({"rule_id": "myrule", "prefix": "/a",
                                    "status": "enabled", "expiration": {"days": 10}})
        rule_b = create_s3_lc_rule({"rule_id": "myrule", "prefix": "/a",
                                    "status": "enabled", "expiration": {"days": 10}})
        self.assertTrue(is_same_rule(rule_a, rule_b))

    def test_same_rule_prefix_mismatch(self):
        rule_a = create_s3_lc_rule({"rule_id": "myrule", "prefix": "/myfolder",
                                    "status": "enabled", "expiration": {"days": 10}})
        rule_b = create_s3_lc_rule({"rule_id": "myrule", "prefix": None,
                                    "status": "enabled", "expiration": {"days": 10}})
        self.assertFalse(is_same_rule(rule_a, rule_b))

    def test_same_rule_status_mismatch(self):
        rule_a = create_s3_lc_rule({"rule_id": "myrule", "prefix": "/f1",
                                    "status": "enabled", "expiration": {"days": 10}})
        rule_b = create_s3_lc_rule({"rule_id": "myrule", "prefix": "/f1",
                                    "status": "disabled", "expiration": {"days": 10}})
        self.assertFalse(is_same_rule(rule_a, rule_b))

    def test_same_rule_id_mismatch(self):
        rule_a = create_s3_lc_rule({"rule_id": "myrule", "prefix": "/f1",
                                    "status": "enabled", "expiration": {"days": 10}})
        rule_b = create_s3_lc_rule({"rule_id": "myruler", "prefix": "/f1",
                                    "status": "enabled", "expiration": {"days": 10}})
        self.assertFalse(is_same_rule(rule_a, rule_b))

    def test_same_rule_expiration_days_mismatch(self):
        rule_a = create_s3_lc_rule({"rule_id": "myrule", "prefix": None,
                                    "status": "enabled", "expiration": {"days": 10}})
        rule_b = create_s3_lc_rule({"rule_id": "myrule", "prefix": None,
                                    "status": "enabled", "expiration": {"days": 11}})
        self.assertFalse(is_same_rule(rule_a, rule_b))

    def test_same_rule_type_mismatch(self):
        rule_a = create_s3_lc_rule({"rule_id": "myrule", "prefix": None,
                                    "status": "enabled", "expiration": {"days": 10}})
        rule_b = create_s3_lc_rule({"rule_id": "myrule", "prefix": None,
                                    "status": "enabled", "transition": {"storage_class": "glacier", "days": 10}})
        self.assertFalse(is_same_rule(rule_a, rule_b))


class ValidateLifecycleTest(unittest.TestCase):
    def test_validate_lifecycle_expiration(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"rule_id": "rule1", "prefix": "/f1",
                      "expiration": {"days": 31},
                      "status": "enabled",
                      "state": "present"}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_has_calls(calls=[])

    def test_validate_lifecycle_missing_exp_or_trans(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"rule_id": "rule1",
                      "status": "enabled",
                      "state": "present"}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_called_once_with(msg='missing expiration or transition rule for rule_id: rule1')

    def test_validate_lifecycle_invalid_expiration(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"rule_id": "rule1",
                      "expiration": {},
                      "status": "enabled",
                      "state": "present"}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_called_once_with(msg='missing days or date in expiration rule for rule_id: rule1')

    def test_validate_lifecycle_multi(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [
            {
                "rule_id": "rule1",
                "prefix": "/f1",
                "expiration": {"days": 31},
                "status": "enabled",
                "state": "present"},
            {
                "rule_id": "rule2",
                "prefix": "/f2",
                "expiration": {"days": 31},
                "status": "disabled",
                "state": "absent"
            }]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_has_calls(calls=[])

    def test_validate_lifecycle_invalid_transition(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"rule_id": "rule1",
                      "transition": {},
                      "status": "enabled",
                      "state": "present"}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_called_once_with(msg='missing days or date in transition rule for rule_id: rule1')

    def test_validate_lifecycle_transition_glacier(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"rule_id": "rule1",
                      "transition": {"storage_class": "glacier", "days": 90},
                      "status": "enabled",
                      "state": "present"}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_has_calls(calls=[])

    def test_validate_lifecycle_transition_invalid_storage(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"rule_id": "rule1",
                      "transition": {"storage_class": "frozen", "days": 90},
                      "status": "enabled",
                      "state": "present"}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_called_once_with(msg='invalid storage class frozen for rule_id: rule1')

    def test_validate_lifecycle_transition_missing_storage(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"rule_id": "rule1",
                      "transition": {"days": 90},
                      "status": "enabled",
                      "state": "present"}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_called_once_with(msg='missing storage_class in rule_id: rule1')

    def test_validate_missing_status(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"rule_id": "rule1",
                      "transition": {"storage_class": "frozen", "days": 90},
                      "state": "present"}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_called_once_with(msg='status needed for rule_id: rule1')

    def test_validate_missing_state(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"rule_id": "rule1",
                      "status": "enabled",
                      "transition": {"storage_class": "frozen", "days": 90}}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_called_once_with(msg='state needed for rule_id: rule1')

    def test_validate_invalid_state(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"rule_id": "rule1",
                      "status": "enabled",
                      "state": "abc",
                      "transition": {"storage_class": "frozen", "days": 90}}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_called_once_with(msg='invalid state abc for rule_id: rule1')

    def test_validate_missing_rule_id(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"transition": {"storage_class": "frozen", "days": 90},
                      "state": "present"}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_called_once_with(msg='rule_id required for bucket test')

    def test_validate_lifecycle_expiration_both_days_and_date(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"rule_id": "rule1",
                      "expiration": {"days": 90, "date": "2020-01-30"},
                      "status": "enabled",
                      "state": "present"}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_called_once_with(
            msg='can only have date or days, not both in expiration rule_id: rule1')

    def test_validate_lifecycle_transition_glacier_both_days_and_date(self):
        bucket = 'test'
        module = Mock()
        lifecycle = [{"rule_id": "rule1",
                      "transition": {"storage_class": "glacier", "days": 90, "date": "2020-01-30"},
                      "status": "enabled",
                      "state": "present"}]
        module.fail_json = Mock(return_value=True)
        validate_lifecycle(module, bucket, lifecycle)
        module.fail_json.assert_called_once_with(
            msg='can only have date or days, not both in transition rule_id: rule1')


class CalculateRulesTests(unittest.TestCase):
    def test_new_rule_list(self):
        existing_rules = None
        rule1 = dict(rule_id="rule1", transition={"storage_class": "frozen", "days": 90},
                     status="enabled", state="present")
        lc_rule = create_s3_lc_rule(rule1)
        ansible_rules = [rule1]
        ret = calculate_net_rules(existing_rules, ansible_rules)
        self.assertTrue(ret.changed)
        self.assertTrue(is_same_rule(lc_rule, ret.rules[0]))

    def test_changed_rule_list(self):
        e1 = dict(rule_id="rule1", transition={"storage_class": "glacier", "days": 90},
                  status="enabled", state="present")
        e2 = dict(rule_id="rule2", prefix="/f1", expiration={"days": 31},
                  status="enabled", state="present")
        existing_rules = [create_s3_lc_rule(e1), create_s3_lc_rule(e2)]

        a1 = dict(rule_id="rule2", prefix="/f1", expiration={"days": 7},
                  status="enabled", state="present")
        ansible_rules = [a1]

        ret = calculate_net_rules(existing_rules, ansible_rules)
        self.assertTrue(ret.changed)
        found_rule = None
        for rule in ret.rules:
            if rule.id == a1['rule_id']:
                found_rule = rule
                break
        self.assertIsNotNone(found_rule)
        self.assertTrue(is_same_rule(create_s3_lc_rule(a1), found_rule))

    def test_disable_existing_rule(self):
        e1 = dict(rule_id="rule1", transition={"storage_class": "glacier", "days": 90},
                  status="enabled", state="present")
        e2 = dict(rule_id="rule2", prefix="/f1", expiration={"days": 31},
                  status="enabled", state="present")
        existing_rules = [create_s3_lc_rule(e1), create_s3_lc_rule(e2)]

        a1 = dict(rule_id="rule2", prefix="/f1", expiration={"days": 31},
                  status="disabled", state="present")
        a2 = dict(rule_id="rule1", transition={"storage_class": "glacier", "days": 90},
                  status="enabled", state="present")
        ansible_rules = [a1, a2]

        ret = calculate_net_rules(existing_rules, ansible_rules)
        self.assertTrue(ret.changed)
        self.assertEqual(2, ret.rules.__len__(), msg="Should contain 2 rules, but {} found".format(ret.rules.__len__()))
        found_rule = None
        for rule in ret.rules:
            if rule.id == a1['rule_id']:
                found_rule = rule
                break
        self.assertIsNotNone(found_rule)
        self.assertEqual(found_rule.status, "Disabled", msg="Rule should be disabled {}".format(found_rule))

    def test_add_new_rule_remove_others(self):
        e1 = dict(rule_id="rule1", transition={"storage_class": "glacier", "days": 90},
                  status="enabled", state="present")
        e2 = dict(rule_id="rule2", prefix="/f1", expiration={"days": 31},
                  status="enabled", state="present")
        existing_rules = [create_s3_lc_rule(e1), create_s3_lc_rule(e2)]

        a1 = dict(rule_id="rule3", prefix="/f2", expiration={"days": 7},
                  status="enabled", state="present")
        ansible_rules = [a1]
        ret = calculate_net_rules(existing_rules, ansible_rules)
        self.assertEqual(1, ret.rules.__len__(), msg="Should contain 1 rule, but {} found".format(ret.rules.__len__()))
        self.assertTrue(ret.changed)
        found_rule = None
        for rule in ret.rules:
            if rule.id == a1['rule_id']:
                found_rule = rule
                break
        self.assertIsNotNone(found_rule)
        self.assertTrue(is_same_rule(create_s3_lc_rule(a1), found_rule))

    def test_add_new_rule_to_existing(self):
        e1 = dict(rule_id="rule1", transition={"storage_class": "glacier", "days": 90},
                  status="enabled", state="present")
        e2 = dict(rule_id="rule2", prefix="/f1", expiration={"days": 31},
                  status="enabled", state="present")
        existing_rules = [create_s3_lc_rule(e1), create_s3_lc_rule(e2)]

        a1 = dict(rule_id="rule3", prefix="/f2", expiration={"days": 7},
                  status="enabled", state="present")
        ansible_rules = [a1, e1, e2]
        ret = calculate_net_rules(existing_rules, ansible_rules)
        self.assertEqual(3, ret.rules.__len__(),
                         msg="Should contain 3 rules, only {} found".format(ret.rules.__len__()))
        self.assertTrue(ret.changed)
        found_rule = None
        for rule in ret.rules:
            if rule.id == a1['rule_id']:
                found_rule = rule
                break
        self.assertIsNotNone(found_rule)
        self.assertTrue(is_same_rule(create_s3_lc_rule(a1), found_rule))

    def test_same_rule_list(self):
        rule1 = dict(rule_id="rule1", transition={"storage_class": "frozen", "days": 90},
                     status="enabled", state="present")
        existing_rules = [create_s3_lc_rule(rule1)]
        ansible_rules = [rule1]
        ret = calculate_net_rules(existing_rules, ansible_rules)
        self.assertFalse(ret.changed)

    def test_remove_rule_from_existing(self):
        e1 = dict(rule_id="rule1", transition={"storage_class": "glacier", "days": 90},
                  status="enabled", state="present")
        e2 = dict(rule_id="rule2", prefix="/f1", expiration={"days": 31},
                  status="enabled", state="present")
        existing_rules = [create_s3_lc_rule(e1), create_s3_lc_rule(e2)]
        a1 = dict(rule_id="rule2", prefix="/f1", expiration={"days": 31},
                  status="enabled", state="absent")
        ansible_rules = [a1]
        ret = calculate_net_rules(existing_rules, ansible_rules)
        self.assertTrue(ret.changed, msg='rules not changed {}'.format(ret.rules))
        self.assertEqual(1, ret.rules.__len__(),
                         msg="Should contain 1 rules, only {} found".format(ret.rules.__len__()))

        found_rule = False
        for rule in ret.rules:
            if rule.id == a1['rule_id']:
                found_rule = rule
                break
        self.assertFalse(found_rule, msg='Remove not removed')

    def test_remove_rule_from_existing_and_add_new_rule(self):
        e1 = dict(rule_id="rule1", transition={"storage_class": "glacier", "days": 90},
                  status="enabled", state="present")
        e2 = dict(rule_id="rule2", prefix="/f1", expiration={"days": 31},
                  status="enabled", state="present")
        existing_rules = [create_s3_lc_rule(e1), create_s3_lc_rule(e2)]

        a1 = dict(rule_id="rule2", prefix="/f1", expiration={"days": 31},
                  status="enabled", state="absent")
        a2 = dict(rule_id="rule3", prefix="/f3", expiration={"days": 31},
                  status="enabled", state="present")
        ansible_rules = [a1, a2]
        ret = calculate_net_rules(existing_rules, ansible_rules)
        self.assertEqual(1, ret.rules.__len__(), msg="Should contain 1 rules, but {} found".format(ret.rules.__len__()))

        self.assertTrue(ret.changed, msg='rules not changed {}'.format(ret.rules))
        found_rule = False
        for rule in ret.rules:
            if rule.id == a1['rule_id']:
                found_rule = rule
                break
        self.assertFalse(found_rule, msg='Rule rule2 should not be present')
        found_rule = False
        for rule in ret.rules:
            if rule.id == a2['rule_id']:
                found_rule = rule
                break
        self.assertTrue(found_rule, msg='Rule rule3 should be present')

if __name__ == '__main__':
    unittest.main()
