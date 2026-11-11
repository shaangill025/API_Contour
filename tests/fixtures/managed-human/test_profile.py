import unittest
from deploy.local import origin21_profile as profiles


class HumanProfileTest(unittest.TestCase):
    def test_closed_identity_and_separate_paths(self):
        context = profiles.HUMAN
        self.assertIs(profiles.require_context(context),context)
        self.assertIs(profiles.context_for_profile(context.profile),context)
        self.assertIs(profiles.context_for_bound(context.bound),context)
        self.assertIs(profiles.context_for_capture(context.bound.capture),context)
        self.assertEqual(context.profile.state.parent.name, '.local-mvp-managed-human')
        self.assertNotEqual(context.project, profiles.MANAGED.project)
        self.assertNotEqual(context.network, profiles.MANAGED.network)
        with self.assertRaises(ValueError):
            profiles.require_context(context._replace())
        with self.assertRaises(ValueError):
            profiles.context_for_profile(context.profile._replace())


if __name__ == '__main__':
    unittest.main()
