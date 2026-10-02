from django.http import HttpResponse
from django.test import TestCase, override_settings

from todo import views


class CookieSecurityTest(TestCase):
  @override_settings(DEBUG=False)
  def test_preference_cookie_has_security_attributes(self):
    response = HttpResponse()

    views._set_cookie(response, 'VISITOR_INFO0', 'value')

    cookie = response.cookies['VISITOR_INFO0']
    self.assertTrue(cookie['secure'])
    self.assertTrue(cookie['httponly'])
    self.assertEqual(cookie['samesite'], 'Lax')

  @override_settings(DEBUG=True)
  def test_preference_cookie_is_not_secure_on_local_http(self):
    response = HttpResponse()

    views._set_cookie(response, 'VISITOR_INFO0', 'value')

    self.assertFalse(response.cookies['VISITOR_INFO0']['secure'])

  def test_malformed_cookie_is_ignored(self):
    self.assertIsNone(views._deserialized_cookie_value('abcde'))
