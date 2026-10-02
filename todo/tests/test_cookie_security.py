import datetime
from unittest import mock

from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings

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

  def test_jwt_for_missing_user_is_denied(self):
    self._assert_jwt_user_is_denied([])

  def test_jwt_for_inactive_user_is_denied(self):
    self._assert_jwt_user_is_denied([mock.Mock(is_active=False)])

  def _assert_jwt_user_is_denied(self, users):
    request = RequestFactory().post('/todo/api', secure=True)
    request.META['HTTP_AUTHORIZATION'] = ' '.join(('Bearer', 'test-token'))
    session = mock.Mock(
        user_id=1,
        expires_at=views.timezone.now() + datetime.timedelta(hours=1))
    with mock.patch.object(
        views.jwt_auth_settings, 'JWT_DECODE_HANDLER',
        return_value={'slug': 'session', 'expiry': '4102444800'}):
      with mock.patch.object(
          views.models.JwtSession.objects, 'filter', return_value=[session]):
        with mock.patch.object(
            views.User.objects, 'filter', return_value=users):
          with self.assertRaises(PermissionDenied):
            views._active_authenticated_user_via_jwt(request)
