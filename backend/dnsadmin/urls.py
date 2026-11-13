from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from zones.security import admin_sso
from zones import views as v
from zones.views import EncryptedTokenView, LoginKeyView, TokenView
from zones.views.doh import DohView

urlpatterns = [
    path('admin/login/', admin_sso.admin_login),
    path('admin/sso/', admin_sso.admin_sso),
    path('admin/', admin.site.urls),
    path('dns-query', DohView.as_view()),
    path('api/token/', TokenView.as_view()),
    path('api/token/encrypted/', EncryptedTokenView.as_view()),
    path('api/login-key/', LoginKeyView.as_view()),
    path('api/me/', v.MeView.as_view()),
    path('api/admin-ticket/', v.AdminTicketView.as_view()),
    path('api/mfa/', v.MfaStatusView.as_view()),
    path('api/mfa/encrypted/', v.MfaEncryptedView.as_view()),
    path('api/mfa/totp/', v.TotpVerifyView.as_view()),
    path('api/mfa/totp/setup/', v.TotpSetupView.as_view()),
    path('api/mfa/totp/confirm/', v.TotpConfirmView.as_view()),
    path('api/mfa/totp/remove/', v.TotpRemoveView.as_view()),
    path('api/mfa/passkey/options/', v.PasskeyOptionsView.as_view()),
    path('api/mfa/passkey/verify/', v.PasskeyVerifyView.as_view()),
    path('api/mfa/passkey/register-options/', v.PasskeyRegisterOptionsView.as_view()),
    path('api/mfa/passkey/register/', v.PasskeyRegisterView.as_view()),
    path('api/mfa/stepup/totp/', v.TotpStepUpView.as_view()),
    path('api/mfa/stepup/passkey/options/', v.PasskeyStepUpOptionsView.as_view()),
    path('api/mfa/stepup/passkey/verify/', v.PasskeyStepUpVerifyView.as_view()),
    path('api/mfa/passkey/<int:pk>/remove/', v.PasskeyRemoveView.as_view()),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema')),
    path('api/', include('zones.urls')),
]
